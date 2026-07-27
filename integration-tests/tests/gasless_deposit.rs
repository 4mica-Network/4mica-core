//! End-to-end gasless deposit against the local stack.
//!
//! The offline suites in `sdk/tests/gasless_deposit*.rs` prove the SDK's signing and submission
//! halves agree with each other. This one closes the remaining seam: that a *real* EIP-3009 token
//! accepts the digest the SDK builds, and that Core4Mica credits the collateral.
//!
//! The depositor here holds **zero ETH** for the whole test. That is the property under test — if
//! any step needed gas from the signer, the flow would fail rather than silently degrade.

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolCall;
use rpc::{RpcProxy, SupportedTokenInfo};
use sdk_4mica::contract::Core4Mica;
use sdk_4mica::{Client, Config, ReceiveAuthorization};
use std::str::FromStr;

sol! {
    /// Just enough of the EIP-3009 surface to detect support.
    contract ERC3009Probe {
        function DOMAIN_SEPARATOR() external view returns (bytes32);
        function receiveWithAuthorization(
            address from,
            address to,
            uint256 value,
            uint256 validAfter,
            uint256 validBefore,
            bytes32 nonce,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) external;
    }
}

mod common;
use crate::common::{
    authed_user_client, core_total, eth_rpc_url, fund_user_with_erc20, get_chain_timestamp,
    mine_confirmations, user_asset, wait_for_collateral_increase,
};

/// Default anvil account, prefunded with ETH — it plays the facilitator and pays every gas fee.
const SUBMITTER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Mirrors `DEPOSIT_AUTHORIZATION_TTL_SECS` in the SDK.
const AUTHORIZATION_TTL_SECS: u64 = 3600;

/// A brand-new account with no ETH, authenticated against core purely by signing (no gas).
async fn new_gasless_depositor()
-> anyhow::Result<(Config<PrivateKeySigner>, Client<PrivateKeySigner>, Address)> {
    let signer = PrivateKeySigner::random();
    let address = signer.address();
    let key = format!("0x{}", alloy::hex::encode(signer.to_bytes()));
    let (config, client) = authed_user_client(&key).await?;
    Ok((config, client, address))
}

async fn eth_balance<S>(config: &Config<S>, who: Address) -> anyhow::Result<U256> {
    let rpc_url = eth_rpc_url(config).await?;
    let provider = ProviderBuilder::new().connect(&rpc_url).await?;
    Ok(provider.get_balance(who).await?)
}

/// Core4Mica bound to a gas-paying wallet, using the SDK's published ABI.
///
/// Submission is not the SDK's job — the SDK signs, a sponsor submits. This mirrors what a
/// facilitator service does, and deliberately goes through `sdk_4mica::contract` so this test
/// exercises the same bindings a real submitter would rather than a redeclared copy.
async fn core_as_submitter<S>(
    config: &Config<S>,
) -> anyhow::Result<Core4Mica::Core4MicaInstance<DynProvider>> {
    let rpc_url = eth_rpc_url(config).await?;
    let signer = PrivateKeySigner::from_str(SUBMITTER_KEY)?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect(&rpc_url)
        .await?
        .erased();

    let mut proxy = RpcProxy::new(config.rpc_url.as_str())?;
    if let Some(token) = &config.bearer_token {
        proxy = proxy.with_bearer_token(token.clone());
    }
    let contract_address = Address::from_str(&proxy.get_public_params().await?.contract_address)?;
    Ok(Core4Mica::new(contract_address, provider))
}

/// Redeem a signed authorization, paying the gas. Dry-runs first so a rejection surfaces as a
/// decoded contract error rather than a mined failure.
async fn submit_authorization<S>(
    config: &Config<S>,
    asset: Address,
    amount: U256,
    auth: ReceiveAuthorization,
) -> anyhow::Result<TransactionReceipt> {
    let core = core_as_submitter(config).await?;
    let call = core.depositStablecoinWithAuthorization(asset, amount, auth);
    call.call().await?;
    Ok(call.send().await?.get_receipt().await?)
}

/// The SDK stamps `validBefore` from the host clock, but the token checks it against
/// `block.timestamp`. Other suites on this stack call `evm_increaseTime` (withdrawal grace
/// periods), which can leave the chain hours or days ahead of wall clock — at which point every
/// authorization this test signs is already expired on arrival.
///
/// Rather than fail confusingly depending on which test ran first, detect the drift and skip.
async fn skip_on_chain_clock_drift<S>(config: &Config<S>) -> anyhow::Result<bool> {
    let chain_ts = get_chain_timestamp(config).await?;
    let host_ts = common::get_now().as_secs();
    if chain_ts >= host_ts.saturating_add(AUTHORIZATION_TTL_SECS) {
        eprintln!(
            "skipping test: chain clock is {}s ahead of the host, so a {AUTHORIZATION_TTL_SECS}s \
             authorization is already expired on-chain. Restart the stack (`make dev-down dev-up`) \
             to run this test.",
            chain_ts.saturating_sub(host_ts)
        );
        return Ok(true);
    }
    Ok(false)
}

/// First supported ERC20 that actually implements EIP-3009, with one whole token in its own
/// decimals.
///
/// Probed rather than assumed. Both halves are checked independently: a token can expose
/// `DOMAIN_SEPARATOR()` (EIP-2612 does too) while lacking `receiveWithAuthorization`, in which case
/// signing succeeds and submission dies with an opaque empty revert from inside Core4Mica.
async fn eip3009_token<S>(
    client: &Client<PrivateKeySigner>,
    config: &Config<S>,
) -> anyhow::Result<Option<(SupportedTokenInfo, U256)>> {
    let rpc_url = eth_rpc_url(config).await?;
    let provider = ProviderBuilder::new().connect(&rpc_url).await?;
    let redeem_selector = alloy::hex::encode(ERC3009Probe::receiveWithAuthorizationCall::SELECTOR);

    for token in client.get_supported_tokens().await?.tokens {
        let asset = Address::from_str(&token.address)?;

        let has_domain_separator = provider
            .call(
                TransactionRequest::default()
                    .with_to(asset)
                    .with_input(ERC3009Probe::DOMAIN_SEPARATORCall {}.abi_encode()),
            )
            .await
            .is_ok();
        // No call can distinguish "function missing" from "reverted on bad args", so look for the
        // selector in the deployed bytecode instead.
        let has_redeem =
            alloy::hex::encode(provider.get_code_at(asset).await?).contains(&redeem_selector);

        if has_domain_separator && has_redeem {
            let amount = U256::from(10u64).pow(U256::from(token.decimals));
            return Ok(Some((token, amount)));
        }
        eprintln!(
            "skipping {} ({}): DOMAIN_SEPARATOR()={has_domain_separator}, \
             receiveWithAuthorization()={has_redeem} — not a usable EIP-3009 token",
            token.symbol, token.address
        );
    }
    Ok(None)
}

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_gasless_deposit_credits_signer_and_costs_them_no_gas() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    let (submitter_config, submitter) = authed_user_client(SUBMITTER_KEY).await?;
    if skip_on_chain_clock_drift(&submitter_config).await? {
        return Ok(());
    }

    let Some((token, amount)) = eip3009_token(&submitter, &submitter_config).await? else {
        eprintln!(
            "skipping test: no supported token implements EIP-3009. The local stack's mock \
             stablecoins gained receiveWithAuthorization in contracts/test/Core4MicaTestBase.sol \
             — redeploy the stack to pick it up."
        );
        return Ok(());
    };
    let asset = Address::from_str(&token.address)?;

    let (depositor_config, depositor, depositor_address) = new_gasless_depositor().await?;

    // Give the depositor tokens but deliberately no ETH.
    let rpc_url = eth_rpc_url(&depositor_config).await?;
    fund_user_with_erc20(&rpc_url, asset, depositor_address, amount).await?;
    let depositor_eth_before = eth_balance(&depositor_config, depositor_address).await?;
    assert_eq!(
        depositor_eth_before,
        U256::ZERO,
        "the depositor must start with no ETH for this to prove anything"
    );

    let collateral_before = core_total(&depositor, asset).await?;

    // Sign locally — no transaction, no allowance, no gas.
    let auth = depositor
        .user
        .sign_deposit_authorization(token.address.clone(), amount)
        .await?;
    assert_eq!(
        auth.from, depositor_address,
        "the authorization must bind the depositor"
    );
    assert_eq!(
        eth_balance(&depositor_config, depositor_address).await?,
        U256::ZERO,
        "signing must not spend gas"
    );

    // A different account submits and pays.
    let submitter_address = submitter_config.signer.address();
    let submitter_eth_before = eth_balance(&submitter_config, submitter_address).await?;
    let receipt = submit_authorization(&submitter_config, asset, amount, auth).await?;
    assert!(receipt.status(), "gasless deposit transaction must succeed");

    mine_confirmations(&depositor_config, 2).await?;
    wait_for_collateral_increase(&depositor.recipient, asset, collateral_before, amount).await?;

    // The collateral landed with the signer, on-chain, not with whoever paid.
    let position = user_asset(&depositor, asset).await?;
    assert!(
        position.collateral >= amount,
        "{} collateral for the depositor should be at least {amount}, got {}",
        token.symbol,
        position.collateral
    );

    assert_eq!(
        eth_balance(&depositor_config, depositor_address).await?,
        U256::ZERO,
        "the depositor must still hold no ETH — the deposit was genuinely gasless for them"
    );
    assert!(
        eth_balance(&submitter_config, submitter_address).await? < submitter_eth_before,
        "the submitter must be the one who paid for the gas"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_gasless_deposit_authorization_cannot_be_replayed() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    let (submitter_config, submitter) = authed_user_client(SUBMITTER_KEY).await?;
    if skip_on_chain_clock_drift(&submitter_config).await? {
        return Ok(());
    }

    let Some((token, amount)) = eip3009_token(&submitter, &submitter_config).await? else {
        eprintln!(
            "skipping test: no supported token implements EIP-3009. The local stack's mock \
             stablecoins gained receiveWithAuthorization in contracts/test/Core4MicaTestBase.sol \
             — redeploy the stack to pick it up."
        );
        return Ok(());
    };
    let asset = Address::from_str(&token.address)?;

    let (depositor_config, depositor, depositor_address) = new_gasless_depositor().await?;
    let rpc_url = eth_rpc_url(&depositor_config).await?;
    // Fund twice over, so a successful replay would be limited by the nonce guard, not by balance.
    fund_user_with_erc20(
        &rpc_url,
        asset,
        depositor_address,
        amount * U256::from(2u64),
    )
    .await?;

    let auth = depositor
        .user
        .sign_deposit_authorization(token.address.clone(), amount)
        .await?;

    submit_authorization(&submitter_config, asset, amount, auth.clone()).await?;

    // EIP-3009 marks the nonce used; the token must reject the second redemption.
    let replayed = submit_authorization(&submitter_config, asset, amount, auth).await;
    assert!(
        replayed.is_err(),
        "a used authorization nonce must not be redeemable a second time"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_gasless_deposit_rejects_a_tampered_amount() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    let (submitter_config, submitter) = authed_user_client(SUBMITTER_KEY).await?;
    if skip_on_chain_clock_drift(&submitter_config).await? {
        return Ok(());
    }

    let Some((token, amount)) = eip3009_token(&submitter, &submitter_config).await? else {
        eprintln!(
            "skipping test: no supported token implements EIP-3009. The local stack's mock \
             stablecoins gained receiveWithAuthorization in contracts/test/Core4MicaTestBase.sol \
             — redeploy the stack to pick it up."
        );
        return Ok(());
    };
    let asset = Address::from_str(&token.address)?;

    let (depositor_config, depositor, depositor_address) = new_gasless_depositor().await?;
    let rpc_url = eth_rpc_url(&depositor_config).await?;
    fund_user_with_erc20(
        &rpc_url,
        asset,
        depositor_address,
        amount * U256::from(4u64),
    )
    .await?;

    let auth = depositor
        .user
        .sign_deposit_authorization(token.address.clone(), amount)
        .await?;

    // The value is inside the signature, so a submitter cannot pull more than was authorized.
    let inflated = submit_authorization(
        &submitter_config,
        asset,
        amount * U256::from(2u64),
        auth.clone(),
    )
    .await;
    assert!(
        inflated.is_err(),
        "a submitter must not be able to redeem more than the signed amount"
    );

    // And the untampered authorization still works afterwards.
    let collateral_before = core_total(&depositor, asset).await?;
    submit_authorization(&submitter_config, asset, amount, auth).await?;
    mine_confirmations(&depositor_config, 2).await?;
    wait_for_collateral_increase(&depositor.recipient, asset, collateral_before, amount).await?;

    Ok(())
}
