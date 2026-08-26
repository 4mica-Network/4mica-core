use alloy::providers::ProviderBuilder;
use sdk_4mica::client::model::Route;
use sdk_4mica::{Address, U256};

mod common;

use crate::common::{
    OwnedERC20, authed_recipient_client, authed_user_client_with_facilitator, eth_rpc_url,
    fund_user_with_erc20, get_now,
};

/// Anvil accounts #2 (debtor) and #9 (creditor). #2 is otherwise unused in this
/// suite; #9 only ever receives funds in `sponsored_claim.rs`, and test binaries
/// run sequentially, so neither assertion here can race another test's.
const DEBTOR_KEY: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const CREDITOR_KEY: &str = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

/// The dev stack's EIP-3009 stablecoin (deterministic deploy address).
const EIP3009_TOKEN: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

/// The sponsored debit path end to end, through a *real* facilitator: a committed
/// ERC-20 cycle where the debtor pays their net debit via the facilitator's
/// `/clearing/pay` — the debtor signs an EIP-3009 authorization, the facilitator's
/// relayer submits `payNetDebitWithAuthorization` and pays the gas, and the exact
/// amount leaves the debtor's wallet with their ETH untouched.
///
/// Needs the local core stack (`make dev-up`) plus a running facilitator (from
/// `facilitator-4mica`, pointed at this core), named via `E2E_FACILITATOR_URL`:
///
/// ```sh
/// E2E_FACILITATOR_URL=http://127.0.0.1:8080 cargo test --test sponsored_pay_debit
/// ```
///
/// Skips with a notice when either is missing. The facilitator's own e2e suite
/// covers the negative half (bad signatures, foreign nonces) without this setup.
#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_sponsored_pay_debit_via_facilitator() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }
    let Some(facilitator_url) = std::env::var("E2E_FACILITATOR_URL")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    else {
        eprintln!(
            "[sponsored-pay-debit] skipped: set E2E_FACILITATOR_URL to a running facilitator \
             (see the facilitator-4mica repo) to exercise the sponsored debit path"
        );
        return Ok(());
    };

    let (debtor_config, debtor) =
        authed_user_client_with_facilitator(DEBTOR_KEY, facilitator_url).await?;
    let (creditor_config, creditor) = authed_recipient_client(CREDITOR_KEY).await?;
    assert!(debtor.settlement.is_gasless_available());
    let debtor_address = debtor_config.signer.address();
    let creditor_address = creditor_config.signer.address();
    let token: Address = EIP3009_TOKEN.parse()?;

    let amount = U256::from(5_000_000u64); // 5 units of the 6-decimals stablecoin
    let cycle_id = format!("e2e-sponsored-pay:{}", get_now().as_nanos());
    let rpc_url = eth_rpc_url(&debtor_config).await?;

    // The debit is pulled from the debtor's wallet, so fund it there — collateral
    // inside Core4Mica is not what `payNetDebitWithAuthorization` draws on.
    fund_user_with_erc20(&rpc_url, token, debtor_address, amount).await?;

    common::clearing::inject_frozen_two_party_cycle_for_asset(
        &cycle_id,
        debtor_address,
        creditor_address,
        amount,
        EIP3009_TOKEN,
    )
    .await?;
    common::clearing::wait_for_payment_window(&cycle_id, &rpc_url).await?;

    // Strictly the gasless route — no self-funded fallback — so a facilitator
    // refusal fails the test instead of quietly passing through the fallback.
    let tokens_before = erc20_balance(&rpc_url, token, debtor_address).await?;
    let eth_before = eth_balance(&rpc_url, debtor_address).await?;
    let receipt = debtor
        .settlement
        .pay(cycle_id.clone())
        .gasless()
        .send()
        .await?;
    assert!(receipt.route.is_gasless());
    assert_eq!(receipt.account, debtor_address);

    // The debtor sent no transaction and granted no allowance: exactly the net
    // debit leaves in tokens, and not a wei of gas.
    let tokens_after = erc20_balance(&rpc_url, token, debtor_address).await?;
    assert_eq!(
        tokens_before - tokens_after,
        amount,
        "exactly the net debit must leave the debtor's wallet"
    );
    let eth_after = eth_balance(&rpc_url, debtor_address).await?;
    assert_eq!(
        eth_after, eth_before,
        "a sponsored payment must cost the debtor no gas"
    );

    // The sponsored payment funded the cycle: the creditor's claim (self-funded —
    // no facilitator configured on that client) pays out in full.
    let creditor_tokens_before = erc20_balance(&rpc_url, token, creditor_address).await?;
    let claim = creditor.settlement.claim(cycle_id).send().await?;
    assert_eq!(claim.route, Route::SelfFunded);
    let creditor_tokens_after = erc20_balance(&rpc_url, token, creditor_address).await?;
    assert_eq!(
        creditor_tokens_after - creditor_tokens_before,
        amount,
        "the full net credit must land on the creditor"
    );

    Ok(())
}

async fn erc20_balance(rpc_url: &str, token: Address, holder: Address) -> anyhow::Result<U256> {
    let provider = ProviderBuilder::new().connect(rpc_url).await?;
    Ok(OwnedERC20::new(token, &provider)
        .balanceOf(holder)
        .call()
        .await?)
}

async fn eth_balance(rpc_url: &str, address: Address) -> anyhow::Result<U256> {
    let response: serde_json::Value = reqwest::Client::new()
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBalance",
            "params": [format!("{address:#x}"), "latest"],
        }))
        .send()
        .await?
        .json()
        .await?;
    let raw = response["result"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("eth_getBalance returned no result: {response}"))?;
    Ok(U256::from_str_radix(raw.trim_start_matches("0x"), 16)?)
}
