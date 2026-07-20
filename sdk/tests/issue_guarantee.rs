use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::{Client, Config, PaymentGuaranteeRequestClaims, SigningScheme, U256};
use std::str::FromStr;
mod common;
use crate::common::{
    ETH_ASSET_ADDRESS, build_authed_recipient_config, eth_rpc_url, fund_user_with_erc20, get_now,
    mine_confirmations, wait_for_collateral_increase,
};

const WALLET_KEY: &str = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_issue_and_verify_payment_guarantee() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    let config = build_authed_recipient_config("http://localhost:3000", WALLET_KEY).await?;
    let wallet_address = config.signer.address();
    let client = Client::new(config.clone()).await?;
    let rpc_url = eth_rpc_url(&config).await?;

    // Native ETH first, then every ERC20 the deployment supports (USDC, etc.).
    issue_and_verify_for_asset(&client, &config, wallet_address, None, 18, &rpc_url).await?;

    let supported = client.get_supported_tokens().await?;
    assert!(
        !supported.tokens.is_empty(),
        "core must advertise at least one supported ERC20"
    );
    for token in &supported.tokens {
        issue_and_verify_for_asset(
            &client,
            &config,
            wallet_address,
            Some(token.address.clone()),
            token.decimals,
            &rpc_url,
        )
        .await
        .map_err(|err| anyhow::anyhow!("{} ({}): {err}", token.symbol, token.address))?;
    }

    Ok(())
}

async fn issue_and_verify_for_asset(
    client: &Client<PrivateKeySigner>,
    config: &Config<PrivateKeySigner>,
    wallet_address: Address,
    erc20_token: Option<String>,
    decimals: u8,
    rpc_url: &str,
) -> anyhow::Result<()> {
    let asset_address = match &erc20_token {
        Some(token) => Address::from_str(token)?,
        None => ETH_ASSET_ADDRESS,
    };
    let unit = U256::from(10u64).pow(U256::from(decimals));
    let deposit_amount = unit;
    let guarantee_amount = unit / U256::from(10u64);

    let balance_before = client
        .recipient
        .get_user_asset_balance(asset_address.to_string())
        .await?;
    let total_before = balance_before.as_ref().map_or(U256::ZERO, |b| b.total);
    let locked_before = balance_before.as_ref().map_or(U256::ZERO, |b| b.locked);
    if let Some(token) = &erc20_token {
        fund_user_with_erc20(rpc_url, asset_address, wallet_address, deposit_amount).await?;
        client
            .user
            .approve_erc20(token.clone(), deposit_amount)
            .await?;
    }

    client
        .user
        .deposit(deposit_amount, erc20_token.clone())
        .await?;
    mine_confirmations(config, 2).await?;
    wait_for_collateral_increase(
        &client.recipient,
        asset_address,
        total_before,
        deposit_amount,
    )
    .await?;

    let req_id = U256::from(get_now().as_nanos());
    let claims = PaymentGuaranteeRequestClaims::new(
        wallet_address.to_string(),
        wallet_address.to_string(),
        req_id,
        guarantee_amount,
        get_now().as_secs(),
        erc20_token.clone(),
    );

    let signature = client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;

    let cert = client
        .recipient
        .issue_payment_guarantee(claims.clone(), signature.signature, SigningScheme::Eip712)
        .await?;

    let verified = client.recipient.verify_payment_guarantee(&cert)?;

    assert_eq!(
        Address::from_str(&verified.user_address)?,
        wallet_address,
        "verified user address should match the signer"
    );
    assert_eq!(
        Address::from_str(&verified.recipient_address)?,
        wallet_address,
        "verified recipient address should match the issuer"
    );
    assert_eq!(verified.amount, guarantee_amount);
    assert_eq!(verified.req_id, req_id);
    assert_eq!(Address::from_str(&verified.asset_address)?, asset_address);

    let locked_after = client
        .recipient
        .get_user_asset_balance(asset_address.to_string())
        .await?
        .map_or(U256::ZERO, |balance| balance.locked);
    assert_eq!(
        locked_after,
        locked_before + guarantee_amount,
        "core should lock the guarantee amount in the user's balance for asset {asset_address}"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_issue_duplicate_guarantee_is_rejected() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    let config = build_authed_recipient_config("http://localhost:3000", WALLET_KEY).await?;
    let wallet_address = config.signer.address();
    let client = Client::new(config.clone()).await?;

    let guarantee_amount = U256::from(50_000_000_000_000_000u128); // 0.05 ETH
    let deposit_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH

    let total_before = client
        .recipient
        .get_user_asset_balance(ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|balance| balance.total)
        .unwrap_or(U256::ZERO);

    client.user.deposit(deposit_amount, None).await?;
    mine_confirmations(&config, 2).await?;
    wait_for_collateral_increase(
        &client.recipient,
        ETH_ASSET_ADDRESS,
        total_before,
        deposit_amount,
    )
    .await?;

    let req_id = U256::from(get_now().as_nanos());
    let claims = PaymentGuaranteeRequestClaims::new(
        wallet_address.to_string(),
        wallet_address.to_string(),
        req_id,
        guarantee_amount,
        get_now().as_secs(),
        None,
    );

    let signature = client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;

    // First issuance succeeds.
    client
        .recipient
        .issue_payment_guarantee(
            claims.clone(),
            signature.signature.clone(),
            SigningScheme::Eip712,
        )
        .await?;

    // Replaying the identical request is rejected.
    let err = client
        .recipient
        .issue_payment_guarantee(claims.clone(), signature.signature, SigningScheme::Eip712)
        .await
        .expect_err("expected duplicate guarantee to be rejected");

    let message = err.to_string().to_lowercase();
    assert!(
        message.contains("already exists"),
        "expected a duplicate-guarantee rejection, got: {err:?}"
    );

    Ok(())
}
