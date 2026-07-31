use alloy::primitives::{Address, utils::parse_ether};
use sdk_4mica::{
    Asset, U256,
    error::{FinalizeWithdrawalError, RequestWithdrawalError},
};
use std::str::FromStr;
use std::time::Duration;

mod common;

use crate::common::{
    ETH_ASSET_ADDRESS, advance_chain_time, authed_user_client, deposit_collateral_and_await,
    user_asset, withdrawal_grace_period,
};

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_withdrawal_request_and_cancel() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    let (config, client) =
        authed_user_client("0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97")
            .await?;

    let collateral_before = user_asset(&client, ETH_ASSET_ADDRESS).await?.collateral;
    let deposit_amount = parse_ether("1")?;
    deposit_collateral_and_await(&client, &config, None, deposit_amount).await?;

    // Request a 0.5 ETH withdrawal; it should be recorded against the asset.
    let withdrawal_amount = parse_ether("0.5")?;
    client
        .withdraw
        .request(Asset::Native, withdrawal_amount)
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let after_request = user_asset(&client, ETH_ASSET_ADDRESS).await?;
    assert_eq!(after_request.withdrawal_request_amount, withdrawal_amount);
    assert!(after_request.withdrawal_request_timestamp > 0);

    // Cancel it; the request clears and collateral is left unchanged.
    client.withdraw.cancel(Asset::Native).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let after_cancel = user_asset(&client, ETH_ASSET_ADDRESS).await?;
    assert_eq!(after_cancel.withdrawal_request_amount, U256::ZERO);
    assert_eq!(after_cancel.withdrawal_request_timestamp, 0);
    assert_eq!(after_cancel.collateral, collateral_before + deposit_amount);

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_withdrawal_finalization_grace_period_not_elapsed() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    // Default anvil account, prefunded with ETH for gas on local fork/dev networks.
    let (config, client) =
        authed_user_client("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
            .await?;

    deposit_collateral_and_await(&client, &config, None, parse_ether("2")?).await?;

    client
        .withdraw
        .request(Asset::Native, parse_ether("1")?)
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Finalizing before the grace period elapses must be rejected.
    let result = client.withdraw.finalize(Asset::Native).await;
    assert!(
        matches!(result, Err(FinalizeWithdrawalError::GracePeriodNotElapsed)),
        "expected withdrawal finalize to fail due to grace period not elapsed"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_withdrawal_insufficient_collateral() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    let (config, client) =
        authed_user_client("0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6")
            .await?;

    deposit_collateral_and_await(&client, &config, None, parse_ether("0.5")?).await?;

    // Requesting more than the deposited collateral must be rejected.
    let collateral = user_asset(&client, ETH_ASSET_ADDRESS).await?.collateral;
    let result = client
        .withdraw
        .request(Asset::Native, collateral + parse_ether("1")?)
        .await;
    assert!(
        matches!(result, Err(RequestWithdrawalError::InsufficientAvailable)),
        "expected withdrawal request to fail due to insufficient collateral"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_withdrawal_finalizes_after_grace_period() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    // Fresh anvil account (#3) so no prior locked collateral blocks the withdrawal.
    let (config, client) =
        authed_user_client("0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6")
            .await?;

    deposit_collateral_and_await(&client, &config, None, parse_ether("1")?).await?;
    let collateral_before = user_asset(&client, ETH_ASSET_ADDRESS).await?.collateral;

    let withdrawal_amount = parse_ether("0.5")?;
    client
        .withdraw
        .request(Asset::Native, withdrawal_amount)
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Fast-forward the chain past the grace period snapshotted at request time,
    // then finalize. The grace defaults to weeks, so advancing wall-clock time is
    // impractical — we elapse it on anvil instead.
    let grace = withdrawal_grace_period(&config).await?;
    advance_chain_time(&config, grace + 60).await?;
    client.withdraw.finalize(Asset::Native).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The request is cleared and collateral dropped by the withdrawn amount.
    let eth = user_asset(&client, ETH_ASSET_ADDRESS).await?;
    assert_eq!(eth.withdrawal_request_amount, U256::ZERO);
    assert_eq!(eth.withdrawal_request_timestamp, 0);
    assert_eq!(eth.collateral, collateral_before - withdrawal_amount);

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_erc20_withdrawal_request_and_cancel() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    // Fresh anvil account (#4), prefunded with ETH for gas.
    let (config, client) =
        authed_user_client("0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a")
            .await?;

    // Pick the first ERC20 the deployment supports.
    let supported = client.supported_tokens().await?;
    let token = supported
        .tokens
        .first()
        .expect("core must advertise at least one supported ERC20");
    let token_address = Address::from_str(&token.address)?;
    let amount = U256::from(10u64).pow(U256::from(token.decimals)); // 1 whole token

    deposit_collateral_and_await(&client, &config, Some(token.address.clone()), amount).await?;

    // Request a withdrawal of half; it is recorded against the ERC20 asset.
    let withdrawal_amount = amount / U256::from(2u64);
    client
        .withdraw
        .request(Asset::Erc20(token_address), withdrawal_amount)
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let after_request = user_asset(&client, token_address).await?;
    assert_eq!(after_request.withdrawal_request_amount, withdrawal_amount);
    assert!(after_request.withdrawal_request_timestamp > 0);

    // Cancel and verify the request clears.
    client.withdraw.cancel(Asset::Erc20(token_address)).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let after_cancel = user_asset(&client, token_address).await?;
    assert_eq!(after_cancel.withdrawal_request_amount, U256::ZERO);
    assert_eq!(after_cancel.withdrawal_request_timestamp, 0);

    Ok(())
}
