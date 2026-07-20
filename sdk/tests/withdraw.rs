use alloy::primitives::Address;
use sdk_4mica::{
    Client, U256,
    error::{FinalizeWithdrawalError, RequestWithdrawalError},
};
use std::str::FromStr;
use std::time::Duration;

mod common;

use crate::common::{
    ETH_ASSET_ADDRESS, advance_chain_time, build_authed_user_config, eth_rpc_url,
    extract_asset_info, fund_user_with_erc20, mine_confirmations, wait_for_collateral_increase,
    withdrawal_grace_period,
};

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_withdrawal_request_and_cancel() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    // Setup user client
    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    )
    .await?;

    let _user_address = user_config.signer.address().to_string();
    let user_client = Client::new(user_config.clone()).await?;

    // Step 1: User deposits collateral (1 ETH)
    let user_info_initial = user_client.user.get_user().await?;
    let eth_asset_before = common::extract_asset_info(&user_info_initial, ETH_ASSET_ADDRESS)
        .expect("ETH asset not found");

    let deposit_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;
    mine_confirmations(&user_config, 2).await?;

    // Step 2: User requests withdrawal (0.5 ETH)
    let withdrawal_amount = U256::from(500_000_000_000_000_000u128); // 0.5 ETH
    let _receipt = user_client
        .user
        .request_withdrawal(withdrawal_amount, None)
        .await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 3: Check withdrawal request was recorded
    let user_info_after_request = user_client.user.get_user().await?;
    let eth_asset_after_request =
        common::extract_asset_info(&user_info_after_request, ETH_ASSET_ADDRESS)
            .expect("ETH asset not found");
    assert_eq!(
        eth_asset_after_request.withdrawal_request_amount,
        withdrawal_amount
    );
    assert!(eth_asset_after_request.withdrawal_request_timestamp > 0);

    // Step 4: Cancel the withdrawal
    let _receipt = user_client.user.cancel_withdrawal(None).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 5: Verify withdrawal was cancelled
    let user_info_after_cancel = user_client.user.get_user().await?;
    let eth_asset_after_cancel =
        common::extract_asset_info(&user_info_after_cancel, ETH_ASSET_ADDRESS)
            .expect("ETH asset not found");
    assert_eq!(
        eth_asset_after_cancel.withdrawal_request_amount,
        U256::from(0)
    );
    assert_eq!(eth_asset_after_cancel.withdrawal_request_timestamp, 0);

    // Collateral should remain unchanged
    assert_eq!(
        eth_asset_after_cancel.collateral,
        eth_asset_before.collateral + deposit_amount
    );

    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
#[test_log::test]
async fn test_withdrawal_finalization_grace_period_not_elapsed() -> anyhow::Result<()> {
    if common::skip_without_local_core_stack() {
        return Ok(());
    }

    // Setup user client
    let user_config = build_authed_user_config(
        "http://localhost:3000",
        // Default anvil account with prefunded ETH for gas on local fork/dev networks.
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )
    .await?;

    let user_client = Client::new(user_config.clone()).await?;

    // Step 1: User deposits collateral (2 ETH)
    let core_total_before = user_client
        .recipient
        .get_user_asset_balance(ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|info| info.total)
        .unwrap_or(U256::ZERO);
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;
    mine_confirmations(&user_config, 1).await?;

    wait_for_collateral_increase(
        &user_client.recipient,
        ETH_ASSET_ADDRESS,
        core_total_before,
        deposit_amount,
    )
    .await?;

    // Step 2: User requests withdrawal (1 ETH)
    let withdrawal_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let _receipt = user_client
        .user
        .request_withdrawal(withdrawal_amount, None)
        .await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 3: Finalize withdrawal
    let result = user_client.user.finalize_withdrawal(None).await;

    // Should fail with GracePeriodNotElapsed error
    assert!(
        matches!(result, Err(FinalizeWithdrawalError::GracePeriodNotElapsed)),
        "Expected withdrawal finalize to fail due to grace period not elapsed"
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

    // Setup user client
    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
    )
    .await?;

    let user_client = Client::new(user_config.clone()).await?;

    // Step 1: User deposits collateral (0.5 ETH)
    let core_total_before = user_client
        .recipient
        .get_user_asset_balance(ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|info| info.total)
        .unwrap_or(U256::ZERO);
    let deposit_amount = U256::from(500_000_000_000_000_000u128); // 0.5 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;
    mine_confirmations(&user_config, 1).await?;

    wait_for_collateral_increase(
        &user_client.recipient,
        ETH_ASSET_ADDRESS,
        core_total_before,
        deposit_amount,
    )
    .await?;

    // Step 2: Try to request withdrawal for more than deposited
    let user_info = user_client.user.get_user().await?;
    let eth_asset =
        common::extract_asset_info(&user_info, ETH_ASSET_ADDRESS).expect("ETH asset not found");

    let withdrawal_amount = eth_asset.collateral + U256::from(1_000_000_000_000_000_000u128);
    let result = user_client
        .user
        .request_withdrawal(withdrawal_amount, None)
        .await;

    // Should fail with InsufficientAvailable error
    assert!(
        matches!(result, Err(RequestWithdrawalError::InsufficientAvailable)),
        "Expected withdrawal request to fail due to insufficient collateral"
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
    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    )
    .await?;
    let user_client = Client::new(user_config.clone()).await?;

    // Step 1: deposit 1 ETH of collateral.
    let core_total_before = user_client
        .recipient
        .get_user_asset_balance(ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|info| info.total)
        .unwrap_or(U256::ZERO);
    let deposit_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;
    mine_confirmations(&user_config, 1).await?;
    wait_for_collateral_increase(
        &user_client.recipient,
        ETH_ASSET_ADDRESS,
        core_total_before,
        deposit_amount,
    )
    .await?;

    let collateral_before =
        extract_asset_info(&user_client.user.get_user().await?, ETH_ASSET_ADDRESS)
            .expect("ETH asset not found")
            .collateral;

    // Step 2: request a 0.5 ETH withdrawal.
    let withdrawal_amount = U256::from(500_000_000_000_000_000u128); // 0.5 ETH
    let _receipt = user_client
        .user
        .request_withdrawal(withdrawal_amount, None)
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 3: fast-forward the chain past the grace period snapshotted at request
    // time, then finalize. The grace defaults to weeks, so advancing wall-clock
    // time is impractical — we elapse it on anvil instead.
    let grace = withdrawal_grace_period(&user_config).await?;
    advance_chain_time(&user_config, grace + 60).await?;

    let _receipt = user_client.user.finalize_withdrawal(None).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 4: the request is cleared and collateral dropped by the withdrawn amount.
    let user_info = user_client.user.get_user().await?;
    let eth_asset = extract_asset_info(&user_info, ETH_ASSET_ADDRESS).expect("ETH asset not found");
    assert_eq!(eth_asset.withdrawal_request_amount, U256::ZERO);
    assert_eq!(eth_asset.withdrawal_request_timestamp, 0);
    assert_eq!(eth_asset.collateral, collateral_before - withdrawal_amount);

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
    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    )
    .await?;
    let user_address = user_config.signer.address();
    let user_client = Client::new(user_config.clone()).await?;

    // Pick the first ERC20 the contract accepts on this deployment.
    let supported = user_client.get_supported_tokens().await?;
    let token = supported
        .tokens
        .first()
        .expect("core must advertise at least one supported ERC20");
    let token_address = Address::from_str(&token.address)?;
    let amount = U256::from(10u64).pow(U256::from(token.decimals)); // 1 whole token

    // Step 1: fund, approve, and deposit the ERC20 as collateral.
    let rpc_url = eth_rpc_url(&user_config).await?;
    fund_user_with_erc20(&rpc_url, token_address, user_address, amount).await?;
    let total_before = user_client
        .recipient
        .get_user_asset_balance(token.address.clone())
        .await?
        .map(|balance| balance.total)
        .unwrap_or(U256::ZERO);
    user_client
        .user
        .approve_erc20(token.address.clone(), amount)
        .await?;
    user_client
        .user
        .deposit(amount, Some(token.address.clone()))
        .await?;
    mine_confirmations(&user_config, 2).await?;
    wait_for_collateral_increase(&user_client.recipient, token_address, total_before, amount)
        .await?;

    // Step 2: request a withdrawal of half the deposited ERC20.
    let withdrawal_amount = amount / U256::from(2u64);
    user_client
        .user
        .request_withdrawal(withdrawal_amount, Some(token.address.clone()))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 3: the request is recorded against the ERC20 asset.
    let user_info = user_client.user.get_user().await?;
    let asset_after_request =
        extract_asset_info(&user_info, token_address).expect("ERC20 asset not found");
    assert_eq!(
        asset_after_request.withdrawal_request_amount,
        withdrawal_amount
    );
    assert!(asset_after_request.withdrawal_request_timestamp > 0);

    // Step 4: cancel and verify the request is cleared.
    user_client
        .user
        .cancel_withdrawal(Some(token.address.clone()))
        .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let user_info_after_cancel = user_client.user.get_user().await?;
    let asset_after_cancel =
        extract_asset_info(&user_info_after_cancel, token_address).expect("ERC20 asset not found");
    assert_eq!(asset_after_cancel.withdrawal_request_amount, U256::ZERO);
    assert_eq!(asset_after_cancel.withdrawal_request_timestamp, 0);

    Ok(())
}
