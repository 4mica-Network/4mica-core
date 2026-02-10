use sdk_4mica::{
    Client, U256,
    error::{FinalizeWithdrawalError, RequestWithdrawalError},
};
use std::time::Duration;

mod common;

use crate::common::{ETH_ASSET_ADDRESS, build_authed_user_config, wait_for_collateral_increase};

#[tokio::test]
#[serial_test::serial]
#[test_log::test]
async fn test_withdrawal_request_and_cancel() -> anyhow::Result<()> {
    // Setup user client
    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    )
    .await?;

    let user_address = user_config.signer.address().to_string();
    let user_client = Client::new(user_config).await?;

    // Step 1: User deposits collateral (1 ETH)
    let user_info_initial = user_client.user.get_user().await?;
    let eth_asset_before = common::extract_asset_info(&user_info_initial, ETH_ASSET_ADDRESS)
        .expect("ETH asset not found");

    let core_total_before = user_client
        .recipient
        .get_user_asset_balance(user_address.clone(), ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|info| info.total)
        .unwrap_or(U256::ZERO);
    let deposit_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;

    wait_for_collateral_increase(
        &user_client.recipient,
        &user_address,
        ETH_ASSET_ADDRESS,
        core_total_before,
        deposit_amount,
    )
    .await?;

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
#[serial_test::serial]
#[test_log::test]
async fn test_withdrawal_finalization_grace_period_not_elapsed() -> anyhow::Result<()> {
    // Setup user client
    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    )
    .await?;

    let user_address = user_config.signer.address().to_string();
    let user_client = Client::new(user_config).await?;

    // Step 1: User deposits collateral (2 ETH)
    let core_total_before = user_client
        .recipient
        .get_user_asset_balance(user_address.clone(), ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|info| info.total)
        .unwrap_or(U256::ZERO);
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;

    wait_for_collateral_increase(
        &user_client.recipient,
        &user_address,
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
#[serial_test::serial]
#[test_log::test]
async fn test_withdrawal_insufficient_collateral() -> anyhow::Result<()> {
    // Setup user client
    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
    )
    .await?;

    let user_address = user_config.signer.address().to_string();
    let user_client = Client::new(user_config).await?;

    // Step 1: User deposits collateral (0.5 ETH)
    let core_total_before = user_client
        .recipient
        .get_user_asset_balance(user_address.clone(), ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|info| info.total)
        .unwrap_or(U256::ZERO);
    let deposit_amount = U256::from(500_000_000_000_000_000u128); // 0.5 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;

    wait_for_collateral_increase(
        &user_client.recipient,
        &user_address,
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
