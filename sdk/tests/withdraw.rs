use rust_sdk_4mica::{
    Client, ConfigBuilder, U256,
    error::{FinalizeWithdrawalError, RequestWithdrawalError},
};
use std::time::Duration;

#[tokio::test]
#[test_log::test]
async fn test_withdrawal_request_and_cancel() -> anyhow::Result<()> {
    // Setup user client
    let user_config = ConfigBuilder::default()
        .wallet_private_key(
            "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97".to_string(),
        )
        .build()?;

    let user_client = Client::new(user_config).await?;

    // Step 1: User deposits collateral (1 ETH)
    let user_info_initial = user_client.user.get_user().await?;
    let deposit_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let _receipt = user_client.user.deposit(deposit_amount).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 2: User requests withdrawal (0.5 ETH)
    let withdrawal_amount = U256::from(500_000_000_000_000_000u128); // 0.5 ETH
    let _receipt = user_client
        .user
        .request_withdrawal(withdrawal_amount)
        .await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 3: Check withdrawal request was recorded
    let user_info_after_request = user_client.user.get_user().await?;
    assert_eq!(
        user_info_after_request.withdrawal_request_amount,
        withdrawal_amount
    );
    assert!(user_info_after_request.withdrawal_request_timestamp > 0);

    // Step 4: Cancel the withdrawal
    let _receipt = user_client.user.cancel_withdrawal().await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 5: Verify withdrawal was cancelled
    let user_info_after_cancel = user_client.user.get_user().await?;
    assert_eq!(
        user_info_after_cancel.withdrawal_request_amount,
        U256::from(0)
    );
    assert_eq!(user_info_after_cancel.withdrawal_request_timestamp, 0);

    // Collateral should remain unchanged
    assert_eq!(
        user_info_after_cancel.collateral,
        user_info_initial.collateral + deposit_amount
    );

    Ok(())
}

#[tokio::test]
#[test_log::test]
async fn test_withdrawal_finalization_grace_period_not_elapsed() -> anyhow::Result<()> {
    // Setup user client
    let user_config = ConfigBuilder::default()
        .wallet_private_key(
            "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356".to_string(),
        )
        .build()?;

    let user_client = Client::new(user_config).await?;

    // Step 1: User deposits collateral (2 ETH)
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 2: User requests withdrawal (1 ETH)
    let withdrawal_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let _receipt = user_client
        .user
        .request_withdrawal(withdrawal_amount)
        .await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 3: Finalize withdrawal
    let result = user_client.user.finalize_withdrawal().await;

    // Should fail with GracePeriodNotElapsed error
    assert!(
        matches!(result, Err(FinalizeWithdrawalError::GracePeriodNotElapsed)),
        "Expected withdrawal finalize to fail due to grace period not elapsed"
    );

    Ok(())
}

#[tokio::test]
#[test_log::test]
async fn test_withdrawal_insufficient_collateral() -> anyhow::Result<()> {
    // Setup user client
    let user_config = ConfigBuilder::default()
        .wallet_private_key(
            "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6".to_string(),
        )
        .build()?;

    let user_client = Client::new(user_config).await?;

    // Step 1: User deposits collateral (0.5 ETH)
    let deposit_amount = U256::from(500_000_000_000_000_000u128); // 0.5 ETH
    let _receipt = user_client.user.deposit(deposit_amount).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 2: Try to request withdrawal for more than deposited
    let user_info = user_client.user.get_user().await?;

    let withdrawal_amount = user_info.collateral + U256::from(1_000_000_000_000_000_000u128);
    let result = user_client.user.request_withdrawal(withdrawal_amount).await;

    // Should fail with InsufficientAvailable error
    assert!(
        matches!(result, Err(RequestWithdrawalError::InsufficientAvailable)),
        "Expected withdrawal request to fail due to insufficient collateral"
    );

    Ok(())
}
