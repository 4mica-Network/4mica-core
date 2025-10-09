use rust_sdk_4mica::{
    Client, ConfigBuilder, PaymentGuaranteeClaims, SigningScheme, U256, error::RemunerateError,
};
use std::time::Duration;

mod common;

#[tokio::test]
#[test_log::test]
async fn test_recipient_remuneration() -> anyhow::Result<()> {
    // These wallet keys are picked from the default accounts in anvil test node

    let user_config = ConfigBuilder::default()
        .wallet_private_key(
            "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97".to_string(),
        )
        .build()?;

    let user_address = user_config.wallet_private_key.address().to_string();
    let user_client = Client::new(user_config).await?;

    let recipient_config = ConfigBuilder::default()
        .wallet_private_key(
            "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356".to_string(),
        )
        .build()?;

    let recipient_address = recipient_config.wallet_private_key.address().to_string();
    let recipient_client = Client::new(recipient_config).await?;

    // Step 1: User deposits collateral (2 ETH)
    let user_info = user_client.user.get_user().await?;

    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount).await?;

    let user_info_after = user_client.user.get_user().await?;

    assert_eq!(
        user_info_after.collateral,
        user_info.collateral + deposit_amount
    );

    // Wait for transaction to settle
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 2: Recipient creates a payment tab
    let tab_id = recipient_client
        .recipient
        .create_tab(
            user_address.clone(),
            recipient_address.clone(),
            Some(3600 * 24 * 21), // 21 days
        )
        .await?;

    let guarantee_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    // Step 3: User signs a payment (1 ETH)
    let claims = PaymentGuaranteeClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id: U256::from(0),
        amount: guarantee_amount,
        timestamp: common::get_now().as_secs() - 3600 * 24 * 15, // 15 days ago (to avoid the contract revert)
    };
    let payment_sig = user_client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;

    // Step 4: Recipient issues guarantee
    let bls_cert = recipient_client
        .recipient
        .issue_payment_guarantee(claims, payment_sig.signature, payment_sig.scheme)
        .await?;

    // Step 5: Recipient remunerates the tab
    let _receipt = recipient_client
        .recipient
        .remunerate(bls_cert)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to remunerate the tab: {}", e))?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 6: User checks collateral
    let user_info_after = user_client.user.get_user().await?;

    assert_eq!(
        user_info_after.collateral,
        user_info.collateral + deposit_amount - guarantee_amount
    );

    // Step 7: Recipient checks the tab payment status
    let tab_status = recipient_client
        .recipient
        .get_tab_payment_status(tab_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get the tab payment status: {}", e))?;

    assert!(tab_status.remunerated);

    Ok(())
}

#[tokio::test]
#[test_log::test]
async fn test_double_remuneration_fails() -> anyhow::Result<()> {
    // These wallet keys are picked from the default accounts in anvil test node

    let user_config = ConfigBuilder::default()
        .wallet_private_key(
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".to_string(),
        )
        .build()?;

    let user_address = user_config.wallet_private_key.address().to_string();
    let user_client = Client::new(user_config).await?;

    let recipient_config = ConfigBuilder::default()
        .wallet_private_key(
            "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a".to_string(),
        )
        .build()?;

    let recipient_address = recipient_config.wallet_private_key.address().to_string();
    let recipient_client = Client::new(recipient_config).await?;

    // Step 1: User deposits collateral (2 ETH)
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount).await?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 2: Recipient creates a payment tab
    let tab_id = recipient_client
        .recipient
        .create_tab(
            user_address.clone(),
            recipient_address.clone(),
            Some(3600 * 24 * 21), // 21 days
        )
        .await?;

    let guarantee_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH

    // Step 3: User signs a payment (1 ETH)
    let claims = PaymentGuaranteeClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id: U256::from(0),
        amount: guarantee_amount,
        timestamp: common::get_now().as_secs() - 3600 * 24 * 15, // 15 days ago
    };
    let payment_sig = user_client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;

    // Step 4: Recipient issues guarantee
    let bls_cert = recipient_client
        .recipient
        .issue_payment_guarantee(claims, payment_sig.signature, payment_sig.scheme)
        .await?;

    // Step 5: Recipient remunerates the tab
    let _receipt = recipient_client
        .recipient
        .remunerate(bls_cert.clone())
        .await?;

    tokio::time::sleep(Duration::from_secs(1)).await;

    // Step 6: Recipient remunerates the tab again
    let result = recipient_client.recipient.remunerate(bls_cert).await;

    // Should fail with InvalidSignature error
    assert!(matches!(
        result,
        Err(RemunerateError::TabPreviouslyRemunerated)
    ));

    Ok(())
}
