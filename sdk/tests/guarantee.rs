use rust_sdk_4mica::{Client, ConfigBuilder, PaymentGuaranteeClaims, SigningScheme, U256};
use std::time::Duration;

#[tokio::test]
async fn test_payment_flow_with_guarantee() -> anyhow::Result<()> {
    // These wallet keys are picked from the default accounts in anvil test node

    let user_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .chain_id(31337)
        .wallet_private_key(
            "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97".to_string(),
        )
        .build()?;

    let user_address = user_config.wallet_private_key.address().to_string();
    let user_client = Client::new(user_config).await?;

    let recipient_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .chain_id(31337)
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
        .create_tab(user_address.clone(), recipient_address.clone(), Some(3600))
        .await?;

    // Step 3: User signs a payment (1 ETH)
    let claims = PaymentGuaranteeClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id: U256::from(0),
        amount: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    };
    let payment_sig = user_client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;

    // Step 4: Recipient issues guarantee
    let _bls_cert = recipient_client
        .recipient
        .issue_payment_guarantee(claims, payment_sig.signature, payment_sig.scheme)
        .await?;

    // Step 5: User pays the tab
    let _receipt = user_client
        .user
        .pay_tab(
            tab_id,
            U256::from(0),
            U256::from(1_000_000_000_000_000_000u128),
            recipient_address.clone(),
        )
        .await?;

    Ok(())
}
