use rust_sdk_4mica::{
    Client, ConfigBuilder, PaymentGuaranteeRequestClaims, SigningScheme, U256,
    error::RemunerateError,
};
use std::time::Duration;

#[tokio::test]
async fn test_decoding_contract_errors() -> anyhow::Result<()> {
    // These wallet keys are picked from the default accounts in anvil test node

    let user_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .wallet_private_key(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string(),
        )
        .build()?;

    let user_address = user_config.wallet_private_key.address().to_string();
    let user_client = Client::new(user_config).await?;

    let recipient_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .wallet_private_key(
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".to_string(),
        )
        .build()?;

    let recipient_address = recipient_config.wallet_private_key.address().to_string();
    let recipient_client = Client::new(recipient_config).await?;

    // Step 1: User deposits collateral (2 ETH)
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;

    // Wait for transaction to settle
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Step 2: Recipient creates a payment tab
    let tab_id = recipient_client
        .recipient
        .create_tab(
            user_address.clone(),
            recipient_address.clone(),
            None,
            Some(3600),
        )
        .await?;

    // Step 3: User signs a payment (1 ETH)
    let claims = PaymentGuaranteeRequestClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        amount: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        asset_address: "0x0000000000000000000000000000000000000000".into(),
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

    let mut mismatched = bls_cert.clone();
    if let Some(last) = mismatched.claims.pop() {
        let replacement = match last {
            '0' => '1',
            '1' => '2',
            '2' => '3',
            '3' => '4',
            '4' => '5',
            '5' => '6',
            '6' => '7',
            '7' => '8',
            '8' => '9',
            '9' => 'a',
            'a' => 'b',
            'b' => 'c',
            'c' => 'd',
            'd' => 'e',
            'e' => 'f',
            _ => '0',
        };
        mismatched.claims.push(replacement);
    } else {
        panic!("certificate claims unexpectedly empty");
    }

    let result = recipient_client.recipient.remunerate(mismatched).await;
    assert!(matches!(result, Err(RemunerateError::CertificateMismatch)));

    let mut malformed = bls_cert.clone();
    malformed.signature.pop();
    let result = recipient_client.recipient.remunerate(malformed).await;
    assert!(matches!(
        result,
        Err(RemunerateError::CertificateInvalid(_))
    ));

    // Step 5: Recipient tries to remunerate immediately (should fail with TabNotYetOverdue)
    let result = recipient_client.recipient.remunerate(bls_cert).await;
    dbg!(&result);
    assert!(matches!(result, Err(RemunerateError::TabNotYetOverdue)));
    Ok(())
}
