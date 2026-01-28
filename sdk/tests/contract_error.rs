use rust_sdk_4mica::{
    Client, PaymentGuaranteeRequestClaims, SigningScheme, U256, error::RemunerateError,
};

mod common;

use crate::common::{
    ETH_ASSET_ADDRESS, build_authed_recipient_config, build_authed_user_config,
    wait_for_collateral_increase,
};

#[tokio::test]
#[serial_test::serial]
async fn test_decoding_contract_errors() -> anyhow::Result<()> {
    // These wallet keys are picked from the default accounts in anvil test node

    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    )
    .await?;

    let user_address = user_config.wallet_private_key.address().to_string();
    let user_client = Client::new(user_config).await?;

    let recipient_config = build_authed_recipient_config(
        "http://localhost:3000",
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )
    .await?;

    let recipient_address = recipient_config.wallet_private_key.address().to_string();
    let recipient_client = Client::new(recipient_config).await?;

    // Step 1: User deposits collateral (2 ETH)
    let core_total_before = recipient_client
        .recipient
        .get_user_asset_balance(user_address.clone(), ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|info| info.total)
        .unwrap_or(U256::ZERO);
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;

    wait_for_collateral_increase(
        &recipient_client.recipient,
        &user_address,
        ETH_ASSET_ADDRESS,
        core_total_before,
        deposit_amount,
    )
    .await?;

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
        req_id: U256::ZERO,
        amount: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        asset_address: ETH_ASSET_ADDRESS.to_string(),
    };
    let payment_sig = user_client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;

    println!(
        "Signed payment: tab_id={tab_id}, user={user_address}, recipient={recipient_address}, amount={}, asset={}, ts={}",
        claims.amount, claims.asset_address, claims.timestamp
    );

    // Step 4: User issues guarantee
    let bls_cert = recipient_client
        .recipient
        .issue_payment_guarantee(claims, payment_sig.signature, payment_sig.scheme)
        .await?;

    println!(
        "Issued BLS certificate: claims_len={}, signature_len={}",
        bls_cert.claims.len(),
        bls_cert.signature.len()
    );

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
    println!("Remunerate with mismatched cert -> {result:?}");
    assert!(matches!(result, Err(RemunerateError::CertificateMismatch)));

    let mut malformed = bls_cert.clone();
    malformed.signature.pop();
    let result = recipient_client.recipient.remunerate(malformed).await;
    println!("Remunerate with malformed cert -> {result:?}");
    assert!(matches!(
        result,
        Err(RemunerateError::CertificateInvalid(_))
    ));

    // Step 5: Recipient tries to remunerate immediately (should fail with TabNotYetOverdue)
    println!(
        "Remunerating with correct cert (claims_len={}, signature_len={})",
        bls_cert.claims.len(),
        bls_cert.signature.len()
    );
    let result = recipient_client.recipient.remunerate(bls_cert).await;
    dbg!(&result);
    assert!(matches!(result, Err(RemunerateError::TabNotYetOverdue)));
    Ok(())
}
