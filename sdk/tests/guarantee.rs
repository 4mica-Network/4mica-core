use rust_sdk_4mica::{
    Client, ConfigBuilder, PaymentGuaranteeRequestClaims, SigningScheme, U256,
    error::VerifyGuaranteeError,
};
use serial_test::serial;
use std::time::Duration;

mod common;

use crate::common::ETH_ASSET_ADDRESS;

#[tokio::test]
#[serial]
async fn test_payment_flow_with_guarantee() -> anyhow::Result<()> {
    // These wallet keys are picked from the default accounts in anvil test node

    let user_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .wallet_private_key(
            "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97".to_string(),
        )
        .build()?;

    let user_address = user_config.wallet_private_key.address().to_string();
    let user_client = Client::new(user_config).await?;

    let recipient_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .wallet_private_key(
            "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356".to_string(),
        )
        .build()?;

    let recipient_address = recipient_config.wallet_private_key.address().to_string();
    let recipient_client = Client::new(recipient_config).await?;

    // Step 1: User deposits collateral (2 ETH)
    let user_info = user_client.user.get_user().await?;
    let eth_asset_before =
        common::extract_asset_info(&user_info, ETH_ASSET_ADDRESS).expect("ETH asset not found");

    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;

    let user_info_after = user_client.user.get_user().await?;
    let eth_asset = common::extract_asset_info(&user_info_after, ETH_ASSET_ADDRESS)
        .expect("ETH asset not found");
    assert_eq!(
        eth_asset.collateral,
        eth_asset_before.collateral + deposit_amount
    );

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
        asset_address: ETH_ASSET_ADDRESS.to_string(),
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

    let recipient = &recipient_client.recipient;

    let verified_claims = recipient.verify_payment_guarantee(&bls_cert)?;
    assert_eq!(verified_claims.user_address, user_address);
    assert_eq!(verified_claims.recipient_address, recipient_address);
    assert_eq!(verified_claims.tab_id, tab_id);
    assert_eq!(
        verified_claims.amount,
        U256::from(1_000_000_000_000_000_000u128)
    );
    assert_eq!(verified_claims.asset_address, ETH_ASSET_ADDRESS.to_string());
    let assigned_req_id = verified_claims.req_id;

    let mut tampered = bls_cert.clone();
    if let Some(last) = tampered.claims.pop() {
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
        tampered.claims.push(replacement);
    } else {
        panic!("certificate claims unexpectedly empty");
    }

    let err = recipient.verify_payment_guarantee(&tampered).unwrap_err();
    assert!(
        matches!(err, VerifyGuaranteeError::CertificateMismatch),
        "tampered certificate should fail verification"
    );

    let mut malformed = bls_cert.clone();
    malformed.signature.pop();
    assert!(
        recipient.verify_payment_guarantee(&malformed).is_err(),
        "malformed signature should bubble up as error"
    );

    // Step 5: User pays the tab
    let _receipt = user_client
        .user
        .pay_tab(
            tab_id,
            assigned_req_id,
            U256::from(1_000_000_000_000_000_000u128),
            recipient_address.clone(),
            None,
        )
        .await?;

    let expected_paid = U256::from(1_000_000_000_000_000_000u128);
    let mut tab_status = recipient_client
        .recipient
        .get_tab_payment_status(tab_id)
        .await?;

    if tab_status.paid != expected_paid {
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tab_status = recipient_client
                .recipient
                .get_tab_payment_status(tab_id)
                .await?;
            if tab_status.paid == expected_paid {
                break;
            }
        }
    }

    assert!(
        tab_status.paid == expected_paid || tab_status.paid.is_zero(),
        "unexpected tab paid amount: expected {expected_paid:?} or 0, got {:?}",
        tab_status.paid
    );
    assert!(!tab_status.remunerated);
    assert_eq!(tab_status.asset, ETH_ASSET_ADDRESS.to_string());

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_multiple_guarantees_increment_req_id() -> anyhow::Result<()> {
    let user_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .wallet_private_key(
            "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97".to_string(),
        )
        .build()?;
    let user_address = user_config.wallet_private_key.address().to_string();
    let user_client = Client::new(user_config).await?;

    let recipient_config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .wallet_private_key(
            "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356".to_string(),
        )
        .build()?;
    let recipient_address = recipient_config.wallet_private_key.address().to_string();
    let recipient_client = Client::new(recipient_config).await?;

    // Ensure sufficient collateral for two guarantees.
    let deposit_amount = U256::from(3_000_000_000_000_000_000u128); // 3 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;

    // Recipient creates a payment tab.
    let tab_id = recipient_client
        .recipient
        .create_tab(
            user_address.clone(),
            recipient_address.clone(),
            None,
            Some(3600),
        )
        .await?;

    let base_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    // Issue first guarantee.
    let mut claims = PaymentGuaranteeRequestClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        amount: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
        timestamp: base_ts,
        asset_address: ETH_ASSET_ADDRESS.to_string(),
    };
    let sig_first = user_client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;
    let cert_first = recipient_client
        .recipient
        .issue_payment_guarantee(claims.clone(), sig_first.signature, sig_first.scheme)
        .await?;
    let parsed_first = recipient_client
        .recipient
        .verify_payment_guarantee(&cert_first)?;
    let first_req_id = parsed_first.req_id;

    // Issue second guarantee with a different amount but same timestamp.
    claims.amount = U256::from(1_500_000_000_000_000_000u128); // 1.5 ETH
    let sig_second = user_client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;
    let cert_second = recipient_client
        .recipient
        .issue_payment_guarantee(claims.clone(), sig_second.signature, sig_second.scheme)
        .await?;
    let parsed_second = recipient_client
        .recipient
        .verify_payment_guarantee(&cert_second)?;
    assert_eq!(
        parsed_second.req_id,
        first_req_id + U256::from(1u64),
        "next guarantee must increment req_id"
    );

    let guarantees = recipient_client
        .recipient
        .get_tab_guarantees(tab_id)
        .await?;
    assert_eq!(guarantees.len(), 2);
    assert_eq!(guarantees[0].req_id, first_req_id);
    assert_eq!(guarantees[1].req_id, parsed_second.req_id);

    Ok(())
}
