use sdk_4mica::client::recipient::RecipientClient;
use sdk_4mica::{
    Client, PaymentGuaranteeRequestClaims, SigningScheme, U256, error::VerifyGuaranteeError,
};
use std::time::Duration;

mod common;

use crate::common::{
    ETH_ASSET_ADDRESS, build_authed_recipient_config, build_authed_user_config,
    wait_for_collateral_increase,
};

async fn resolve_start_timestamp(recipient: &RecipientClient, tab_id: U256) -> anyhow::Result<u64> {
    if let Some(latest) = recipient.get_latest_guarantee(tab_id).await? {
        return Ok(latest.timestamp);
    }

    if let Some(tab) = recipient.get_tab(tab_id).await?
        && tab.start_timestamp > 0
    {
        return Ok(tab.start_timestamp as u64);
    }

    Ok(common::get_now().as_secs())
}

async fn resolve_next_req_id(recipient: &RecipientClient, tab_id: U256) -> anyhow::Result<U256> {
    if let Some(latest) = recipient.get_latest_guarantee(tab_id).await? {
        return Ok(latest.req_id + U256::from(1u64));
    }

    Ok(U256::ZERO)
}

#[tokio::test]
#[serial_test::serial]
async fn test_payment_flow_with_guarantee() -> anyhow::Result<()> {
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
        "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
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
    let start_timestamp = resolve_start_timestamp(&recipient_client.recipient, tab_id).await?;
    let req_id = resolve_next_req_id(&recipient_client.recipient, tab_id).await?;
    let claims = PaymentGuaranteeRequestClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id,
        amount: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
        timestamp: start_timestamp,
        asset_address: ETH_ASSET_ADDRESS.to_string(),
    };
    let payment_sig = user_client
        .user
        .sign_payment(claims.clone(), SigningScheme::Eip712)
        .await?;

    // Step 4: User issues guarantee
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
#[serial_test::serial]
async fn test_multiple_guarantees_increment_req_id() -> anyhow::Result<()> {
    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    )
    .await?;
    let user_address = user_config.wallet_private_key.address().to_string();
    let user_client = Client::new(user_config).await?;

    let recipient_config = build_authed_recipient_config(
        "http://localhost:3000",
        "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    )
    .await?;
    let recipient_address = recipient_config.wallet_private_key.address().to_string();
    let recipient_client = Client::new(recipient_config).await?;

    // Ensure sufficient collateral for two guarantees.
    let core_total_before = recipient_client
        .recipient
        .get_user_asset_balance(user_address.clone(), ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|info| info.total)
        .unwrap_or(U256::ZERO);

    let deposit_amount = U256::from(3_000_000_000_000_000_000u128); // 3 ETH
    let _receipt = user_client.user.deposit(deposit_amount, None).await?;

    wait_for_collateral_increase(
        &recipient_client.recipient,
        &user_address,
        ETH_ASSET_ADDRESS,
        core_total_before,
        deposit_amount,
    )
    .await?;

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

    let guarantees_before = recipient_client
        .recipient
        .get_tab_guarantees(tab_id)
        .await?;
    let guarantees_before_len = guarantees_before.len();

    let base_ts = resolve_start_timestamp(&recipient_client.recipient, tab_id).await?;

    // Issue first guarantee.
    let req_id = resolve_next_req_id(&recipient_client.recipient, tab_id).await?;
    let mut claims = PaymentGuaranteeRequestClaims {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id,
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
    claims.req_id = first_req_id + U256::from(1u64);
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
    assert_eq!(guarantees.len(), guarantees_before_len + 2);
    assert_eq!(guarantees[guarantees_before_len].req_id, first_req_id);
    assert_eq!(
        guarantees[guarantees_before_len + 1].req_id,
        parsed_second.req_id
    );

    Ok(())
}
