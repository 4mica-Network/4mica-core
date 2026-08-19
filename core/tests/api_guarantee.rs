//! HTTP API: payment-guarantee issuance and queries — sequential/out-of-order
//! req_ids, duplicate rejection, stablecoin assets, asset/recipient mismatch,
//! suspension blocking, and locked-collateral accounting.

use alloy::primitives::{Address, U256};
use chrono::Utc;
use core_service::auth::constants::SCOPE_GUARANTEE_ISSUE;
use core_service::config::DEFAULT_ASSET_ADDRESS;
use core_service::persist::canonical::{Canonical, ReqId};
use crypto::bls::BlsPublicKey;
use entities::guarantee as guarantee_entity;
use rpc::{ApiClientError, PaymentGuaranteeClaims};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::str::FromStr;

#[path = "common/mod.rs"]
mod common;
use common::api::*;
use common::fixtures::{ensure_user_with_collateral, random_address, read_locked_collateral};

// ════════════════════════ guarantee issuance & queries ════════════════════════
#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_guarantee_accepts_sequential_req_ids() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();

    let start_ts = chrono::Utc::now().timestamp() as u64;
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client.issue_guarantee(req0).await.expect("first ok");

    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(1u64),
        U256::from(2u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    core_client.issue_guarantee(req1).await.expect("second ok");

    let req_replay = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(1u64),
        U256::from(3u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    let result = core_client.issue_guarantee(req_replay).await;
    assert!(result.is_err(), "must reject replayed req_id");

    let guarantees = list_cycle_guarantees_for_recipient(&ctx, &recipient_addr).await?;
    assert_eq!(guarantees.len(), 2);
    assert_eq!(guarantees[0].req_id, ReqId(U256::ZERO).canonical());
    assert_eq!(guarantees[1].req_id, ReqId(U256::from(1u64)).canonical());

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_guarantee_rejects_timestamp_before_active_cycle() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();

    // The active cycle for `now` starts at the floored cycle boundary. A
    // timestamp one second before that boundary belongs to the previous cycle:
    // it is still `<= now` (so it clears the future-timestamp guard) but must be
    // rejected as stale/replayed. This is the strict cross-cycle replay defense.
    let cycle_secs = config.settlement_cycle.cycle_secs as i64;
    let now = Utc::now().timestamp();
    let period_start = now - now.rem_euclid(cycle_secs);
    let stale_ts = (period_start - 1) as u64;

    let stale_req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        Some(stale_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let err = core_client
        .issue_guarantee(stale_req)
        .await
        .expect_err("must reject a timestamp predating the active cycle");
    match err {
        ApiClientError::Api { status, message } => {
            assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
            assert!(
                message.contains("outside the active settlement cycle"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("unexpected error: {:?}", other),
    }

    // A timestamp exactly at the cycle boundary is in the active cycle and must
    // be accepted — the lower bound is inclusive.
    let fresh_req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        Some(period_start as u64),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client
        .issue_guarantee(fresh_req)
        .await
        .expect("timestamp at the cycle boundary should be accepted");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn core_api_guarantee_queries() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(5u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    core_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");

    let guarantees = list_cycle_guarantees_for_recipient(&ctx, &recipient_addr).await?;
    assert_eq!(guarantees.len(), 1);
    let guarantee = &guarantees[0];
    assert_eq!(guarantee.req_id, ReqId(U256::ZERO).canonical());
    assert_eq!(guarantee.value, U256::from(5u64).to_string());
    assert!(!guarantee.cycle_id.is_empty());
    assert!(!guarantee.guarantee_id.is_empty());

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn core_api_guarantee_history_ordering() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let shared_ts = Utc::now().timestamp() as u64;
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(5u64),
        &wallet,
        Some(shared_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client
        .issue_guarantee(req0)
        .await
        .expect("issue first guarantee");

    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(1u64),
        U256::from(7u64),
        &wallet,
        Some(shared_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client
        .issue_guarantee(req1)
        .await
        .expect("issue second guarantee");

    let guarantees = list_cycle_guarantees_for_recipient(&ctx, &recipient_addr).await?;
    assert_eq!(guarantees.len(), 2);
    assert_eq!(guarantees[0].req_id, ReqId(U256::ZERO).canonical());
    assert_eq!(guarantees[1].req_id, ReqId(U256::from(1u64)).canonical());
    assert_eq!(guarantees[1].value, U256::from(7u64).to_string());

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_two_guarantees_verifies_amount() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(100u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();

    let start_ts = chrono::Utc::now().timestamp() as u64;

    // Issue first guarantee with amount = 15
    let amount1 = U256::from(15u64);
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        amount1,
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    let cert1 = core_client
        .issue_guarantee(req0)
        .await
        .expect("first guarantee ok");

    // Decode first certificate and verify cycle-native amount and cycle id.
    let claims1 = PaymentGuaranteeClaims::try_from(cert1.claims().as_bytes())?;
    assert_eq!(claims1.amount, amount1);
    assert_ne!(claims1.cycle_id, U256::ZERO);

    // Issue second guarantee with amount = 27
    let amount2 = U256::from(27u64);
    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(1u64),
        amount2,
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    let cert2 = core_client
        .issue_guarantee(req1)
        .await
        .expect("second guarantee ok");

    // Decode second certificate and verify it belongs to the same active cycle.
    let claims2 = PaymentGuaranteeClaims::try_from(cert2.claims().as_bytes())?;
    assert_eq!(claims2.amount, amount2);
    assert_eq!(claims2.cycle_id, claims1.cycle_id);

    // Verify certificate is valid
    let pk = BlsPublicKey::from_bytes(&public_params.public_key)?;
    assert!(cert2.verify(&pk).is_ok());

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_guarantee_does_not_require_tab() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let cert = core_client
        .issue_guarantee(req)
        .await
        .expect("cycle-native guarantee should not require a tab");
    let claims = PaymentGuaranteeClaims::try_from(cert.claims().as_bytes())?;
    assert_eq!(claims.req_id, U256::ZERO);
    assert_ne!(claims.cycle_id, U256::ZERO);

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_guarantee_accepts_stablecoin_asset() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    insert_user_with_asset_collateral(&ctx, &user_addr, STABLE_ASSET_ADDRESS, U256::from(5u64))
        .await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        STABLE_ASSET_ADDRESS,
    )
    .await;

    let cert = core_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");
    let pk = BlsPublicKey::from_bytes(&public_params.public_key)?;
    assert!(cert.verify(&pk).is_ok());

    let stored = guarantee_entity::Entity::find()
        .filter(guarantee_entity::Column::ToAddress.eq(norm_addr(&recipient_addr)))
        .filter(guarantee_entity::Column::AssetAddress.eq(norm_addr(STABLE_ASSET_ADDRESS)))
        .one(&*ctx.db)
        .await
        .expect("query guarantee");
    let guarantee = stored.expect("guarantee stored");
    assert_eq!(guarantee.asset_address, STABLE_ASSET_ADDRESS);

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_guarantee_rejects_mismatched_asset_address() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    insert_user_with_asset_collateral(&ctx, &user_addr, STABLE_ASSET_ADDRESS, U256::from(5u64))
        .await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject mismatched asset address");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_guarantee_uses_signed_user_without_tab_match() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let tab_user_addr = alloy::signers::local::PrivateKeySigner::random()
        .address()
        .to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &tab_user_addr, U256::from(5u64)).await?;

    let other_wallet = alloy::signers::local::PrivateKeySigner::random();
    let other_user_addr = other_wallet.address().to_string();
    ensure_user_with_collateral(&ctx, &other_user_addr, U256::from(5u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &other_user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(1u64),
        &other_wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let cert = core_client
        .issue_guarantee(req)
        .await
        .expect("cycle-native issuance should not validate against tab user");
    let claims = PaymentGuaranteeClaims::try_from(cert.claims().as_bytes())?;
    assert_eq!(
        Address::from_str(&claims.user_address)?,
        Address::from_str(&other_user_addr)?
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_guarantee_rejects_mismatched_recipient_address() -> anyhow::Result<()> {
    let (_config, core_client, ctx, _auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    let forged_recipient_addr = random_address();
    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &forged_recipient_addr,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject mismatched recipient address");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_guarantee_accepts_out_of_order_req_ids() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();

    let req_b = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(1u64),
        U256::from(5u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result_b = core_client.issue_guarantee(req_b).await;
    assert!(result_b.is_ok(), "Guarantee with req_id 1 should succeed");

    let req_a = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(3u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result_a = core_client.issue_guarantee(req_a).await;
    assert!(
        result_a.is_ok(),
        "Guarantee with req_id 0 should succeed even after req_id 1"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn suspending_recipient_blocks_guarantee_requests() -> anyhow::Result<()> {
    let (config, core_client, ctx, _) = setup_http_test_environment().await?;

    let user_wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = user_wallet.address().to_string();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    let recipient_wallet = alloy::signers::local::PrivateKeySigner::random();
    let recipient_addr = recipient_wallet.address().to_string();
    let recipient_client = client_with_signer(
        &config,
        &ctx,
        &recipient_wallet,
        "recipient",
        &[SCOPE_GUARANTEE_ISSUE],
    )
    .await?;

    let public_params = core_client.get_public_params().await?;
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(1u64),
        &user_wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    core_client
        .update_user_suspension(recipient_addr.clone(), true)
        .await
        .expect("suspend recipient");

    let err = recipient_client
        .issue_guarantee(req)
        .await
        .expect_err("suspended recipient should not receive guarantees");
    match err {
        ApiClientError::Api { status, message } => {
            assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
            assert!(
                message.contains("user suspended"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("unexpected error: {:?}", other),
    }

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn suspending_user_blocks_guarantee_requests() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;
    let recipient_addr = auth.address.clone();

    let user_wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = user_wallet.address().to_string();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    let public_params = core_client.get_public_params().await?;
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(1u64),
        &user_wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    core_client
        .update_user_suspension(user_addr.clone(), true)
        .await
        .expect("suspend user");

    let err = core_client
        .issue_guarantee(req)
        .await
        .expect_err("suspended user should not receive guarantees");
    match err {
        ApiClientError::Api { status, message } => {
            assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
            assert!(
                message.contains("user suspended"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("unexpected error: {:?}", other),
    }

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issued_guarantee_increases_locked_collateral() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    let locked_before = read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(7u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");

    let locked_after = read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(locked_after - locked_before, U256::from(7u64));

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_guarantee_rejected_when_collateral_insufficient() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_http_test_environment().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(3u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::ZERO,
        U256::from(10u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(
        result.is_err(),
        "must reject guarantee that exceeds available collateral"
    );

    Ok(())
}
