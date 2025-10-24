use alloy::{
    primitives::{Address, Signature, U256},
    signers::Signer,
    sol_types::{SolStruct, eip712_domain, sol},
};
use alloy_sol_types::SolValue;
use chrono::{Duration, Utc};
use core_service::config::{AppConfig, DEFAULT_ASSET_ADDRESS};
use core_service::persist::{PersistCtx, repo};
use core_service::{auth::verify_promise_signature, util::u256_to_string};
use entities::sea_orm_active_enums::CollateralEventType;
use entities::{collateral_event, guarantee as guarantee_entity};
use rand::random;
use rpc::{
    common::{
        CreatePaymentTabRequest, PaymentGuaranteeClaims, PaymentGuaranteeRequest, SigningScheme,
    },
    core::{CoreApiClient, CorePublicParameters},
    proxy::RpcProxy,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use std::str::FromStr;
use uuid::Uuid;

#[path = "common/mod.rs"]
mod common;
use common::fixtures::{
    clear_all_tables, ensure_user_with_collateral, init_test_env, random_address,
};

const STABLE_ASSET_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

async fn setup_clean_db() -> Option<(AppConfig, RpcProxy, PersistCtx)> {
    let (config, ctx) = init_test_env().await.ok()?;
    let core_addr = format!(
        "http://{}:{}",
        config.server_config.host, config.server_config.port
    );
    let core_client = RpcProxy::new(&core_addr).ok()?;

    clear_all_tables(&ctx).await.ok()?;

    Some((config, core_client, ctx))
}

async fn insert_user_with_collateral(ctx: &PersistCtx, addr: &str, amount: U256) -> bool {
    match ensure_user_with_collateral(ctx, addr, amount).await {
        Ok(_) => true,
        Err(err) => {
            eprintln!("skipping test: failed to seed user collateral: {err}");
            false
        }
    }
}

async fn insert_user_with_asset_collateral(
    ctx: &PersistCtx,
    addr: &str,
    asset: &str,
    amount: U256,
) -> bool {
    if let Err(err) = common::fixtures::ensure_user(ctx, addr).await {
        eprintln!("skipping test: failed to ensure user: {err}");
        return false;
    }
    if let Err(err) = repo::deposit(ctx, addr.to_string(), asset.to_string(), amount).await {
        eprintln!("skipping test: failed to deposit collateral: {err}");
        return false;
    }
    true
}

#[allow(clippy::too_many_arguments)]
async fn build_signed_req(
    public_params: &CorePublicParameters,
    user_addr: &str,
    recipient_addr: &str,
    tab_id: U256,
    req_id: U256,
    amount: U256,
    wallet: &alloy::signers::local::PrivateKeySigner,
    timestamp: Option<u64>,
    asset_address: &str,
) -> PaymentGuaranteeRequest {
    sol! {
        struct PaymentGuarantee {
            address user;
            address recipient;
            uint256 tabId;
            uint256  reqId;
            uint256 amount;
            uint64  timestamp;
        }
    }

    let ts = timestamp.unwrap_or_else(|| Utc::now().timestamp() as u64);
    let domain = eip712_domain!(
        name: public_params.eip712_name.clone(),
        version: public_params.eip712_version.clone(),
        chain_id: public_params.chain_id,
    );
    let msg = PaymentGuarantee {
        user: Address::from_str(user_addr).unwrap(),
        recipient: Address::from_str(recipient_addr).unwrap(),
        tabId: tab_id,
        reqId: req_id,
        amount,
        timestamp: ts,
    };
    let digest = msg.eip712_signing_hash(&domain);
    let sig: Signature = wallet.sign_hash(&digest).await.unwrap();
    PaymentGuaranteeRequest {
        claims: PaymentGuaranteeClaims {
            user_address: user_addr.to_string(),
            recipient_address: recipient_addr.to_string(),
            tab_id,
            req_id,
            amount,
            timestamp: ts,
            asset_address: asset_address.to_string(),
        },
        signature: crypto::hex::encode_hex(&sig.as_bytes()),
        scheme: SigningScheme::Eip712,
    }
}

async fn build_eip712_signed_request(
    params: &CorePublicParameters,
    wallet: &alloy::signers::local::PrivateKeySigner,
) -> PaymentGuaranteeRequest {
    sol! {
        struct PaymentGuarantee {
            address user;
            address recipient;
            uint256  tabId;
            uint256  reqId;
            uint256 amount;
            uint64  timestamp;
        }
    }

    let timestamp = Utc::now().timestamp() as u64;
    let req_id_u64 = 0u64;

    let domain = eip712_domain!(
        name:     params.eip712_name.clone(),
        version:  params.eip712_version.clone(),
        chain_id: params.chain_id,
    );

    let recipient = Address::from(random::<[u8; 20]>());
    let msg = PaymentGuarantee {
        user: wallet.address(),
        recipient,
        tabId: U256::from(0x7461622d6f6b32u128),
        reqId: U256::from(req_id_u64),
        amount: U256::from(42u64),
        timestamp,
    };
    let digest = msg.eip712_signing_hash(&domain);
    let sig: Signature = wallet.sign_hash(&digest).await.unwrap();

    PaymentGuaranteeRequest {
        claims: PaymentGuaranteeClaims {
            user_address: wallet.address().to_string(),
            recipient_address: recipient.to_string(),
            tab_id: U256::from(0x7461622d6f6b32u128),
            req_id: U256::from(0u64),
            amount: U256::from(42u64),
            timestamp,
            asset_address: "0x0000000000000000000000000000000000000000".into(),
        },
        signature: crypto::hex::encode_hex(&sig.as_bytes()),
        scheme: SigningScheme::Eip712,
    }
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_future_timestamp() {
    let Some((_config, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await {
        return;
    }

    let public_params = core_client.get_public_params().await.unwrap();
    let future_ts = (Utc::now() + Duration::hours(1)).timestamp() as u64;
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(0x7461622d667574757265u128),
        U256::from(0u64),
        U256::from(1u64),
        &wallet,
        Some(future_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject promise with future timestamp");
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_insufficient_collateral() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(1u64)).await {
        return;
    }

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(0x7461622d6e6f636f6c6c61746572616cu128),
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
        "must reject when collateral is insufficient"
    );
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_wrong_req_id_sequence() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await {
        return;
    }

    let public_params = core_client.get_public_params().await.unwrap();

    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await
        .expect("create tab");

    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client.issue_guarantee(req0).await.expect("first ok");

    let req2 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::from(2u64),
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req2).await;
    assert!(result.is_err(), "must reject non-sequential req_id");
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_guarantee_queries() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await {
        return;
    }

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(900),
        })
        .await
        .expect("create tab")
        .id;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
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

    let guarantees = core_client
        .get_tab_guarantees(tab_id)
        .await
        .expect("get tab guarantees");
    assert_eq!(guarantees.len(), 1);
    let guarantee = &guarantees[0];
    assert_eq!(guarantee.tab_id, tab_id);
    assert!(guarantee.certificate.is_some());

    let latest = core_client
        .get_latest_guarantee(tab_id)
        .await
        .expect("latest guarantee")
        .expect("exists");
    assert_eq!(latest.req_id, guarantee.req_id);

    let specific = core_client
        .get_guarantee(tab_id, guarantee.req_id)
        .await
        .expect("specific guarantee")
        .expect("found");
    assert_eq!(specific.amount, guarantee.amount);
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_guarantee_history_ordering() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await {
        return;
    }

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(1200),
        })
        .await
        .expect("create tab")
        .id;

    let public_params = core_client.get_public_params().await.unwrap();
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        U256::from(5u64),
        &wallet,
        None,
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
        tab_id,
        U256::from(1u64),
        U256::from(7u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client
        .issue_guarantee(req1)
        .await
        .expect("issue second guarantee");

    let guarantees = core_client
        .get_tab_guarantees(tab_id)
        .await
        .expect("get guarantees");
    assert_eq!(guarantees.len(), 2);
    assert_eq!(guarantees[0].req_id, U256::ZERO);
    assert_eq!(guarantees[1].req_id, U256::from(1u64));

    let latest = core_client
        .get_latest_guarantee(tab_id)
        .await
        .expect("latest guarantee")
        .expect("exists");
    assert_eq!(latest.req_id, U256::from(1u64));
    assert_eq!(latest.amount, U256::from(7u64));
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_guarantee_queries_empty_state() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let user_addr = random_address();
    let recipient_addr = random_address();
    if common::fixtures::ensure_user(&ctx, &user_addr)
        .await
        .is_err()
    {
        return;
    }

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(300),
        })
        .await
        .expect("create tab")
        .id;

    let empty_guarantees = core_client
        .get_tab_guarantees(tab_id)
        .await
        .expect("get empty guarantees");
    assert!(empty_guarantees.is_empty());

    let latest = core_client
        .get_latest_guarantee(tab_id)
        .await
        .expect("latest empty");
    assert!(latest.is_none());

    let specific = core_client
        .get_guarantee(tab_id, U256::ZERO)
        .await
        .expect("specific empty");
    assert!(specific.is_none());
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_pending_remunerations_clear_after_settlement() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(12u64)).await {
        return;
    }

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(900),
        })
        .await
        .expect("create tab")
        .id;

    let params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        U256::from(3u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");

    let pending = core_client
        .list_pending_remunerations(recipient_addr.clone())
        .await
        .expect("pending rems");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].tab.tab_id, tab_id);

    repo::remunerate_recipient(
        &ctx,
        tab_id,
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(3u64),
    )
    .await
    .expect("remunerate");

    let cleared = core_client
        .list_pending_remunerations(recipient_addr)
        .await
        .expect("pending rems cleared");
    assert!(cleared.is_empty());
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_modified_start_ts() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await {
        return;
    }

    let public_params = core_client.get_public_params().await.unwrap();
    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await
        .expect("create tab");

    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    let ts0 = req0.claims.timestamp;
    core_client.issue_guarantee(req0).await.expect("first ok");

    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        Some(ts0 + 5),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req1).await;
    assert!(result.is_err(), "must reject modified start timestamp");
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_two_sequential_guarantees_ok() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await {
        return;
    }

    let public_params = core_client.get_public_params().await.unwrap();
    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(3600),
        })
        .await
        .expect("create tab");
    let tab_id = tab.id;

    let start_ts = chrono::Utc::now().timestamp() as u64;
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
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
        tab_id,
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    let cert2 = core_client.issue_guarantee(req1).await.expect("second ok");

    assert!(cert2.verify(&public_params.public_key).unwrap());
    let rows = guarantee_entity::Entity::find()
        .filter(guarantee_entity::Column::TabId.eq(u256_to_string(tab_id)))
        .all(&*ctx.db)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_when_tab_not_found() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await {
        return;
    }

    let public_params = core_client.get_public_params().await.unwrap();
    let tab_id = U256::from_be_bytes(rand::random::<[u8; 32]>());
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject when tab not found");
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_should_open_tab() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await {
        return;
    }

    let tab_result = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await
        .expect("create tab");

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_result.id,
        U256::ZERO,
        U256::ONE,
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    core_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");

    let tab = repo::get_tab_by_id(&ctx, tab_result.id)
        .await
        .expect("get tab")
        .expect("tab exists");
    assert_eq!(tab.status, entities::sea_orm_active_enums::TabStatus::Open);
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_accepts_stablecoin_asset() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    if !insert_user_with_asset_collateral(&ctx, &user_addr, STABLE_ASSET_ADDRESS, U256::from(5u64))
        .await
    {
        return;
    }

    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: Some(STABLE_ASSET_ADDRESS.to_string()),
            ttl: Some(3600),
        })
        .await
        .expect("create tab");

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
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
    assert!(cert.verify(&public_params.public_key).unwrap());

    let stored = guarantee_entity::Entity::find()
        .filter(guarantee_entity::Column::TabId.eq(u256_to_string(tab.id)))
        .one(&*ctx.db)
        .await
        .expect("query guarantee");
    let guarantee = stored.expect("guarantee stored");
    assert_eq!(guarantee.asset_address, STABLE_ASSET_ADDRESS);
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_mismatched_asset_address() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    if !insert_user_with_asset_collateral(&ctx, &user_addr, STABLE_ASSET_ADDRESS, U256::from(5u64))
        .await
    {
        return;
    }

    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: Some(STABLE_ASSET_ADDRESS.to_string()),
            ttl: Some(3600),
        })
        .await
        .expect("create tab");

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject mismatched asset address");
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_invalid_req_id_when_tab_is_pending() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await {
        return;
    }

    let tab_result = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await
        .expect("create tab");

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_result.id,
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject if tab is pending");
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_get_tab_and_list_recipient_tabs() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let user_addr = random_address();
    let recipient_addr = random_address();
    if common::fixtures::ensure_user(&ctx, &user_addr)
        .await
        .is_err()
    {
        return;
    }

    let create_res = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(600),
        })
        .await
        .expect("create tab");
    let tab_id = create_res.id;

    let fetched = core_client
        .get_tab(tab_id)
        .await
        .expect("get tab")
        .expect("tab exists");
    assert_eq!(fetched.user_address, user_addr);
    assert_eq!(fetched.recipient_address, recipient_addr);
    assert_eq!(fetched.status, "PENDING");
    assert_eq!(fetched.settlement_status, "PENDING");

    let all_tabs = core_client
        .list_recipient_tabs(recipient_addr.clone(), None)
        .await
        .expect("list tabs");
    assert!(all_tabs.iter().any(|t| t.tab_id == tab_id));

    let settled_only = core_client
        .list_recipient_tabs(recipient_addr, Some(vec!["settled".into()]))
        .await
        .expect("filter tabs");
    assert!(settled_only.is_empty());
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_get_tab_returns_none_for_missing() {
    let Some((_, core_client, _)) = setup_clean_db().await else {
        return;
    };

    let missing = core_client
        .get_tab(U256::from(999u64))
        .await
        .expect("get missing tab");
    assert!(missing.is_none());
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_list_recipient_tabs_invalid_status_errors() {
    let Some((_, core_client, _)) = setup_clean_db().await else {
        return;
    };
    let err = core_client
        .list_recipient_tabs(random_address(), Some(vec!["unknown".into()]))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("invalid settlement status"),
        "unexpected error: {err}"
    );
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_list_recipient_tabs_case_insensitive_filter() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let user_addr = random_address();
    let recipient_addr = random_address();
    if common::fixtures::ensure_user(&ctx, &user_addr)
        .await
        .is_err()
    {
        return;
    }

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(300),
        })
        .await
        .expect("create tab")
        .id;

    let filtered = core_client
        .list_recipient_tabs(
            recipient_addr.clone(),
            Some(vec!["pending".into(), "SETTLED".into()]),
        )
        .await
        .expect("list tabs");
    assert!(filtered.iter().any(|t| t.tab_id == tab_id));

    let empty = core_client
        .list_recipient_tabs(recipient_addr, Some(vec!["failed".into()]))
        .await
        .expect("list tabs failed");
    assert!(empty.is_empty());
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn create_tab_rejects_unregistered_user() {
    let Some((_, core_client, _)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    let tab_result = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await;
    assert!(tab_result.is_err(), "must reject if user is not registered");
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_recipient_payments_and_events() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let user_addr = random_address();
    let recipient_addr = random_address();
    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await {
        return;
    }

    let create_res = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(1200),
        })
        .await
        .expect("create tab");
    let tab_id = create_res.id;

    let tx_hash = format!("0x{:032x}", random::<u128>());
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        tx_hash,
        U256::from(7u64),
    )
    .await
    .expect("submit payment tx");

    repo::remunerate_recipient(
        &ctx,
        tab_id,
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(5u64),
    )
    .await
    .expect("remunerate tab");

    let payments = core_client
        .list_recipient_payments(recipient_addr.clone())
        .await
        .expect("list recipient payments");
    assert_eq!(payments.len(), 1);
    assert_eq!(payments[0].user_address, user_addr);

    let events = core_client
        .get_collateral_events_for_tab(tab_id)
        .await
        .expect("collateral events");
    assert!(!events.is_empty());
    assert_eq!(events[0].event_type, "REMUNERATE");
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_recipient_payments_flags() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let user_addr = random_address();
    let recipient_addr = random_address();

    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(30u64)).await {
        return;
    }

    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        "0xdeadbeef".into(),
        U256::from(10u64),
    )
    .await
    .expect("submit payment");

    repo::fail_transaction(&ctx, user_addr.clone(), "0xdeadbeef".into())
        .await
        .expect("mark failed");

    let payments = core_client
        .list_recipient_payments(recipient_addr)
        .await
        .expect("list payments");
    assert_eq!(payments.len(), 1);
    let payment = &payments[0];
    assert!(payment.failed);
    assert!(payment.finalized);
    assert_eq!(payment.amount, U256::from(10u64));
    assert_eq!(payment.user_address, user_addr);
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_list_recipient_payments_empty() {
    let Some((_, core_client, _)) = setup_clean_db().await else {
        return;
    };
    let payments = core_client
        .list_recipient_payments(random_address())
        .await
        .expect("list empty payments");
    assert!(payments.is_empty());
}
#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_collateral_events_multiple_types() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(40u64)).await {
        return;
    }

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(1200),
        })
        .await
        .expect("create tab")
        .id;

    let now = Utc::now().naive_utc();
    let unlock_event = collateral_event::ActiveModel {
        id: sea_orm::ActiveValue::Set(Uuid::new_v4().to_string()),
        user_address: sea_orm::ActiveValue::Set(user_addr.clone()),
        asset_address: sea_orm::ActiveValue::Set(DEFAULT_ASSET_ADDRESS.to_string()),
        amount: sea_orm::ActiveValue::Set(U256::from(5u64).to_string()),
        event_type: sea_orm::ActiveValue::Set(CollateralEventType::Unlock),
        tab_id: sea_orm::ActiveValue::Set(Some(u256_to_string(tab_id))),
        req_id: sea_orm::ActiveValue::Set(None),
        tx_id: sea_orm::ActiveValue::Set(None),
        created_at: sea_orm::ActiveValue::Set(now - Duration::minutes(1)),
    };
    unlock_event
        .insert(ctx.db.as_ref())
        .await
        .expect("insert unlock event");

    let remunerate_event = collateral_event::ActiveModel {
        id: sea_orm::ActiveValue::Set(Uuid::new_v4().to_string()),
        user_address: sea_orm::ActiveValue::Set(user_addr.clone()),
        asset_address: sea_orm::ActiveValue::Set(DEFAULT_ASSET_ADDRESS.to_string()),
        amount: sea_orm::ActiveValue::Set(U256::from(10u64).to_string()),
        event_type: sea_orm::ActiveValue::Set(CollateralEventType::Remunerate),
        tab_id: sea_orm::ActiveValue::Set(Some(u256_to_string(tab_id))),
        req_id: sea_orm::ActiveValue::Set(None),
        tx_id: sea_orm::ActiveValue::Set(None),
        created_at: sea_orm::ActiveValue::Set(now),
    };
    remunerate_event
        .insert(ctx.db.as_ref())
        .await
        .expect("insert remunerate event");

    let events = core_client
        .get_collateral_events_for_tab(tab_id)
        .await
        .expect("events");
    assert!(events.len() >= 2);
    let mut seen = events
        .iter()
        .map(|e| e.event_type.as_str())
        .collect::<Vec<_>>();
    seen.sort();
    assert!(seen.contains(&"REMUNERATE"));
    assert!(seen.contains(&"UNLOCK"));
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_collateral_events_empty_for_tab_without_events() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let user_addr = random_address();
    let recipient_addr = random_address();
    if common::fixtures::ensure_user(&ctx, &user_addr)
        .await
        .is_err()
    {
        return;
    }

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr,
            recipient_address: recipient_addr,
            erc20_token: None,
            ttl: Some(300),
        })
        .await
        .expect("create tab")
        .id;

    let events = core_client
        .get_collateral_events_for_tab(tab_id)
        .await
        .expect("events");
    assert!(events.is_empty());
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_get_user_asset_balance() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let user_addr = random_address();
    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(15u64)).await {
        return;
    }

    let balance = core_client
        .get_user_asset_balance(user_addr.clone(), DEFAULT_ASSET_ADDRESS.to_string())
        .await
        .expect("get balance")
        .expect("balance exists");
    assert_eq!(balance.user_address, user_addr);
    assert_eq!(balance.total, U256::from(15u64));
    assert_eq!(balance.locked, U256::ZERO);

    let missing = core_client
        .get_user_asset_balance(user_addr, STABLE_ASSET_ADDRESS.to_string())
        .await
        .expect("get missing balance");
    assert!(missing.is_none());

    let unknown_user = core_client
        .get_user_asset_balance(random_address(), DEFAULT_ASSET_ADDRESS.to_string())
        .await
        .expect("unknown user balance");
    assert!(unknown_user.is_none());
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_get_user_asset_balance_locked_amount() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(25u64)).await {
        return;
    }

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(600),
        })
        .await
        .expect("create tab")
        .id;

    let params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        U256::from(12u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");

    let balance = core_client
        .get_user_asset_balance(user_addr.clone(), DEFAULT_ASSET_ADDRESS.to_string())
        .await
        .expect("get balance")
        .expect("balance exists");
    assert_eq!(balance.total, U256::from(25u64));
    assert_eq!(balance.locked, U256::from(12u64));
}

async fn build_eip712_signed_request_with_wallet(
    params: &CorePublicParameters,
    wallet: &alloy::signers::local::PrivateKeySigner,
) -> PaymentGuaranteeRequest {
    build_eip712_signed_request(params, wallet).await
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn verify_eip712_signature_ok() {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();

    let req = build_eip712_signed_request_with_wallet(&params, &wallet).await;
    verify_promise_signature(&params, &req).expect("valid EIP-712 signature must verify");
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn verify_eip712_signature_fails_if_tampered() {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();

    let mut req = build_eip712_signed_request_with_wallet(&params, &wallet).await;
    req.claims.amount = U256::from(999u64);

    let err = verify_promise_signature(&params, &req).unwrap_err();
    assert!(
        format!("{err:?}").contains("Invalid signature"),
        "tampered claims must produce invalid signature error"
    );
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn verify_eip191_signature_ok() {
    use alloy::{primitives::keccak256, sol_types::sol};
    sol! {
        struct PaymentGuarantee {
            address user;
            address recipient;
            uint256 tabId;
            uint256 reqId;
            uint256 amount;
            uint64 timestamp;
        }
    }

    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user = wallet.address();
    let recipient = Address::from(rand::random::<[u8; 20]>());
    let timestamp = Utc::now().timestamp() as u64;
    let tab_id = U256::from(0x7461622d7473u128);

    let msg = PaymentGuarantee {
        user,
        recipient,
        tabId: tab_id,
        reqId: U256::from(0u64),
        amount: U256::from(1u64),
        timestamp,
    };
    let data = msg.abi_encode();
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);
    let digest = keccak256(prefixed);

    let sig: Signature = wallet.sign_hash(&digest).await.unwrap();

    let req = PaymentGuaranteeRequest {
        claims: PaymentGuaranteeClaims {
            user_address: user.to_string(),
            recipient_address: recipient.to_string(),
            tab_id,
            req_id: U256::from(0u64),
            amount: U256::from(1u64),
            timestamp,
            asset_address: "0x0000000000000000000000000000000000000000".into(),
        },
        signature: crypto::hex::encode_hex(&sig.as_bytes()),
        scheme: SigningScheme::Eip191,
    };

    verify_promise_signature(&params, &req).expect("valid EIP-191 signature must verify");
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn verify_signature_fails_with_invalid_hex() {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_request_with_wallet(&params, &wallet).await;

    req.signature = "0xZZZZ".to_string();

    let err = verify_promise_signature(&params, &req).unwrap_err();
    assert!(
        format!("{err:?}").contains("invalid hex signature"),
        "invalid hex must be rejected"
    );
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn list_settled_tabs_returns_only_settled_entries() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    if !insert_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await {
        return;
    }

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(600),
        })
        .await
        .expect("create tab")
        .id;

    repo::remunerate_recipient(
        &ctx,
        tab_id,
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(10u64),
    )
    .await
    .expect("remunerate tab");

    let settled = core_client
        .list_settled_tabs(recipient_addr.clone())
        .await
        .expect("list settled tabs");
    assert!(settled.iter().any(|tab| tab.tab_id == tab_id));

    let all_tabs = core_client
        .list_recipient_tabs(recipient_addr, None)
        .await
        .expect("list tabs");
    assert!(all_tabs.iter().any(|tab| tab.tab_id == tab_id));
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn list_settled_tabs_empty_when_none() {
    let Some((_, core_client, _)) = setup_clean_db().await else {
        return;
    };

    let recipient_addr = random_address();
    let settled = core_client
        .list_settled_tabs(recipient_addr)
        .await
        .expect("list settled tabs");
    assert!(settled.is_empty());
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn list_settled_tabs_ignores_pending_tabs() {
    let Some((_, core_client, ctx)) = setup_clean_db().await else {
        return;
    };

    let user_addr = random_address();
    let recipient_addr = random_address();
    if common::fixtures::ensure_user(&ctx, &user_addr)
        .await
        .is_err()
    {
        return;
    }

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(600),
        })
        .await
        .expect("create tab")
        .id;

    let settled = core_client
        .list_settled_tabs(recipient_addr.clone())
        .await
        .expect("list settled tabs");
    assert!(settled.is_empty());

    let all_tabs = core_client
        .list_recipient_tabs(recipient_addr, None)
        .await
        .expect("list tabs");
    assert!(all_tabs.iter().any(|tab| tab.tab_id == tab_id));
}
