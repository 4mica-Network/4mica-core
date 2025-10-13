use alloy::{
    primitives::{Address, Signature, U256},
    signers::Signer,
    sol_types::{SolStruct, eip712_domain, sol},
};
use alloy_sol_types::SolValue;
use chrono::{Duration, Utc};
use core_service::config::AppConfig;
use core_service::persist::{PersistCtx, repo};
use core_service::{auth::verify_promise_signature, util::u256_to_string};
use entities::guarantee;
use hex;
use rand::random;
use rpc::{
    common::{
        CreatePaymentTabRequest, PaymentGuaranteeClaims, PaymentGuaranteeRequest, SigningScheme,
    },
    core::{CoreApiClient, CorePublicParameters},
    proxy::RpcProxy,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sea_orm::{ConnectionTrait, Statement};
use serial_test::serial;
use std::str::FromStr;
use test_log::test;

async fn setup_clean_db() -> (AppConfig, RpcProxy, PersistCtx) {
    let config = {
        dotenv::dotenv().ok();
        AppConfig::fetch()
    };
    let core_addr = format!(
        "http://{}:{}",
        config.server_config.host, config.server_config.port
    );
    let core_client = RpcProxy::new(&core_addr).expect("connect RPC");
    let ctx = PersistCtx::new().await.expect("db ctx");

    for table in [
        "UserTransaction",
        "Withdrawal",
        "Guarantee",
        "Tabs",
        "CollateralEvent",
        "User",
    ] {
        ctx.db
            .as_ref()
            .execute(Statement::from_string(
                ctx.db.get_database_backend(),
                format!(r#"DELETE FROM "{table}";"#),
            ))
            .await
            .unwrap();
    }

    (config, core_client, ctx)
}

async fn insert_user_with_collateral(ctx: &PersistCtx, addr: &str, amount: U256) {
    repo::ensure_user_exists_on(ctx.db.as_ref(), addr)
        .await
        .expect("ensure user exists");
    repo::deposit(ctx, addr.to_string(), amount)
        .await
        .expect("deposit");
}

async fn build_signed_req(
    public_params: &CorePublicParameters,
    user_addr: &str,
    recipient_addr: &str,
    tab_id: U256,
    req_id: U256,
    amount: U256,
    wallet: &alloy::signers::local::PrivateKeySigner,
    timestamp: Option<u64>,
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
            tab_id: tab_id,
            req_id: req_id,
            amount,
            timestamp: ts,
        },
        signature: format!("0x{}", hex::encode(sig.as_bytes())),
        scheme: SigningScheme::Eip712,
    }
}

/// Invalid: future timestamp
#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_future_timestamp() {
    let (_config, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

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
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject promise with future timestamp");
}

/// Invalid: Not enough collateral
#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_insufficient_collateral() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    insert_user_with_collateral(&ctx, &user_addr, U256::from(1u64)).await; // only 1 unit

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(0x7461622d6e6f636f6c6c61746572616cu128), // "tab-nocollateral" as bytes
        U256::ZERO,
        U256::from(10u64), // request more than deposited
        &wallet,
        None,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(
        result.is_err(),
        "must reject when collateral is insufficient"
    );
}

/// Invalid: Wrong req_id sequence
#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_wrong_req_id_sequence() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();

    // use a unique tab id so we never collide with data left by another test
    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            ttl: None,
        })
        .await
        .expect("create tab");
    // First request req_id=0 is OK
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::ONE,
        &wallet,
        None,
    )
    .await;
    core_client.issue_guarantee(req0).await.expect("first ok");

    // Second request with req_id=2 (skip 1) should fail
    let req2 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::from(2u64),
        U256::from(1u64),
        &wallet,
        None,
    )
    .await;

    let result = core_client.issue_guarantee(req2).await;
    assert!(result.is_err(), "must reject non-sequential req_id");
}

/// Invalid: Modified start timestamp in second request
#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_modified_start_ts() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();
    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            ttl: None,
        })
        .await
        .expect("create tab");
    // First request is OK
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
    )
    .await;
    let ts0 = req0.claims.timestamp;
    core_client.issue_guarantee(req0).await.expect("first ok");

    // Second request with req_id=1 but different timestamp than first start_ts -> should fail
    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        Some(ts0 + 5), // different start_ts
    )
    .await;

    let result = core_client.issue_guarantee(req1).await;
    assert!(result.is_err(), "must reject modified start timestamp");
}

/// Valid: second sequential request works
#[test(tokio::test)]
#[serial]
async fn issue_two_sequential_guarantees_ok() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();
    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            ttl: Some(3600),
        })
        .await
        .expect("create tab");
    let tab_id = tab.id;

    let start_ts = chrono::Utc::now().timestamp() as u64;
    // First req
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        Some(start_ts),
    )
    .await;
    core_client.issue_guarantee(req0).await.expect("first ok");

    // Second req sequential
    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        Some(start_ts),
    )
    .await;
    let cert2 = core_client.issue_guarantee(req1).await.expect("second ok");

    assert!(cert2.verify(&public_params.public_key).unwrap());
    let rows = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(u256_to_string(tab_id)))
        .all(&*ctx.db)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
}

/// Invalid: Tab not found
#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_when_tab_not_found() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

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
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject if tab is not found");
}

/// Valid: Issue guarantee should open tab
#[test(tokio::test)]
#[serial]
async fn issue_guarantee_should_open_tab() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let tab_result = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            ttl: Some(3600),
        })
        .await
        .expect("create tab");

    let tab = repo::get_tab_by_id(&ctx, tab_result.id)
        .await
        .expect("get tab")
        .expect("tab exists");
    assert_eq!(
        tab.status,
        entities::sea_orm_active_enums::TabStatus::Pending
    );

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

/// Invalid: Invalid req_id when tab is still pending
#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_invalid_req_id_when_tab_is_pending() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let tab_result = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
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
        U256::from(1u64), // invalid req_id, should be 0
        U256::from(1u64),
        &wallet,
        None,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject if tab is pending");
}

/// Invalid: User not registered in DB
#[test(tokio::test)]
#[serial]
async fn create_tab_rejects_unregistered_user() {
    let (_, core_client, _) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));

    let tab_result = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            ttl: None,
        })
        .await;
    assert!(tab_result.is_err(), "must reject if user is not registered");
}

/// Build a valid EIP-712 signed request
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
        },
        signature: format!("0x{}", hex::encode(sig.as_bytes())),
        scheme: SigningScheme::Eip712,
    }
}

#[tokio::test]
#[serial]
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

    let req = build_eip712_signed_request(&params, &wallet).await;
    // should not return error
    verify_promise_signature(&params, &req).expect("valid EIP-712 signature must verify");
}

#[tokio::test]
#[serial]
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

    let mut req = build_eip712_signed_request(&params, &wallet).await;
    // tamper with claims after signing
    req.claims.amount = U256::from(999u64);

    let err = verify_promise_signature(&params, &req).unwrap_err();
    assert!(
        format!("{err:?}").contains("Invalid signature"),
        "tampered claims must produce invalid signature error"
    );
}

#[tokio::test]
#[serial]
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

    // --- use one variable so we can reuse the exact same tab id everywhere ---
    let tab = U256::from(0x7461622d7473u128); // "tab-ts" as bytes

    let msg = PaymentGuarantee {
        user,
        recipient,
        tabId: tab,
        reqId: U256::from(0u64),
        amount: U256::from(1u64),
        timestamp,
    };
    let data = msg.abi_encode();
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);
    let digest = keccak256(prefixed);

    let sig: Signature = wallet.sign_hash(&digest).await.unwrap();

    // ---- claims must use the same tab id that was signed ----
    let req = PaymentGuaranteeRequest {
        claims: PaymentGuaranteeClaims {
            user_address: user.to_string(),
            recipient_address: recipient.to_string(),
            tab_id: tab,
            req_id: U256::from(0u64),
            amount: U256::from(1u64),
            timestamp,
        },
        signature: format!("0x{}", hex::encode(sig.as_bytes())),
        scheme: SigningScheme::Eip191,
    };

    verify_promise_signature(&params, &req).expect("valid EIP-191 signature must verify");
}

#[tokio::test]
#[serial]
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
    let mut req = build_eip712_signed_request(&params, &wallet).await;

    // Provide completely invalid hex string as signature
    req.signature = "0xZZZZ".to_string();

    let err = verify_promise_signature(&params, &req).unwrap_err();
    assert!(
        format!("{err:?}").contains("invalid hex signature"),
        "invalid hex must be rejected"
    );
}
