use alloy::{
    primitives::{Address, Signature, U256},
    signers::Signer,
    sol_types::{SolStruct, eip712_domain, sol},
};
use alloy_sol_types::SolValue;
use chrono::{Duration, Utc};
use core_service::auth::verify_promise_signature;
use core_service::config::AppConfig;
use core_service::persist::{PersistCtx, repo};
use entities::guarantee;
use hex;
use rand::random;
use rpc::{
    common::{PaymentGuaranteeClaims, PaymentGuaranteeRequest, SigningScheme},
    core::{CoreApiClient, CorePublicParameters},
    proxy::RpcProxy,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use sea_orm::{ConnectionTrait, Statement};
use std::str::FromStr;
use test_log::test;

async fn setup_clean_db() -> (AppConfig, RpcProxy, PersistCtx) {
    let config = {
        dotenv::dotenv().ok();
        AppConfig::fetch()
    };
    let core_addr = format!(
        "{}:{}",
        config.server_config.host, config.server_config.port
    );
    let core_client = RpcProxy::new(&core_addr).await.expect("connect RPC");
    let ctx = PersistCtx::new().await.expect("db ctx");
    ctx.db
        .as_ref()
        .execute(Statement::from_string(
            ctx.db.get_database_backend(),
            "TRUNCATE \"Guarantee\", \"Tabs\", \"CollateralEvent\", \"User\" CASCADE".to_string(),
        ))
        .await
        .unwrap();
    (config, core_client, ctx)
}

async fn insert_user_with_collateral(ctx: &PersistCtx, addr: &str, amount: U256) {
    let now = chrono::Utc::now().naive_utc();
    let user_model = entities::user::ActiveModel {
        address: Set(addr.to_string()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        collateral: Set("0".to_string()),
        locked_collateral: Set("0".to_string()),
    };
    entities::user::Entity::insert(user_model)
        .exec(ctx.db.as_ref())
        .await
        .expect("insert user");
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
        U256::from(0x7461622d6c6f77636f6c6c6174656eu128), // "tab-lowcoll" as bytes
        U256::from(0u64),
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
async fn issue_guarantee_rejects_wrong_req_id_sequence() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();

    // use a unique tab id so we never collide with data left by another test
    let tab_id = U256::from_be_bytes(rand::random::<[u8; 32]>());

    // First request req_id=0 is OK
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::from(0u64),
        U256::from(1u64),
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
        tab_id,
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
async fn issue_guarantee_rejects_modified_start_ts() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();
    let tab_id = U256::from_be_bytes(rand::random::<[u8; 32]>());
    // First request is OK
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::from(0u64),
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
        tab_id,
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        Some(ts0 + 5), // different start_ts
    )
    .await;

    let result = core_client.issue_guarantee(req1).await;
    assert!(result.is_err(), "must reject modified start timestamp");
}

/// Invalid: User not registered in DB
#[test(tokio::test)]
async fn issue_guarantee_rejects_unregistered_user() {
    let (_, core_client, _) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    let tab_id = U256::from_be_bytes(rand::random::<[u8; 32]>());
    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::from(0u64),
        U256::from(1u64),
        &wallet,
        None,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject if user is not registered");
}

/// Valid: second sequential request works
#[test(tokio::test)]
async fn issue_two_sequential_guarantees_ok() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = format!("0x{}", hex::encode(random::<[u8; 20]>()));
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();

    // First req
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(0x7461622d6f6b32u128),
        U256::from(0u64),
        U256::from(1u64),
        &wallet,
        Some(chrono::Utc::now().timestamp() as u64),
    )
    .await;
    core_client.issue_guarantee(req0).await.expect("first ok");

    // Second req sequential
    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(0x7461622d6f6b32u128),
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        Some(chrono::Utc::now().timestamp() as u64),
    )
    .await;
    core_client
        .issue_guarantee(req1.clone())
        .await
        .expect("second ok");
    let rows = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(req1.claims.tab_id.to_string()))
        .all(&*ctx.db)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
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
async fn verify_eip712_signature_ok() {
    let params = CorePublicParameters {
        public_key: vec![],
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
async fn verify_eip712_signature_fails_if_tampered() {
    let params = CorePublicParameters {
        public_key: vec![],
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
            tab_id: tab, // <-- fixed
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
async fn verify_signature_fails_with_invalid_hex() {
    let params = CorePublicParameters {
        public_key: vec![],
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
