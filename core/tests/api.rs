use alloy::{
    primitives::{Address, Signature, U256},
    signers::Signer,
    signers::local::PrivateKeySigner,
    sol_types::{SolStruct, eip712_domain, sol},
};
use alloy_sol_types::SolValue;
use chrono::{DateTime, Duration, Utc};
use core_service::config::{AppConfig, DEFAULT_ASSET_ADDRESS};
use core_service::persist::{GuaranteeData, PersistCtx, repo};
use core_service::service::{SCOPE_GUARANTEE_ISSUE, SCOPE_TAB_CREATE, SCOPE_TAB_READ};
use core_service::{auth::verify_guarantee_request_signature, util::u256_to_string};
use entities::sea_orm_active_enums::CollateralEventType;
use entities::{collateral_event, guarantee as guarantee_entity};
use rand::random;
use rpc::{
    ApiClientError, CorePublicParameters, CreatePaymentTabRequest, PaymentGuaranteeRequest,
    PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1, RpcProxy, SigningScheme,
    TabInfo, UpdateUserSuspensionRequest,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;
use std::str::FromStr;
use uuid::Uuid;

#[path = "common/mod.rs"]
mod common;
use common::fixtures::{
    clear_all_tables, ensure_user_with_collateral, init_test_env, random_address,
    set_locked_collateral,
};

const STABLE_ASSET_ADDRESS: &str = "0x1111111111111111111111111111111111111111";
const DEFAULT_WALLET_ROLE: &str = "admin";
const DEFAULT_WALLET_STATUS: &str = "active";

#[derive(Debug, Deserialize)]
struct AuthNonceResponse {
    nonce: String,
    siwe: SiweTemplateResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SiweTemplateResponse {
    domain: String,
    uri: String,
    chain_id: u64,
    statement: String,
    expiration: String,
    issued_at: String,
}

#[derive(Debug, Deserialize)]
struct AuthVerifyResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct AuthTokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Clone, Debug)]
struct AuthSession {
    address: String,
    access_token: String,
}

fn core_base_url(config: &AppConfig) -> String {
    format!(
        "http://{}:{}",
        config.server_config.host, config.server_config.port
    )
}

async fn setup_clean_db() -> anyhow::Result<(AppConfig, RpcProxy, PersistCtx, AuthSession)> {
    let (config, ctx) = init_test_env().await?;
    let core_addr = core_base_url(&config);
    clear_all_tables(&ctx).await?;

    let recipient_signer = PrivateKeySigner::random();
    let auth = login_with_siwe(
        &core_addr,
        &ctx,
        &recipient_signer,
        DEFAULT_WALLET_ROLE,
        &[SCOPE_TAB_CREATE, SCOPE_TAB_READ, SCOPE_GUARANTEE_ISSUE],
    )
    .await?;
    let core_client = RpcProxy::new(&core_addr)?.with_bearer_token(auth.access_token.clone());

    Ok((config, core_client, ctx, auth))
}

async fn insert_user_with_asset_collateral(
    ctx: &PersistCtx,
    addr: &str,
    asset: &str,
    amount: U256,
) -> anyhow::Result<()> {
    if let Err(err) = common::fixtures::ensure_user(ctx, addr).await {
        return Err(anyhow::anyhow!("failed to ensure user: {err}"));
    }
    repo::deposit(ctx, addr.to_string(), asset.to_string(), amount).await?;
    Ok(())
}

sol! {
    struct SolGuaranteeRequestClaimsV1 {
        address user;
        address recipient;
        uint256  tabId;
        uint256 reqId;
        uint256 amount;
        address asset;
        uint64  timestamp;
    }
}

fn build_siwe_message_from_template(
    template: &SiweTemplateResponse,
    address: &str,
    nonce: &str,
) -> String {
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n{address}\n\n{statement}\n\nURI: {uri}\nVersion: 1\nChain ID: {chain_id}\nNonce: {nonce}\nIssued At: {issued_at}\nExpiration Time: {expiration}",
        domain = template.domain,
        address = address,
        statement = template.statement,
        uri = template.uri,
        chain_id = template.chain_id,
        nonce = nonce,
        issued_at = template.issued_at,
        expiration = template.expiration,
    )
}

async fn login_with_siwe(
    base_addr: &str,
    ctx: &PersistCtx,
    signer: &PrivateKeySigner,
    role: &str,
    scopes: &[&str],
) -> anyhow::Result<AuthSession> {
    let address = signer.address().to_string();
    let scopes = scopes
        .iter()
        .map(|scope| (*scope).to_string())
        .collect::<Vec<_>>();
    repo::upsert_wallet_role(ctx, &address, role, &scopes, DEFAULT_WALLET_STATUS).await?;

    let client = reqwest::Client::new();
    let nonce_res = client
        .post(format!("{base_addr}/auth/nonce"))
        .json(&serde_json::json!({ "address": address }))
        .send()
        .await?
        .error_for_status()?;
    let nonce_res: AuthNonceResponse = nonce_res.json().await?;

    let message = build_siwe_message_from_template(&nonce_res.siwe, &address, &nonce_res.nonce);
    let signature = signer.sign_message(message.as_bytes()).await?;
    let signature_hex = crypto::hex::encode_hex(&Vec::<u8>::from(signature));

    let verify_res = client
        .post(format!("{base_addr}/auth/verify"))
        .json(&serde_json::json!({
            "address": address,
            "message": message,
            "signature": signature_hex,
        }))
        .send()
        .await?
        .error_for_status()?;
    let verify_res: AuthVerifyResponse = verify_res.json().await?;

    Ok(AuthSession {
        address,
        access_token: verify_res.access_token,
    })
}

async fn client_with_signer(
    config: &AppConfig,
    ctx: &PersistCtx,
    signer: &PrivateKeySigner,
    role: &str,
    scopes: &[&str],
) -> anyhow::Result<RpcProxy> {
    let base_addr = core_base_url(config);
    let auth = login_with_siwe(&base_addr, ctx, signer, role, scopes).await?;
    Ok(RpcProxy::new(&base_addr)?.with_bearer_token(auth.access_token))
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
    let ts = timestamp.unwrap_or_else(|| Utc::now().timestamp() as u64);
    let domain = eip712_domain!(
        name: public_params.eip712_name.clone(),
        version: public_params.eip712_version.clone(),
        chain_id: public_params.chain_id,
    );
    let msg = SolGuaranteeRequestClaimsV1 {
        user: Address::from_str(user_addr).unwrap(),
        recipient: Address::from_str(recipient_addr).unwrap(),
        tabId: tab_id,
        reqId: req_id,
        amount,
        asset: Address::from_str(asset_address).unwrap(),
        timestamp: ts,
    };
    let digest = msg.eip712_signing_hash(&domain);
    let sig: Signature = wallet.sign_hash(&digest).await.unwrap();
    PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(PaymentGuaranteeRequestClaimsV1 {
            user_address: user_addr.to_string(),
            recipient_address: recipient_addr.to_string(),
            tab_id,
            req_id,
            amount,
            timestamp: ts,
            asset_address: asset_address.to_string(),
        }),
        crypto::hex::encode_hex(&sig.as_bytes()),
        SigningScheme::Eip712,
    )
}

async fn build_eip712_signed_request(
    params: &CorePublicParameters,
    wallet: &alloy::signers::local::PrivateKeySigner,
) -> PaymentGuaranteeRequest {
    let timestamp = Utc::now().timestamp() as u64;

    let domain = eip712_domain!(
        name:     params.eip712_name.clone(),
        version:  params.eip712_version.clone(),
        chain_id: params.chain_id,
    );

    let recipient = Address::from(random::<[u8; 20]>());
    let msg = SolGuaranteeRequestClaimsV1 {
        user: wallet.address(),
        recipient,
        tabId: U256::from(0x7461622d6f6b32u128),
        reqId: U256::from(0u64),
        amount: U256::from(42u64),
        asset: Address::from_str(DEFAULT_ASSET_ADDRESS).unwrap(),
        timestamp,
    };
    let digest = msg.eip712_signing_hash(&domain);

    let sig: Signature = wallet.sign_hash(&digest).await.unwrap();

    PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(PaymentGuaranteeRequestClaimsV1 {
            user_address: wallet.address().to_string(),
            recipient_address: recipient.to_string(),
            tab_id: U256::from(0x7461622d6f6b32u128),
            req_id: U256::from(0u64),
            amount: U256::from(42u64),
            timestamp,
            asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        }),
        crypto::hex::encode_hex(&sig.as_bytes()),
        SigningScheme::Eip712,
    )
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn auth_nonce_reuse_is_rejected() -> anyhow::Result<()> {
    let (config, _core_client, ctx, _auth) = setup_clean_db().await?;
    let base_addr = core_base_url(&config);
    let signer = PrivateKeySigner::random();
    let address = signer.address().to_string();
    let scopes = vec![SCOPE_TAB_READ.to_string()];
    repo::upsert_wallet_role(&ctx, &address, "user", &scopes, DEFAULT_WALLET_STATUS).await?;

    let client = reqwest::Client::new();
    let nonce_res = client
        .post(format!("{base_addr}/auth/nonce"))
        .json(&serde_json::json!({ "address": address }))
        .send()
        .await?
        .error_for_status()?;
    let nonce_res: AuthNonceResponse = nonce_res.json().await?;

    let message = build_siwe_message_from_template(&nonce_res.siwe, &address, &nonce_res.nonce);
    let signature = signer.sign_message(message.as_bytes()).await?;
    let signature_hex = crypto::hex::encode_hex(&Vec::<u8>::from(signature));

    let payload = serde_json::json!({
        "address": address,
        "message": message,
        "signature": signature_hex,
    });
    let first = client
        .post(format!("{base_addr}/auth/verify"))
        .json(&payload)
        .send()
        .await?;
    assert!(first.status().is_success());

    let second = client
        .post(format!("{base_addr}/auth/verify"))
        .json(&payload)
        .send()
        .await?;
    assert_eq!(second.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = second.json().await?;
    let error = body
        .get("error")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(
        error.contains("nonce"),
        "unexpected error response: {body:?}"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn auth_verify_rejects_invalid_signature() -> anyhow::Result<()> {
    let (config, _core_client, ctx, _auth) = setup_clean_db().await?;
    let base_addr = core_base_url(&config);
    let signer = PrivateKeySigner::random();
    let address = signer.address().to_string();
    let scopes = vec![SCOPE_TAB_READ.to_string()];
    repo::upsert_wallet_role(&ctx, &address, "user", &scopes, DEFAULT_WALLET_STATUS).await?;

    let client = reqwest::Client::new();
    let nonce_res = client
        .post(format!("{base_addr}/auth/nonce"))
        .json(&serde_json::json!({ "address": address }))
        .send()
        .await?
        .error_for_status()?;
    let nonce_res: AuthNonceResponse = nonce_res.json().await?;

    let message = build_siwe_message_from_template(&nonce_res.siwe, &address, &nonce_res.nonce);
    let signature_hex = "invalid-hex-signature";

    let resp = client
        .post(format!("{base_addr}/auth/verify"))
        .json(&serde_json::json!({
            "address": address,
            "message": message,
            "signature": signature_hex,
        }))
        .send()
        .await?;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await?;
    let error = body
        .get("error")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(
        error.contains("invalid signature"),
        "unexpected error response: {body:?}"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn auth_refresh_rotates_tokens() -> anyhow::Result<()> {
    let (config, _core_client, ctx, _auth) = setup_clean_db().await?;
    let base_addr = core_base_url(&config);
    let signer = PrivateKeySigner::random();
    let address = signer.address().to_string();
    let scopes = vec![SCOPE_TAB_READ.to_string()];
    repo::upsert_wallet_role(&ctx, &address, "user", &scopes, DEFAULT_WALLET_STATUS).await?;

    let client = reqwest::Client::new();
    let nonce_res = client
        .post(format!("{base_addr}/auth/nonce"))
        .json(&serde_json::json!({ "address": address }))
        .send()
        .await?
        .error_for_status()?;
    let nonce_res: AuthNonceResponse = nonce_res.json().await?;

    let message = build_siwe_message_from_template(&nonce_res.siwe, &address, &nonce_res.nonce);
    let signature = signer.sign_message(message.as_bytes()).await?;
    let signature_hex = crypto::hex::encode_hex(&Vec::<u8>::from(signature));

    let verify_res = client
        .post(format!("{base_addr}/auth/verify"))
        .json(&serde_json::json!({
            "address": address,
            "message": message,
            "signature": signature_hex,
        }))
        .send()
        .await?
        .error_for_status()?;
    let verify_res: AuthTokenResponse = verify_res.json().await?;

    let refresh_token = verify_res.refresh_token.clone();
    let refresh_res = client
        .post(format!("{base_addr}/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh_token.clone() }))
        .send()
        .await?
        .error_for_status()?;
    let refresh_res: AuthTokenResponse = refresh_res.json().await?;

    assert_ne!(refresh_res.refresh_token, verify_res.refresh_token);
    assert!(!refresh_res.access_token.is_empty());
    assert!(refresh_res.expires_in > 0);

    let reuse_res = client
        .post(format!("{base_addr}/auth/refresh"))
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await?;
    assert_eq!(reuse_res.status(), reqwest::StatusCode::UNAUTHORIZED);

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn auth_scope_denial_rejects_tab_creation() -> anyhow::Result<()> {
    let (config, _core_client, ctx, _auth) = setup_clean_db().await?;
    let base_addr = core_base_url(&config);
    let signer = PrivateKeySigner::random();
    let recipient_address = signer.address().to_string();
    let user_address = random_address();

    let auth = login_with_siwe(
        &base_addr,
        &ctx,
        &signer,
        DEFAULT_WALLET_ROLE,
        &[SCOPE_TAB_READ],
    )
    .await?;
    let client = RpcProxy::new(&base_addr)?.with_bearer_token(auth.access_token);

    let err = client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address,
            recipient_address,
            erc20_token: None,
            ttl: None,
        })
        .await
        .expect_err("missing scope should reject");
    match err {
        ApiClientError::Api { status, message } => {
            assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
            assert!(
                message.contains("missing scope"),
                "unexpected message: {message}"
            );
        }
        other => anyhow::bail!("unexpected error: {other:?}"),
    }

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_future_timestamp() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let future_ts = (Utc::now() + Duration::hours(1)).timestamp() as u64;
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(0x7461622d667574757265u128),
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        Some(future_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = user_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject promise with future timestamp");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_insufficient_collateral() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(1u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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

    let result = user_client.issue_guarantee(req).await;
    assert!(
        result.is_err(),
        "must reject when collateral is insufficient"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_accepts_sequential_req_ids() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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

    let start_ts = chrono::Utc::now().timestamp() as u64;
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    user_client.issue_guarantee(req0).await.expect("first ok");

    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::from(1u64),
        U256::from(2u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    user_client.issue_guarantee(req1).await.expect("second ok");

    let req_replay = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::from(1u64),
        U256::from(3u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    let result = user_client.issue_guarantee(req_replay).await;
    assert!(result.is_err(), "must reject replayed req_id");

    let guarantees = core_client
        .get_tab_guarantees(tab.id)
        .await
        .expect("list guarantees");
    assert_eq!(guarantees.len(), 2);
    assert_eq!(guarantees[0].req_id, U256::ZERO);
    assert_eq!(guarantees[1].req_id, U256::from(1u64));

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_guarantee_queries() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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

    user_client
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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_guarantee_history_ordering() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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
    let shared_ts = Utc::now().timestamp() as u64;
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        U256::from(5u64),
        &wallet,
        Some(shared_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    user_client
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
        Some(shared_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    user_client
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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_guarantee_queries_empty_state() -> anyhow::Result<()> {
    let (_, core_client, ctx, auth) = setup_clean_db().await?;

    let user_addr = random_address();
    let recipient_addr = auth.address.clone();
    common::fixtures::ensure_user(&ctx, &user_addr).await?;

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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_pending_remunerations_clear_after_settlement() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(12u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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
    user_client
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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_modified_start_ts() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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

    let start_ts = chrono::Utc::now().timestamp() as u64;
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    user_client.issue_guarantee(req0).await.expect("first ok");

    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        Some(start_ts + 5),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = user_client.issue_guarantee(req1).await;
    assert!(result.is_err(), "must reject modified start timestamp");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_two_sequential_guarantees_ok() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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
    user_client.issue_guarantee(req0).await.expect("first ok");

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
    let cert2 = user_client.issue_guarantee(req1).await.expect("second ok");

    assert!(cert2.verify(&public_params.public_key).unwrap());
    let rows = guarantee_entity::Entity::find()
        .filter(guarantee_entity::Column::TabId.eq(u256_to_string(tab_id)))
        .all(&*ctx.db)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_two_guarantees_verifies_total_amount() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(100u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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

    // Issue first guarantee with amount = 15
    let amount1 = U256::from(15u64);
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        amount1,
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    let cert1 = user_client
        .issue_guarantee(req0)
        .await
        .expect("first guarantee ok");

    // Decode first certificate and verify total_amount equals amount1
    let claims1_bytes = cert1.claims_bytes()?;
    let claims1 = rpc::PaymentGuaranteeClaims::try_from(claims1_bytes.as_slice())?;
    assert_eq!(claims1.amount, amount1);
    assert_eq!(
        claims1.total_amount, amount1,
        "First guarantee: total_amount should equal amount"
    );

    // Issue second guarantee with amount = 27
    let amount2 = U256::from(27u64);
    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::from(1u64),
        amount2,
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    let cert2 = user_client
        .issue_guarantee(req1)
        .await
        .expect("second guarantee ok");

    // Decode second certificate and verify total_amount equals amount1 + amount2
    let claims2_bytes = cert2.claims_bytes()?;
    let claims2 = rpc::PaymentGuaranteeClaims::try_from(claims2_bytes.as_slice())?;
    assert_eq!(claims2.amount, amount2);
    let expected_total = amount1.checked_add(amount2).unwrap();
    assert_eq!(
        claims2.total_amount, expected_total,
        "Second guarantee: total_amount should equal sum of all amounts (15 + 27 = 42)"
    );

    // Verify certificate is valid
    assert!(cert2.verify(&public_params.public_key).unwrap());

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_when_tab_not_found() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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

    let result = user_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject when tab not found");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_should_open_tab() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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

    user_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");

    let tab = repo::get_tab_by_id(&ctx, tab_result.id)
        .await
        .expect("get tab")
        .expect("tab exists");
    assert_eq!(tab.status, entities::sea_orm_active_enums::TabStatus::Open);

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_does_not_open_tab_on_insufficient_collateral() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(1u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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
        U256::from(2u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = user_client.issue_guarantee(req).await;
    assert!(
        result.is_err(),
        "must reject when collateral is insufficient"
    );

    let tab = repo::get_tab_by_id(&ctx, tab_result.id)
        .await
        .expect("get tab")
        .expect("tab exists");
    assert_eq!(
        tab.status,
        entities::sea_orm_active_enums::TabStatus::Pending
    );

    let guarantees = repo::get_guarantees_for_tab(&ctx, tab_result.id)
        .await
        .expect("get guarantees");
    assert!(
        guarantees.is_empty(),
        "must not store guarantees on failure"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_advances_req_id_from_manual_gap() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(7200),
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
        U256::from(4u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    user_client.issue_guarantee(req0).await.expect("first ok");

    // Manually insert a guarantee with a higher req_id to emulate a gap.
    let forced_req_id = U256::from(5u64);
    let start_dt = DateTime::from_timestamp(start_ts as i64, 0)
        .ok_or_else(|| anyhow::anyhow!("invalid timestamp"))?
        .naive_utc();
    repo::store_guarantee_on(
        ctx.db.as_ref(),
        GuaranteeData {
            tab_id,
            req_id: forced_req_id,
            from: user_addr.clone(),
            to: recipient_addr.clone(),
            asset: DEFAULT_ASSET_ADDRESS.to_string(),
            value: U256::from(2u64),
            start_ts: start_dt,
            cert: "{}".into(),
        },
    )
    .await?;

    let req_next = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        forced_req_id + U256::from(1u64),
        U256::from(3u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    user_client
        .issue_guarantee(req_next)
        .await
        .expect("next guarantee ok");

    let latest = core_client
        .get_latest_guarantee(tab_id)
        .await
        .expect("latest guarantee")
        .expect("exists");
    assert_eq!(latest.req_id, forced_req_id + U256::from(1u64));

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_accepts_stablecoin_asset() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    insert_user_with_asset_collateral(&ctx, &user_addr, STABLE_ASSET_ADDRESS, U256::from(5u64))
        .await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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

    let cert = user_client
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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_mismatched_asset_address() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    insert_user_with_asset_collateral(&ctx, &user_addr, STABLE_ASSET_ADDRESS, U256::from(5u64))
        .await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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

    let result = user_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject mismatched asset address");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_mismatched_user_address() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let tab_user_addr = alloy::signers::local::PrivateKeySigner::random()
        .address()
        .to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &tab_user_addr, U256::from(5u64)).await?;

    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: tab_user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(3600),
        })
        .await
        .expect("create tab");

    let other_wallet = alloy::signers::local::PrivateKeySigner::random();
    let other_user_addr = other_wallet.address().to_string();
    ensure_user_with_collateral(&ctx, &other_user_addr, U256::from(5u64)).await?;
    let user_client = client_with_signer(
        &config,
        &ctx,
        &other_wallet,
        "user",
        &[SCOPE_GUARANTEE_ISSUE],
    )
    .await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &other_user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &other_wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = user_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject mismatched user address");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_mismatched_recipient_address() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let tab_recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: tab_recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(3600),
        })
        .await
        .expect("create tab");

    let forged_recipient_addr = random_address();
    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &forged_recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = user_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject mismatched recipient address");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_rejects_pending_tab_with_existing_history() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

    let tab_result = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await
        .expect("create tab");

    // Simulate a bad state where a pending tab already has a guarantee history.
    let fake_start = chrono::Utc::now().naive_utc();
    repo::store_guarantee_on(
        ctx.db.as_ref(),
        GuaranteeData {
            tab_id: tab_result.id,
            req_id: U256::ZERO,
            from: user_addr.clone(),
            to: recipient_addr.clone(),
            asset: DEFAULT_ASSET_ADDRESS.to_string(),
            value: U256::from(1u64),
            start_ts: fake_start,
            cert: "{}".into(),
        },
    )
    .await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_result.id,
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        Some(fake_start.and_utc().timestamp() as u64),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = user_client.issue_guarantee(req).await;
    assert!(
        result.is_err(),
        "must reject if pending tab already has history"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_get_tab_and_list_recipient_tabs() -> anyhow::Result<()> {
    let (_, core_client, ctx, auth) = setup_clean_db().await?;

    let user_addr = random_address();
    let recipient_addr = auth.address.clone();
    common::fixtures::ensure_user(&ctx, &user_addr).await?;

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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_get_tab_returns_none_for_missing() -> anyhow::Result<()> {
    let (_, core_client, _, _auth) = setup_clean_db().await?;

    let missing = core_client
        .get_tab(U256::from(999u64))
        .await
        .expect("get missing tab");
    assert!(missing.is_none());

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_list_recipient_tabs_invalid_status_errors() -> anyhow::Result<()> {
    let (_, core_client, _, auth) = setup_clean_db().await?;

    let err = core_client
        .list_recipient_tabs(auth.address.clone(), Some(vec!["unknown".into()]))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("invalid settlement status"),
        "unexpected error: {err}"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_list_recipient_tabs_case_insensitive_filter() -> anyhow::Result<()> {
    let (_, core_client, ctx, auth) = setup_clean_db().await?;

    let user_addr = random_address();
    let recipient_addr = auth.address.clone();
    common::fixtures::ensure_user(&ctx, &user_addr).await?;

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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_list_recipient_tabs_http_query_variants() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let user_addr = random_address();
    let recipient_addr = auth.address.clone();
    common::fixtures::ensure_user(&ctx, &user_addr).await?;

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

    let base_addr = format!(
        "http://{}:{}",
        config.server_config.host, config.server_config.port
    );
    let access_token = auth.access_token.clone();
    let http_client = reqwest::Client::new();

    let single_url = format!(
        "{base}/core/recipients/{recipient}/tabs?settlement_status=pending",
        base = base_addr,
        recipient = recipient_addr
    );
    let resp = http_client
        .get(&single_url)
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("single status request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let tabs: Vec<TabInfo> = resp.json().await.expect("decode single response");
    assert!(
        tabs.iter().any(|tab| tab.tab_id == tab_id),
        "expected tab_id {tab_id} in single-status response"
    );

    let multi_url = format!(
        "{base}/core/recipients/{recipient}/tabs?settlement_status=pending&settlement_status=settled",
        base = base_addr,
        recipient = recipient_addr
    );
    let resp = http_client
        .get(&multi_url)
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("multi status request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let tabs: Vec<TabInfo> = resp.json().await.expect("decode multi response");
    assert!(
        tabs.iter().any(|tab| tab.tab_id == tab_id),
        "expected tab_id {tab_id} in multi-status response"
    );

    let invalid_url = format!(
        "{base}/core/recipients/{recipient}/tabs?settlement_status=unknown",
        base = base_addr,
        recipient = recipient_addr
    );
    let resp = http_client
        .get(&invalid_url)
        .bearer_auth(&access_token)
        .send()
        .await
        .expect("invalid status request");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let err_json: serde_json::Value = resp.json().await.expect("decode invalid response");
    assert!(
        err_json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("invalid settlement status"),
        "unexpected error payload: {err_json:?}"
    );

    let bad_body = http_client
        .post(format!("{base}/core/payment-tabs", base = base_addr))
        .bearer_auth(access_token)
        .json(&serde_json::json!({
            "recipient_address": recipient_addr,
            "ttl": 1200
        }))
        .send()
        .await
        .expect("send invalid body");
    assert_eq!(
        bad_body.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "expected 422 for malformed request body"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn create_tab_rejects_unregistered_user() -> anyhow::Result<()> {
    let (_, core_client, _, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();

    let tab_result = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await;
    assert!(tab_result.is_err(), "must reject if user is not registered");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_recipient_payments_and_events() -> anyhow::Result<()> {
    let (_, core_client, ctx, auth) = setup_clean_db().await?;

    let user_addr = random_address();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

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

    set_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS, U256::from(5u64))
        .await
        .expect("lock collateral before remuneration");

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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_recipient_payments_flags() -> anyhow::Result<()> {
    let (_, core_client, ctx, auth) = setup_clean_db().await?;

    let user_addr = random_address();
    let recipient_addr = auth.address.clone();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(30u64)).await?;

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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_list_recipient_payments_empty() -> anyhow::Result<()> {
    let (_, core_client, _, auth) = setup_clean_db().await?;

    let payments = core_client
        .list_recipient_payments(auth.address.clone())
        .await
        .expect("list empty payments");
    assert!(payments.is_empty());

    Ok(())
}
#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_collateral_events_multiple_types() -> anyhow::Result<()> {
    let (_, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(40u64)).await?;

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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_collateral_events_empty_for_tab_without_events() -> anyhow::Result<()> {
    let (_, core_client, ctx, auth) = setup_clean_db().await?;

    let user_addr = random_address();
    let recipient_addr = auth.address.clone();
    common::fixtures::ensure_user(&ctx, &user_addr).await?;

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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_get_user_asset_balance() -> anyhow::Result<()> {
    let (_, core_client, ctx, _auth) = setup_clean_db().await?;

    let user_addr = random_address();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(15u64)).await?;

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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn core_api_get_user_asset_balance_locked_amount() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(25u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

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
    user_client
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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn verify_eip712_signature_ok() -> anyhow::Result<()> {
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
    verify_guarantee_request_signature(&params, &req).expect("valid EIP-712 signature must verify");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn verify_eip712_signature_fails_if_tampered() -> anyhow::Result<()> {
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
    match &mut req.claims {
        PaymentGuaranteeRequestClaims::V1(claims) => {
            claims.amount = U256::from(999u64);
        }
    }

    let err = verify_guarantee_request_signature(&params, &req).unwrap_err();
    assert!(
        format!("{err:?}").contains("Invalid signature"),
        "tampered claims must produce invalid signature error"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn verify_eip191_signature_ok() -> anyhow::Result<()> {
    use alloy::{primitives::keccak256, sol_types::sol};
    sol! {
        struct SolGuaranteeRequestClaimsV1 {
            address user;
            address recipient;
            uint256  tabId;
            uint256 reqId;
            uint256 amount;
            address asset;
            uint64  timestamp;
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

    let msg = SolGuaranteeRequestClaimsV1 {
        user,
        recipient,
        tabId: tab_id,
        reqId: U256::ZERO,
        amount: U256::from(1u64),
        asset: Address::from_str(DEFAULT_ASSET_ADDRESS).unwrap(),
        timestamp,
    };
    let data = msg.abi_encode();
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);
    let digest = keccak256(prefixed);

    let sig: Signature = wallet.sign_hash(&digest).await.unwrap();

    let req = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(PaymentGuaranteeRequestClaimsV1 {
            user_address: user.to_string(),
            recipient_address: recipient.to_string(),
            tab_id,
            req_id: U256::ZERO,
            amount: U256::from(1u64),
            timestamp,
            asset_address: "0x0000000000000000000000000000000000000000".into(),
        }),
        crypto::hex::encode_hex(&sig.as_bytes()),
        SigningScheme::Eip191,
    );

    verify_guarantee_request_signature(&params, &req).expect("valid EIP-191 signature must verify");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn verify_signature_fails_with_invalid_hex() -> anyhow::Result<()> {
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

    req.signature = "0xZZZZ".to_string();

    let err = verify_guarantee_request_signature(&params, &req).unwrap_err();
    assert!(
        format!("{err:?}").contains("invalid hex signature"),
        "invalid hex must be rejected"
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn list_settled_tabs_returns_only_settled_entries() -> anyhow::Result<()> {
    let (_, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

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

    set_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS, U256::from(10u64))
        .await
        .expect("lock collateral before remuneration");

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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn list_settled_tabs_empty_when_none() -> anyhow::Result<()> {
    let (_, core_client, _, auth) = setup_clean_db().await?;

    let recipient_addr = auth.address.clone();
    let settled = core_client
        .list_settled_tabs(recipient_addr)
        .await
        .expect("list settled tabs");
    assert!(settled.is_empty());

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn list_settled_tabs_ignores_pending_tabs() -> anyhow::Result<()> {
    let (_, core_client, ctx, auth) = setup_clean_db().await?;

    let user_addr = random_address();
    let recipient_addr = auth.address.clone();
    common::fixtures::ensure_user(&ctx, &user_addr).await?;

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

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn suspending_user_blocks_payment_tabs() -> anyhow::Result<()> {
    let (_, core_client, ctx, auth) = setup_clean_db().await?;

    let user_addr = random_address();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    let status = core_client
        .update_user_suspension(user_addr.clone(), true)
        .await
        .expect("suspend user");
    assert!(status.suspended);

    let err = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(600),
        })
        .await
        .expect_err("suspended user should not create tabs");
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

    let status = core_client
        .update_user_suspension(user_addr.clone(), false)
        .await
        .expect("unsuspend user");
    assert!(!status.suspended);

    core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr,
            recipient_address: recipient_addr,
            erc20_token: None,
            ttl: Some(600),
        })
        .await
        .expect("create tab after unsuspending");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::serial]
async fn suspending_user_blocks_guarantee_requests() -> anyhow::Result<()> {
    let (config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    let user_client =
        client_with_signer(&config, &ctx, &wallet, "user", &[SCOPE_GUARANTEE_ISSUE]).await?;

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(600),
        })
        .await?
        .id;

    let public_params = core_client.get_public_params().await?;
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

    core_client
        .update_user_suspension(user_addr.clone(), true)
        .await
        .expect("suspend user");

    let err = user_client
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
#[serial_test::serial]
async fn suspension_endpoint_accepts_admin_role() -> anyhow::Result<()> {
    let (config, _core_client, ctx, auth) = setup_clean_db().await?;
    let user_addr = random_address();
    common::fixtures::ensure_user(&ctx, &user_addr).await?;

    let base_addr = format!(
        "http://{}:{}",
        config.server_config.host, config.server_config.port
    );
    let access_token = auth.access_token.clone();
    let http_client = reqwest::Client::new();
    let resp = http_client
        .post(format!(
            "{base}/core/users/{user}/suspension",
            base = base_addr,
            user = user_addr
        ))
        .bearer_auth(access_token)
        .json(&UpdateUserSuspensionRequest { suspended: true })
        .send()
        .await?;

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    Ok(())
}
