use alloy::{
    primitives::{Address, B256, Signature, U256},
    signers::Signer,
    signers::local::PrivateKeySigner,
    sol_types::{SolStruct, eip712_domain, sol},
};
use alloy_sol_types::SolValue;
use chrono::Utc;
use core_service::auth::constants::{SCOPE_GUARANTEE_ISSUE, SCOPE_PAYMENT_READ};
use core_service::config::{AppConfig, DEFAULT_ASSET_ADDRESS};
use core_service::http;
use core_service::metrics::setup_metrics_recorder;
use core_service::persist::{PersistCtx, repo};
use core_service::service::CoreService;
use core_service::{auth::verify_guarantee_request_signature, util::u256_to_string};
use crypto::bls::BlsPublicKey;
use entities::guarantee as guarantee_entity;
use metrics_exporter_prometheus::PrometheusHandle;
use rand::random;
use rpc::{
    ApiClientError, CorePublicParameters, PaymentGuaranteeClaims, PaymentGuaranteeRequest,
    PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1,
    PaymentGuaranteeRequestClaimsV2, PaymentGuaranteeValidationPolicyV2, RpcProxy, SigningScheme,
    UpdateUserSuspensionRequest, compute_validation_request_hash, compute_validation_subject_hash,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde::Deserialize;
use std::str::FromStr;
use std::sync::OnceLock;
use tokio::net::TcpListener;

#[path = "common/mod.rs"]
mod common;
use common::fixtures::{
    clear_all_tables, ensure_user_with_collateral, init_test_env, random_address,
    read_locked_collateral,
};
const STABLE_ASSET_ADDRESS: &str = "0x1111111111111111111111111111111111111111";
const ADMIN_WALLET_ROLE: &str = "admin";
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

fn test_metrics_recorder(config: &AppConfig) -> anyhow::Result<PrometheusHandle> {
    static METRICS: OnceLock<PrometheusHandle> = OnceLock::new();
    if let Some(handle) = METRICS.get() {
        return Ok(handle.clone());
    }

    let handle = setup_metrics_recorder(config)?;
    let _ = METRICS.set(handle.clone());
    Ok(handle)
}

async fn spawn_test_api(config: &mut AppConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    config.server_config.host = local_addr.ip().to_string();
    config.server_config.port = local_addr.port().to_string();

    let service = CoreService::new(config.clone()).await?;
    let metrics = test_metrics_recorder(config)?;
    let app = http::router(service, metrics);
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            log::error!("test api server exited: {err}");
        }
    });

    Ok(())
}

async fn setup_clean_db() -> anyhow::Result<(AppConfig, RpcProxy, PersistCtx, AuthSession)> {
    let (mut config, ctx) = init_test_env().await?;
    clear_all_tables(&ctx).await?;
    spawn_test_api(&mut config).await?;
    let core_addr = core_base_url(&config);

    let recipient_signer = PrivateKeySigner::random();
    let auth = login_with_siwe(
        &core_addr,
        &ctx,
        &recipient_signer,
        ADMIN_WALLET_ROLE,
        &[SCOPE_PAYMENT_READ, SCOPE_GUARANTEE_ISSUE],
    )
    .await?;
    let core_client = RpcProxy::new(&core_addr)?.with_bearer_token(auth.access_token.clone());

    Ok((config, core_client, ctx, auth))
}

sol! {
    struct SolGuaranteeRequestClaimsV1 {
        address user;
        address recipient;
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
    login_with_siwe_as_address(base_addr, ctx, signer, &address, role, scopes).await
}

async fn login_with_siwe_as_address(
    base_addr: &str,
    ctx: &PersistCtx,
    signer: &PrivateKeySigner,
    address: &str,
    role: &str,
    scopes: &[&str],
) -> anyhow::Result<AuthSession> {
    let scopes = scopes
        .iter()
        .map(|scope| (*scope).to_string())
        .collect::<Vec<_>>();
    repo::upsert_wallet_role(ctx, address, role, &scopes, DEFAULT_WALLET_STATUS).await?;

    let client = reqwest::Client::new();
    let nonce_res = client
        .post(format!("{base_addr}/auth/nonce"))
        .json(&serde_json::json!({ "address": address }))
        .send()
        .await?
        .error_for_status()?;
    let nonce_res: AuthNonceResponse = nonce_res.json().await?;

    let message = build_siwe_message_from_template(&nonce_res.siwe, address, &nonce_res.nonce);
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
        address: format!("{:#x}", signer.address()),
        access_token: verify_res.access_token,
    })
}

fn mixed_case_address(raw: &str) -> String {
    let mut toggled = false;
    let mut out = String::with_capacity(raw.len());

    for (idx, ch) in raw.chars().enumerate() {
        if idx < 2 {
            out.push(ch);
            continue;
        }

        if !toggled && ch.is_ascii_hexdigit() && ch.is_ascii_lowercase() {
            out.push(ch.to_ascii_uppercase());
            toggled = true;
        } else {
            out.push(ch);
        }
    }

    out
}

fn normalize_address(raw: &str) -> String {
    format!(
        "{:#x}",
        Address::from_str(raw).expect("valid address for test")
    )
}

#[allow(clippy::too_many_arguments)]
async fn build_signed_req(
    public_params: &CorePublicParameters,
    user_addr: &str,
    recipient_addr: &str,
    _tab_id: U256,
    req_id: U256,
    amount: U256,
    wallet: &alloy::signers::local::PrivateKeySigner,
    timestamp: Option<u64>,
    asset_address: &str,
) -> PaymentGuaranteeRequest {
    let ts = timestamp.unwrap_or_else(|| Utc::now().timestamp() as u64);
    let accepted_versions = public_params.accepted_guarantee_versions_or_default();
    let prefers_v1 = accepted_versions.contains(&1);
    let requires_v2 = accepted_versions.iter().all(|&version| version >= 2);

    if !prefers_v1 && requires_v2 {
        let validation_subject_hash = compute_validation_subject_hash(
            user_addr,
            recipient_addr,
            req_id,
            amount,
            asset_address,
            ts,
        )
        .expect("compute validation subject hash");

        let validation_registry_address = public_params
            .trusted_validation_registries
            .first()
            .and_then(|value| Address::from_str(value).ok())
            .unwrap_or_else(|| {
                Address::from_str("0x1111111111111111111111111111111111111111")
                    .expect("fallback validation registry")
            });

        let mut policy = PaymentGuaranteeValidationPolicyV2 {
            validation_registry_address,
            validation_request_hash: B256::ZERO,
            validation_chain_id: public_params.chain_id,
            validator_address: Address::from_str(recipient_addr).expect("valid recipient"),
            validator_agent_id: U256::from(1u64),
            min_validation_score: 80,
            validation_subject_hash: B256::from(validation_subject_hash),
            job_hash: B256::repeat_byte(0x11),
            required_validation_tag: "hard-finality".to_string(),
        };
        policy.validation_request_hash =
            B256::from(compute_validation_request_hash(&policy).expect("compute request hash"));

        let claims = PaymentGuaranteeRequestClaimsV2 {
            user_address: user_addr.to_string(),
            recipient_address: recipient_addr.to_string(),
            req_id,
            amount,
            timestamp: ts,
            asset_address: asset_address.to_string(),
            validation_policy: policy,
        };

        let domain = eip712_domain!(
            name: public_params.eip712_name.clone(),
            version: public_params.eip712_version.clone(),
            chain_id: public_params.chain_id,
        );
        let msg = SolGuaranteeRequestClaimsV2 {
            user: Address::from_str(user_addr).unwrap(),
            recipient: Address::from_str(recipient_addr).unwrap(),
            reqId: req_id,
            amount,
            asset: Address::from_str(asset_address).unwrap(),
            timestamp: ts,
            validationRegistryAddress: claims.validation_policy.validation_registry_address,
            validationRequestHash: claims.validation_policy.validation_request_hash,
            validationChainId: U256::from(claims.validation_policy.validation_chain_id),
            validatorAddress: claims.validation_policy.validator_address,
            validatorAgentId: claims.validation_policy.validator_agent_id,
            minValidationScore: claims.validation_policy.min_validation_score,
            validationSubjectHash: claims.validation_policy.validation_subject_hash,
            jobHash: claims.validation_policy.job_hash,
            requiredValidationTag: claims.validation_policy.required_validation_tag.clone(),
        };
        let digest = msg.eip712_signing_hash(&domain);
        let sig: Signature = wallet.sign_hash(&digest).await.unwrap();
        return PaymentGuaranteeRequest::new(
            PaymentGuaranteeRequestClaims::V2(Box::new(claims)),
            crypto::hex::encode_hex(&sig.as_bytes()),
            SigningScheme::Eip712,
        );
    }

    let domain = eip712_domain!(
        name: public_params.eip712_name.clone(),
        version: public_params.eip712_version.clone(),
        chain_id: public_params.chain_id,
    );
    let msg = SolGuaranteeRequestClaimsV1 {
        user: Address::from_str(user_addr).unwrap(),
        recipient: Address::from_str(recipient_addr).unwrap(),
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
            req_id,
            amount,
            timestamp: ts,
            asset_address: asset_address.to_string(),
        }),
        crypto::hex::encode_hex(&sig.as_bytes()),
        SigningScheme::Eip712,
    )
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn auth_nonce_reuse_is_rejected() -> anyhow::Result<()> {
    let (config, _core_client, ctx, _auth) = setup_clean_db().await?;
    let base_addr = core_base_url(&config);
    let signer = PrivateKeySigner::random();
    let address = signer.address().to_string();
    let scopes = vec![SCOPE_PAYMENT_READ.to_string()];
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
#[serial_test::file_serial(db)]
async fn auth_verify_rejects_invalid_signature() -> anyhow::Result<()> {
    let (config, _core_client, ctx, _auth) = setup_clean_db().await?;
    let base_addr = core_base_url(&config);
    let signer = PrivateKeySigner::random();
    let address = signer.address().to_string();
    let scopes = vec![SCOPE_PAYMENT_READ.to_string()];
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
#[serial_test::file_serial(db)]
async fn auth_refresh_rotates_tokens() -> anyhow::Result<()> {
    let (config, _core_client, ctx, _auth) = setup_clean_db().await?;
    let base_addr = core_base_url(&config);
    let signer = PrivateKeySigner::random();
    let address = signer.address().to_string();
    let scopes = vec![SCOPE_PAYMENT_READ.to_string()];
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
#[serial_test::file_serial(db)]
async fn wallet_role_lookup_accepts_mixed_case_wallet_address() -> anyhow::Result<()> {
    let (_config, _core_client, ctx, _auth) = setup_clean_db().await?;
    let signer = PrivateKeySigner::random();
    let stored_address = format!("{:#x}", signer.address());
    let presented_address = mixed_case_address(&stored_address);

    assert_eq!(stored_address, presented_address.to_ascii_lowercase());
    let scopes = vec![
        SCOPE_PAYMENT_READ.to_string(),
        SCOPE_GUARANTEE_ISSUE.to_string(),
    ];
    repo::upsert_wallet_role(
        &ctx,
        &stored_address,
        ADMIN_WALLET_ROLE,
        &scopes,
        DEFAULT_WALLET_STATUS,
    )
    .await?;
    let row = repo::get_wallet_role(&ctx, &presented_address)
        .await?
        .expect("wallet role should be retrievable by mixed-case address");
    assert_eq!(row.role, ADMIN_WALLET_ROLE);
    assert_eq!(
        row.scopes,
        serde_json::json!(["guarantee:issue", "payment:read"])
    );

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
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
#[serial_test::file_serial(db)]
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
#[serial_test::file_serial(db)]
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
#[serial_test::file_serial(db)]
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

async fn insert_user_with_asset_collateral(
    ctx: &PersistCtx,
    addr: &str,
    asset: &str,
    amount: U256,
) -> anyhow::Result<()> {
    if let Err(err) = common::fixtures::ensure_user(ctx, addr).await {
        return Err(anyhow::anyhow!("failed to ensure user: {err}"));
    }
    repo::deposit(
        ctx,
        normalize_address(addr),
        normalize_address(asset),
        amount,
    )
    .await?;
    Ok(())
}

async fn list_cycle_guarantees_for_recipient(
    ctx: &PersistCtx,
    recipient_addr: &str,
) -> anyhow::Result<Vec<guarantee_entity::Model>> {
    let rows = guarantee_entity::Entity::find()
        .filter(guarantee_entity::Column::ToAddress.eq(normalize_address(recipient_addr)))
        .order_by_asc(guarantee_entity::Column::ReqId)
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

sol! {
    struct SolGuaranteeRequestClaimsV2 {
        address user;
        address recipient;
        uint256 reqId;
        uint256 amount;
        address asset;
        uint64 timestamp;
        address validationRegistryAddress;
        bytes32 validationRequestHash;
        uint256 validationChainId;
        address validatorAddress;
        uint256 validatorAgentId;
        uint8 minValidationScore;
        bytes32 validationSubjectHash;
        bytes32 jobHash;
        string requiredValidationTag;
    }
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
            req_id: U256::from(0u64),
            amount: U256::from(42u64),
            timestamp,
            asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        }),
        crypto::hex::encode_hex(&sig.as_bytes()),
        SigningScheme::Eip712,
    )
}

fn sample_v2_claims(
    params: &CorePublicParameters,
    wallet: &PrivateKeySigner,
) -> PaymentGuaranteeRequestClaimsV2 {
    let user_address = wallet.address().to_string();
    let recipient_address = Address::from(random::<[u8; 20]>()).to_string();
    let asset_address = DEFAULT_ASSET_ADDRESS.to_string();
    let req_id = U256::from(0u64);
    let amount = U256::from(42u64);
    let timestamp = Utc::now().timestamp() as u64;

    let validation_subject_hash = compute_validation_subject_hash(
        &user_address,
        &recipient_address,
        req_id,
        amount,
        &asset_address,
        timestamp,
    )
    .expect("compute subject hash");

    let mut policy = PaymentGuaranteeValidationPolicyV2 {
        validation_registry_address: Address::from_str(
            "0x1111111111111111111111111111111111111111",
        )
        .expect("valid validation registry"),
        validation_request_hash: B256::ZERO,
        validation_chain_id: params.chain_id,
        validator_address: Address::from_str("0x2222222222222222222222222222222222222222")
            .expect("valid validator"),
        validator_agent_id: U256::from(77u64),
        min_validation_score: 80,
        validation_subject_hash: B256::from(validation_subject_hash),
        job_hash: B256::repeat_byte(0x11),
        required_validation_tag: "hard-finality".to_string(),
    };

    policy.validation_request_hash =
        B256::from(compute_validation_request_hash(&policy).expect("compute request hash"));

    PaymentGuaranteeRequestClaimsV2 {
        user_address,
        recipient_address,
        req_id,
        amount,
        asset_address,
        timestamp,
        validation_policy: policy,
    }
}

async fn build_eip712_signed_request_v2(
    params: &CorePublicParameters,
    wallet: &PrivateKeySigner,
) -> PaymentGuaranteeRequest {
    let claims = sample_v2_claims(params, wallet);
    let digest = SolGuaranteeRequestClaimsV2 {
        user: Address::from_str(&claims.user_address).expect("valid user"),
        recipient: Address::from_str(&claims.recipient_address).expect("valid recipient"),
        reqId: claims.req_id,
        amount: claims.amount,
        asset: Address::from_str(&claims.asset_address).expect("valid asset"),
        timestamp: claims.timestamp,
        validationRegistryAddress: claims.validation_policy.validation_registry_address,
        validationRequestHash: claims.validation_policy.validation_request_hash,
        validationChainId: U256::from(claims.validation_policy.validation_chain_id),
        validatorAddress: claims.validation_policy.validator_address,
        validatorAgentId: claims.validation_policy.validator_agent_id,
        minValidationScore: claims.validation_policy.min_validation_score,
        validationSubjectHash: claims.validation_policy.validation_subject_hash,
        jobHash: claims.validation_policy.job_hash,
        requiredValidationTag: claims.validation_policy.required_validation_tag.clone(),
    }
    .eip712_signing_hash(&eip712_domain!(
        name: params.eip712_name.clone(),
        version: params.eip712_version.clone(),
        chain_id: params.chain_id,
    ));

    let sig: Signature = wallet.sign_hash(&digest).await.expect("sign v2 eip712");
    PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V2(Box::new(claims)),
        crypto::hex::encode_hex(&sig.as_bytes()),
        SigningScheme::Eip712,
    )
}

async fn build_eip191_signed_request_v2(
    params: &CorePublicParameters,
    wallet: &PrivateKeySigner,
) -> PaymentGuaranteeRequest {
    let claims = sample_v2_claims(params, wallet);
    let data = SolGuaranteeRequestClaimsV2 {
        user: Address::from_str(&claims.user_address).expect("valid user"),
        recipient: Address::from_str(&claims.recipient_address).expect("valid recipient"),
        reqId: claims.req_id,
        amount: claims.amount,
        asset: Address::from_str(&claims.asset_address).expect("valid asset"),
        timestamp: claims.timestamp,
        validationRegistryAddress: claims.validation_policy.validation_registry_address,
        validationRequestHash: claims.validation_policy.validation_request_hash,
        validationChainId: U256::from(claims.validation_policy.validation_chain_id),
        validatorAddress: claims.validation_policy.validator_address,
        validatorAgentId: claims.validation_policy.validator_agent_id,
        minValidationScore: claims.validation_policy.min_validation_score,
        validationSubjectHash: claims.validation_policy.validation_subject_hash,
        jobHash: claims.validation_policy.job_hash,
        requiredValidationTag: claims.validation_policy.required_validation_tag.clone(),
    }
    .abi_encode();
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    prefixed.extend_from_slice(&data);
    let digest = alloy::primitives::keccak256(prefixed);
    let sig: Signature = wallet.sign_hash(&digest).await.expect("sign v2 eip191");
    PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V2(Box::new(claims)),
        crypto::hex::encode_hex(&sig.as_bytes()),
        SigningScheme::Eip191,
    )
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_guarantee_accepts_sequential_req_ids() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();

    let tab_id = U256::from_be_bytes(random::<[u8; 32]>());

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
        tab_id,
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
    assert_eq!(guarantees[0].req_id, u256_to_string(U256::ZERO));
    assert_eq!(guarantees[1].req_id, u256_to_string(U256::from(1u64)));

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn core_api_guarantee_queries() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    let tab_id = U256::from_be_bytes(random::<[u8; 32]>());

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

    let guarantees = list_cycle_guarantees_for_recipient(&ctx, &recipient_addr).await?;
    assert_eq!(guarantees.len(), 1);
    let guarantee = &guarantees[0];
    assert_eq!(guarantee.req_id, u256_to_string(U256::ZERO));
    assert_eq!(guarantee.value, U256::from(5u64).to_string());
    assert!(!guarantee.cycle_id.is_empty());
    assert!(!guarantee.guarantee_id.is_empty());

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn core_api_guarantee_history_ordering() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

    let tab_id = U256::from_be_bytes(random::<[u8; 32]>());

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
    assert_eq!(guarantees[0].req_id, u256_to_string(U256::ZERO));
    assert_eq!(guarantees[1].req_id, u256_to_string(U256::from(1u64)));
    assert_eq!(guarantees[1].value, U256::from(7u64).to_string());

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_two_guarantees_verifies_total_amount() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(100u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let tab_id = U256::from_be_bytes(random::<[u8; 32]>());

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
        tab_id,
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
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

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
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    insert_user_with_asset_collateral(&ctx, &user_addr, STABLE_ASSET_ADDRESS, U256::from(5u64))
        .await?;

    let tab_id = U256::from_be_bytes(random::<[u8; 32]>());

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
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
        .filter(guarantee_entity::Column::ToAddress.eq(normalize_address(&recipient_addr)))
        .filter(guarantee_entity::Column::AssetAddress.eq(normalize_address(STABLE_ASSET_ADDRESS)))
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
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    insert_user_with_asset_collateral(&ctx, &user_addr, STABLE_ASSET_ADDRESS, U256::from(5u64))
        .await?;

    let tab_id = U256::from_be_bytes(random::<[u8; 32]>());

    let public_params = core_client.get_public_params().await.unwrap();
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
    assert!(result.is_err(), "must reject mismatched asset address");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn issue_guarantee_uses_signed_user_without_tab_match() -> anyhow::Result<()> {
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;

    let tab_user_addr = alloy::signers::local::PrivateKeySigner::random()
        .address()
        .to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &tab_user_addr, U256::from(5u64)).await?;

    let tab_id = U256::from_be_bytes(random::<[u8; 32]>());

    let other_wallet = alloy::signers::local::PrivateKeySigner::random();
    let other_user_addr = other_wallet.address().to_string();
    ensure_user_with_collateral(&ctx, &other_user_addr, U256::from(5u64)).await?;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &other_user_addr,
        &recipient_addr,
        tab_id,
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
    let (_config, core_client, ctx, _auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    let tab_id = U256::from_be_bytes(random::<[u8; 32]>());

    let forged_recipient_addr = random_address();
    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &forged_recipient_addr,
        tab_id,
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
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = auth.address.clone();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

    let tab_id = U256::from_be_bytes(random::<[u8; 32]>());

    let public_params = core_client.get_public_params().await.unwrap();

    let req_b = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
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
        tab_id,
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
async fn verify_eip712_signature_ok() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 1,
        accepted_guarantee_versions: vec![1],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();

    let req = build_eip712_signed_request(&params, &wallet).await;
    verify_guarantee_request_signature(&params, &req).expect("valid EIP-712 signature must verify");

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_eip712_signature_fails_if_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 1,
        accepted_guarantee_versions: vec![1],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();

    let mut req = build_eip712_signed_request(&params, &wallet).await;
    match &mut req.claims {
        PaymentGuaranteeRequestClaims::V1(claims) => {
            claims.amount = U256::from(999u64);
        }
        PaymentGuaranteeRequestClaims::V2(_) => {
            panic!("test fixture builds only v1 guarantee requests");
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
#[serial_test::file_serial(db)]
async fn verify_eip191_signature_ok() -> anyhow::Result<()> {
    use alloy::{primitives::keccak256, sol_types::sol};
    sol! {
        struct SolGuaranteeRequestClaimsV1 {
            address user;
            address recipient;
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
        max_accepted_guarantee_version: 1,
        accepted_guarantee_versions: vec![1],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user = wallet.address();
    let recipient = Address::from(rand::random::<[u8; 20]>());
    let timestamp = Utc::now().timestamp() as u64;
    let msg = SolGuaranteeRequestClaimsV1 {
        user,
        recipient,
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
#[serial_test::file_serial(db)]
async fn verify_signature_fails_with_invalid_hex() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 1,
        accepted_guarantee_versions: vec![1],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
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
#[serial_test::file_serial(db)]
async fn verify_v2_eip712_signature_ok() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let req = build_eip712_signed_request_v2(&params, &wallet).await;
    verify_guarantee_request_signature(&params, &req).expect("valid V2 EIP-712 must verify");
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_v2_eip191_signature_ok() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let req = build_eip191_signed_request_v2(&params, &wallet).await;
    verify_guarantee_request_signature(&params, &req).expect("valid V2 EIP-191 must verify");
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_v2_signature_fails_if_validation_request_hash_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_request_v2(&params, &wallet).await;
    match &mut req.claims {
        PaymentGuaranteeRequestClaims::V2(claims) => {
            claims.validation_policy.validation_request_hash = B256::repeat_byte(0x11);
        }
        PaymentGuaranteeRequestClaims::V1(_) => panic!("must be V2"),
    }
    let err = verify_guarantee_request_signature(&params, &req).expect_err("tamper must fail");
    assert!(format!("{err:?}").contains("Invalid signature"));
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_v2_signature_fails_if_validator_address_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_request_v2(&params, &wallet).await;
    match &mut req.claims {
        PaymentGuaranteeRequestClaims::V2(claims) => {
            claims.validation_policy.validator_address = Address::from(random::<[u8; 20]>());
        }
        PaymentGuaranteeRequestClaims::V1(_) => panic!("must be V2"),
    }
    let err = verify_guarantee_request_signature(&params, &req).expect_err("tamper must fail");
    assert!(format!("{err:?}").contains("Invalid signature"));
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_v2_signature_fails_if_validation_subject_hash_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_request_v2(&params, &wallet).await;
    match &mut req.claims {
        PaymentGuaranteeRequestClaims::V2(claims) => {
            claims.validation_policy.validation_subject_hash = B256::repeat_byte(0x22);
        }
        PaymentGuaranteeRequestClaims::V1(_) => panic!("must be V2"),
    }
    let err = verify_guarantee_request_signature(&params, &req).expect_err("tamper must fail");
    assert!(format!("{err:?}").contains("Invalid signature"));
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn verify_v2_signature_fails_if_required_validation_tag_tampered() -> anyhow::Result<()> {
    let params = CorePublicParameters {
        public_key: vec![],
        contract_address: "".to_string(),
        ethereum_http_rpc_url: "".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 1,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    };
    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let mut req = build_eip712_signed_request_v2(&params, &wallet).await;
    match &mut req.claims {
        PaymentGuaranteeRequestClaims::V2(claims) => {
            claims.validation_policy.required_validation_tag = "soft-finality".to_string();
        }
        PaymentGuaranteeRequestClaims::V1(_) => panic!("must be V2"),
    }
    let err = verify_guarantee_request_signature(&params, &req).expect_err("tamper must fail");
    assert!(format!("{err:?}").contains("Invalid signature"));
    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn suspending_recipient_blocks_guarantee_requests() -> anyhow::Result<()> {
    let (config, core_client, ctx, _) = setup_clean_db().await?;

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

    let tab_id = U256::from_be_bytes(random::<[u8; 32]>());

    let public_params = core_client.get_public_params().await?;
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
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
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;
    let recipient_addr = auth.address.clone();

    let user_wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = user_wallet.address().to_string();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    let tab_id = U256::from_be_bytes(random::<[u8; 32]>());

    let public_params = core_client.get_public_params().await?;
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
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
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;

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
    let (_config, core_client, ctx, auth) = setup_clean_db().await?;

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
