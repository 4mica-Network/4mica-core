//! HTTP-layer test harness: spins up the core API server, drives the SIWE auth
//! flow, and builds signed guarantee requests. Shared by `api_auth.rs`,
//! `api_guarantee.rs`, and `signatures.rs`.

use alloy::{
    primitives::{Address, B256, Signature, U256},
    signers::Signer,
    signers::local::PrivateKeySigner,
    sol_types::{SolStruct, eip712_domain, sol},
};
use alloy_sol_types::SolValue;
use chrono::Utc;
use core_service::config::{AppConfig, DEFAULT_ASSET_ADDRESS};
use core_service::http;
use core_service::metrics::setup_metrics_recorder;
use core_service::persist::{PersistCtx, repo};
use core_service::service::CoreService;
use entities::guarantee as guarantee_entity;
use metrics_exporter_prometheus::PrometheusHandle;
use rand::random;
use rpc::{
    CorePublicParameters, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestClaimsV1, PaymentGuaranteeRequestClaimsV2,
    PaymentGuaranteeValidationPolicyV2, RpcProxy, SigningScheme, compute_validation_request_hash,
    compute_validation_subject_hash,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use serde::Deserialize;
use std::str::FromStr;
use std::sync::OnceLock;
use tokio::net::TcpListener;

use super::db::{clear_all_tables, setup_db_test_env};
use super::fixtures::normalize_address;

pub const STABLE_ASSET_ADDRESS: &str = "0x1111111111111111111111111111111111111111";
pub const ADMIN_WALLET_ROLE: &str = "admin";
pub const DEFAULT_WALLET_STATUS: &str = "active";

#[derive(Debug, Deserialize)]
pub struct AuthNonceResponse {
    pub nonce: String,
    pub siwe: SiweTemplateResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiweTemplateResponse {
    pub domain: String,
    pub uri: String,
    pub chain_id: u64,
    pub statement: String,
    pub expiration: String,
    pub issued_at: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthVerifyResponse {
    pub access_token: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Clone, Debug)]
pub struct AuthSession {
    pub address: String,
    pub access_token: String,
}

pub fn core_base_url(config: &AppConfig) -> String {
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

pub async fn spawn_test_api(config: &mut AppConfig) -> anyhow::Result<()> {
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

/// Spin up a clean DB + API server, log in an admin recipient via SIWE, and
/// return a bearer-authenticated RpcProxy plus the auth session.
pub async fn setup_http_test_environment()
-> anyhow::Result<(AppConfig, RpcProxy, PersistCtx, AuthSession)> {
    use core_service::auth::constants::{SCOPE_GUARANTEE_ISSUE, SCOPE_PAYMENT_READ};

    let (mut config, ctx) = setup_db_test_env().await?;
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

pub fn build_siwe_message_from_template(
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

pub async fn login_with_siwe(
    base_addr: &str,
    ctx: &PersistCtx,
    signer: &PrivateKeySigner,
    role: &str,
    scopes: &[&str],
) -> anyhow::Result<AuthSession> {
    let address = signer.address().to_string();
    login_with_siwe_as_address(base_addr, ctx, signer, &address, role, scopes).await
}

pub async fn login_with_siwe_as_address(
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

pub fn mixed_case_address(raw: &str) -> String {
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

/// Infallible address normalization for test assertions (panics on bad input).
pub fn norm_addr(raw: &str) -> String {
    normalize_address(raw).expect("valid address for test")
}

pub async fn client_with_signer(
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

pub async fn insert_user_with_asset_collateral(
    ctx: &PersistCtx,
    addr: &str,
    asset: &str,
    amount: U256,
) -> anyhow::Result<()> {
    super::fixtures::ensure_user(ctx, addr).await?;
    repo::deposit(ctx, norm_addr(addr), norm_addr(asset), amount).await?;
    Ok(())
}

pub async fn list_cycle_guarantees_for_recipient(
    ctx: &PersistCtx,
    recipient_addr: &str,
) -> anyhow::Result<Vec<guarantee_entity::Model>> {
    let rows = guarantee_entity::Entity::find()
        .filter(guarantee_entity::Column::ToAddress.eq(norm_addr(recipient_addr)))
        .order_by_asc(guarantee_entity::Column::ReqId)
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
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

/// Build an EIP-712-signed guarantee request. Picks V2 when the server only
/// accepts validation-gated versions, otherwise V1.
#[allow(clippy::too_many_arguments)]
pub async fn build_signed_req(
    public_params: &CorePublicParameters,
    user_addr: &str,
    recipient_addr: &str,
    req_id: U256,
    amount: U256,
    wallet: &PrivateKeySigner,
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

pub async fn build_eip712_signed_request(
    params: &CorePublicParameters,
    wallet: &PrivateKeySigner,
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

pub fn sample_v2_claims(
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

pub async fn build_eip712_signed_request_v2(
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

pub async fn build_eip191_signed_request_v2(
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
