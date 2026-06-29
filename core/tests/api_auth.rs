//! HTTP API: authentication (SIWE nonce/verify/refresh), JWT expiry, core
//! payment/balance queries, and the admin suspension endpoint.

use alloy::primitives::U256;
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Result, bail};
use chrono::Utc;
use core_service::auth::constants::ROLE_USER;
use core_service::auth::constants::SCOPE_PAYMENT_READ;
use core_service::auth::jwt::{AccessTokenClaims, validate_access_token};
use core_service::config::{AuthConfig, DEFAULT_ASSET_ADDRESS};
use core_service::error::ServiceError;
use core_service::persist::repo;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use rpc::UpdateUserSuspensionRequest;

#[path = "common/mod.rs"]
mod common;
use common::api::*;
use common::fixtures::{ensure_user_with_collateral, random_address};

// ════════════════════════ SIWE auth flow ════════════════════════
#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn auth_nonce_reuse_is_rejected() -> anyhow::Result<()> {
    let (config, _core_client, ctx, _auth) = setup_http_test_environment().await?;
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
    let (config, _core_client, ctx, _auth) = setup_http_test_environment().await?;
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
    let (config, _core_client, ctx, _auth) = setup_http_test_environment().await?;
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

// ════════════════════════ core API queries ════════════════════════

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn core_api_recipient_payments_flags() -> anyhow::Result<()> {
    let (_, core_client, ctx, auth) = setup_http_test_environment().await?;

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
    let (_, core_client, _, auth) = setup_http_test_environment().await?;

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
    let (_, core_client, ctx, _auth) = setup_http_test_environment().await?;

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
async fn core_api_get_user_asset_balance_denies_foreign_read_for_plain_user() -> anyhow::Result<()>
{
    let (config, _core_client, ctx, _auth) = setup_http_test_environment().await?;
    let base_addr = core_base_url(&config);

    let caller = PrivateKeySigner::random();
    let caller_auth =
        login_with_siwe(&base_addr, &ctx, &caller, ROLE_USER, &[SCOPE_PAYMENT_READ]).await?;
    let caller_client =
        rpc::RpcProxy::new(&base_addr)?.with_bearer_token(caller_auth.access_token.clone());

    let foreign_user = random_address();
    ensure_user_with_collateral(&ctx, &foreign_user, U256::from(15u64)).await?;

    let err = caller_client
        .get_user_asset_balance(foreign_user, DEFAULT_ASSET_ADDRESS.to_string())
        .await
        .expect_err("plain user must not read another wallet's balance");

    match err {
        rpc::ApiClientError::Api { status, message } => {
            assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
            assert!(
                message.contains("user address does not match token subject"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    Ok(())
}

#[test_log::test(tokio::test)]
#[serial_test::file_serial(db)]
async fn suspension_endpoint_accepts_admin_role() -> anyhow::Result<()> {
    let (config, _core_client, ctx, auth) = setup_http_test_environment().await?;
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

// ════════════════════════ JWT ════════════════════════

fn test_auth_config() -> AuthConfig {
    AuthConfig {
        nonce_ttl_secs: 300,
        refresh_ttl_secs: 3600,
        access_ttl_secs: 900,
        jwt_issuer: "test-issuer".to_string(),
        jwt_audience: "test-audience".to_string(),
        siwe_statement: "Sign in to 4mica.".to_string(),
        siwe_domain: None,
        siwe_uri: None,
    }
}

fn test_keys() -> (EncodingKey, DecodingKey) {
    let secret = "test-secret";
    let secret_bytes = secret.as_bytes();
    let enc_key = EncodingKey::from_secret(secret_bytes);
    let dec_key = DecodingKey::from_secret(secret_bytes);
    (enc_key, dec_key)
}

#[test]
fn access_token_expiry_is_enforced() -> Result<()> {
    let cfg = test_auth_config();
    let (enc_key, dec_key) = test_keys();

    let now = Utc::now().timestamp();
    let now = if now < 3600 { 3600 } else { now };
    let iat = usize::try_from(now as u64).map_err(|_| anyhow::anyhow!("timestamp overflow"))?;
    let exp = iat - 3600;
    let chain_id = 1;

    let claims = AccessTokenClaims {
        sub: "0x0000000000000000000000000000000000000001".into(),
        role: "user".into(),
        scopes: vec!["payment:read".into()],
        iss: cfg.jwt_issuer.clone(),
        aud: cfg.jwt_audience.clone(),
        iat,
        exp,
        nbf: iat,
        jti: "test-jti".into(),
        chain_id,
    };

    let token = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &enc_key)?;

    match validate_access_token(&cfg, &dec_key, chain_id, &token) {
        Ok(_) => bail!("expired token should be rejected"),
        Err(ServiceError::Unauthorized(_)) => Ok(()),
        Err(err) => bail!("unexpected error: {err:?}"),
    }
}
