use anyhow::{Result, bail};
use chrono::Utc;
use core_service::auth::jwt::{AccessTokenClaims, validate_access_token};
use core_service::config::AuthConfig;
use core_service::error::ServiceError;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};

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
        scopes: vec!["tab:read".into()],
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
