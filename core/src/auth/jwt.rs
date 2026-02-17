use crate::config::AuthConfig;
use crate::error::{ServiceError, ServiceResult};
use anyhow::anyhow;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub role: String,
    pub scopes: Vec<String>,
    pub iss: String,
    pub aud: String,
    pub iat: usize,
    pub exp: usize,
    pub nbf: usize,
    pub jti: String,
    pub chain_id: u64,
}

pub fn issue_access_token(
    cfg: &AuthConfig,
    encoding_key: &EncodingKey,
    sub: &str,
    role: &str,
    scopes: Vec<String>,
    chain_id: u64,
) -> ServiceResult<String> {
    let now = unix_timestamp()?;
    let exp = now
        .checked_add(cfg.access_ttl_secs)
        .ok_or_else(|| ServiceError::Other(anyhow!("access token exp overflow")))?;

    let claims = AccessTokenClaims {
        sub: sub.to_string(),
        role: role.to_string(),
        scopes,
        iss: cfg.jwt_issuer.clone(),
        aud: cfg.jwt_audience.clone(),
        iat: to_usize(now, "iat")?,
        exp: to_usize(exp, "exp")?,
        nbf: to_usize(now, "nbf")?,
        jti: Uuid::new_v4().to_string(),
        chain_id,
    };

    let header = Header::new(Algorithm::HS256);
    jsonwebtoken::encode(&header, &claims, encoding_key)
        .map_err(|err| ServiceError::Other(anyhow!("failed to issue jwt: {err}")))
}

pub fn validate_access_token(
    cfg: &AuthConfig,
    decoding_key: &DecodingKey,
    expected_chain_id: u64,
    token: &str,
) -> ServiceResult<AccessTokenClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(std::slice::from_ref(&cfg.jwt_issuer));
    validation.set_audience(std::slice::from_ref(&cfg.jwt_audience));
    validation.validate_exp = true;
    validation.validate_nbf = true;

    let data = jsonwebtoken::decode::<AccessTokenClaims>(token, decoding_key, &validation)
        .map_err(|_| ServiceError::Unauthorized("invalid access token".into()))?;

    if data.claims.chain_id != expected_chain_id {
        return Err(ServiceError::Unauthorized("invalid chain id".into()));
    }

    Ok(data.claims)
}

fn unix_timestamp() -> ServiceResult<u64> {
    let now = Utc::now().timestamp();
    u64::try_from(now).map_err(|_| ServiceError::Other(anyhow!("system clock before epoch")))
}

fn to_usize(value: u64, label: &str) -> ServiceResult<usize> {
    usize::try_from(value)
        .map_err(|_| ServiceError::Other(anyhow!("jwt claim {label} does not fit into usize")))
}
