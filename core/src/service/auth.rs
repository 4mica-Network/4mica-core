use crate::auth::siwe::{parse_siwe_message, verify_siwe_message};
use crate::error::{ServiceError, ServiceResult};
use crate::persist::repo;
use crate::service::CoreService;
use chrono::{DateTime, Duration, Utc};
use rand::random;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
pub struct AuthNonceRequest {
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct AuthNonceResponse {
    pub nonce: String,
    pub siwe: SiweTemplate,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiweTemplate {
    pub domain: String,
    pub uri: String,
    pub chain_id: u64,
    pub statement: String,
    pub expiration: String,
    pub issued_at: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthVerifyRequest {
    pub address: String,
    pub message: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct AuthVerifyResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct AuthRefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthRefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct AuthLogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthLogoutResponse {
    pub revoked: bool,
}

fn generate_token(prefix: &str) -> String {
    let bytes: [u8; 32] = random();
    format!("{prefix}_{}", hex::encode(bytes))
}

fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_rfc3339(label: &str, raw: &str) -> ServiceResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ServiceError::InvalidParams(format!("invalid {label} timestamp")))
}

impl CoreService {
    pub async fn create_auth_nonce(
        &self,
        req: AuthNonceRequest,
    ) -> ServiceResult<AuthNonceResponse> {
        let auth_cfg = &self.inner.config.auth;
        let now = Utc::now();
        let expires_at = now + Duration::seconds(auth_cfg.nonce_ttl_secs);
        let nonce = repo::common::new_uuid();

        repo::insert_auth_nonce(
            &self.inner.persist_ctx,
            &req.address,
            &nonce,
            expires_at.naive_utc(),
        )
        .await?;

        let host = self.inner.config.server_config.host.trim();
        let port = self.inner.config.server_config.port.trim();
        let domain = auth_cfg
            .siwe_domain
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|| {
                if host.is_empty() {
                    "localhost".to_string()
                } else {
                    host.to_string()
                }
            });
        let uri = auth_cfg
            .siwe_uri
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_string())
            .unwrap_or_else(|| {
                if port.is_empty() {
                    format!("http://{domain}")
                } else {
                    format!("http://{domain}:{port}")
                }
            });

        Ok(AuthNonceResponse {
            nonce: nonce.clone(),
            siwe: SiweTemplate {
                domain,
                uri,
                chain_id: self.inner.config.ethereum_config.chain_id,
                statement: auth_cfg.siwe_statement.clone(),
                expiration: expires_at.to_rfc3339(),
                issued_at: now.to_rfc3339(),
            },
        })
    }

    pub async fn verify_auth(&self, req: AuthVerifyRequest) -> ServiceResult<AuthVerifyResponse> {
        let auth_cfg = &self.inner.config.auth;
        let parsed = parse_siwe_message(&req.message)?;

        if parsed.address.to_string() != req.address {
            return Err(ServiceError::Unauthorized("address mismatch".into()));
        }

        if parsed.chain_id != self.inner.config.ethereum_config.chain_id {
            return Err(ServiceError::Unauthorized("invalid chain id".into()));
        }

        if let Some(expiration) = parsed.expiration_time.as_deref()
            && parse_rfc3339("expiration", expiration)? < Utc::now()
        {
            return Err(ServiceError::Unauthorized("message expired".into()));
        }

        if let Some(not_before) = parsed.not_before.as_deref()
            && parse_rfc3339("not_before", not_before)? > Utc::now()
        {
            return Err(ServiceError::Unauthorized("message not valid yet".into()));
        }

        let nonce_row =
            repo::get_auth_nonce(&self.inner.persist_ctx, &req.address, &parsed.nonce).await?;
        let nonce_row = nonce_row
            .ok_or_else(|| ServiceError::Unauthorized("nonce not found or expired".into()))?;
        if nonce_row.used_at.is_some() || nonce_row.expires_at < Utc::now().naive_utc() {
            return Err(ServiceError::Unauthorized("nonce not valid".into()));
        }

        verify_siwe_message(
            &self.inner.read_provider,
            &req.address,
            &req.message,
            &req.signature,
        )
        .await?;

        if !repo::mark_auth_nonce_used(&self.inner.persist_ctx, &req.address, &parsed.nonce).await?
        {
            return Err(ServiceError::Unauthorized("nonce already used".into()));
        }

        let refresh_token = generate_token("refresh");
        let refresh_hash = hash_refresh_token(&refresh_token);
        let now = Utc::now();
        let expires_at = now + Duration::seconds(auth_cfg.refresh_ttl_secs);

        repo::insert_refresh_token(
            &self.inner.persist_ctx,
            &refresh_hash,
            &req.address,
            now.naive_utc(),
            expires_at.naive_utc(),
        )
        .await?;

        Ok(AuthVerifyResponse {
            // Placeholder token until JWT issuance is added.
            access_token: generate_token("access"),
            refresh_token,
            expires_in: auth_cfg.access_ttl_secs,
        })
    }

    pub async fn refresh_auth(
        &self,
        req: AuthRefreshRequest,
    ) -> ServiceResult<AuthRefreshResponse> {
        let auth_cfg = &self.inner.config.auth;
        let token_hash = hash_refresh_token(&req.refresh_token);
        let row = repo::get_refresh_token(&self.inner.persist_ctx, &token_hash)
            .await?
            .ok_or_else(|| ServiceError::Unauthorized("invalid refresh token".into()))?;

        if row.revoked_at.is_some() || row.expires_at < Utc::now().naive_utc() {
            return Err(ServiceError::Unauthorized("refresh token expired".into()));
        }

        let refresh_token = generate_token("refresh");
        let refresh_hash = hash_refresh_token(&refresh_token);
        let now = Utc::now();
        let expires_at = now + Duration::seconds(auth_cfg.refresh_ttl_secs);

        repo::insert_refresh_token(
            &self.inner.persist_ctx,
            &refresh_hash,
            &row.address,
            now.naive_utc(),
            expires_at.naive_utc(),
        )
        .await?;

        repo::revoke_refresh_token(&self.inner.persist_ctx, &token_hash, Some(&refresh_hash))
            .await?;

        Ok(AuthRefreshResponse {
            access_token: generate_token("access"),
            refresh_token,
            expires_in: auth_cfg.access_ttl_secs,
        })
    }

    pub async fn logout_auth(&self, req: AuthLogoutRequest) -> ServiceResult<AuthLogoutResponse> {
        let token_hash = hash_refresh_token(&req.refresh_token);
        let revoked =
            repo::revoke_refresh_token(&self.inner.persist_ctx, &token_hash, None).await?;
        Ok(AuthLogoutResponse { revoked })
    }
}
