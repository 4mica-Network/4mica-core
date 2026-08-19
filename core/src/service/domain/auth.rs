use crate::auth;
use crate::auth::constants::{DEFAULT_ROLE, DEFAULT_SCOPES};
use crate::auth::jwt::AccessTokenClaims;
use crate::error::{ServiceError, ServiceResult};
use crate::persist::{mapper, repo};
use crate::service::ctx::Ctx;
use chrono::{DateTime, Duration, Utc};
use log::{debug, warn};
use rpc::{
    AuthLogoutRequest, AuthLogoutResponse, AuthNonceRequest, AuthNonceResponse, AuthRefreshRequest,
    AuthRefreshResponse, AuthVerifyRequest, AuthVerifyResponse, SiweTemplate, UserSuspensionStatus,
};
use std::sync::Arc;

const SIWE_CLOCK_SKEW_SECS: i64 = 30;

fn validate_siwe_issued_at(
    issued_at: &str,
    now: DateTime<Utc>,
    max_age: Duration,
) -> ServiceResult<()> {
    let issued_at = auth::utils::parse_rfc3339_date("issued_at", issued_at)?;

    if issued_at > now + Duration::seconds(SIWE_CLOCK_SKEW_SECS) {
        return Err(ServiceError::Unauthorized(
            "siwe issued_at is too far in the future".into(),
        ));
    }

    if now.signed_duration_since(issued_at) > max_age {
        return Err(ServiceError::Unauthorized(
            "siwe issued_at is too old".into(),
        ));
    }

    Ok(())
}

fn validate_optional_expiration(expiration: Option<&str>, now: DateTime<Utc>) -> ServiceResult<()> {
    let Some(expiration) = expiration else {
        return Ok(());
    };

    let expiration = auth::utils::parse_rfc3339_date("expiration", expiration)?;
    if expiration < now {
        return Err(ServiceError::Unauthorized("message expired".into()));
    }

    Ok(())
}

fn validate_optional_not_before(not_before: Option<&str>, now: DateTime<Utc>) -> ServiceResult<()> {
    let Some(not_before) = not_before else {
        return Ok(());
    };

    let not_before = auth::utils::parse_rfc3339_date("not_before", not_before)?;
    if not_before > now {
        return Err(ServiceError::Unauthorized("message not valid yet".into()));
    }

    Ok(())
}

pub struct AuthService {
    ctx: Arc<Ctx>,
}

impl AuthService {
    pub fn new(ctx: Arc<Ctx>) -> Self {
        Self { ctx }
    }

    fn build_siwe_context(&self) -> (String, String, String) {
        let auth_cfg = &self.ctx.config.auth;
        let host = self.ctx.config.server_config.host.trim();
        let port = self.ctx.config.server_config.port.trim();
        let domain = auth_cfg
            .siwe_domain
            .as_deref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                if host.is_empty() {
                    "localhost".to_owned()
                } else {
                    host.to_string()
                }
            });
        let uri = auth_cfg
            .siwe_uri
            .as_deref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                if port.is_empty() {
                    format!("http://{domain}")
                } else {
                    format!("http://{domain}:{port}")
                }
            });
        (domain, uri, auth_cfg.siwe_statement.clone())
    }

    pub fn validate_access_token(&self, token: &str) -> ServiceResult<AccessTokenClaims> {
        auth::jwt::validate_access_token(
            &self.ctx.config.auth,
            &self.ctx.config.secrets.jwt_dec_key,
            self.ctx.config.ethereum_config.chain_id,
            token,
        )
    }

    async fn load_wallet_claims(&self, address: &str) -> ServiceResult<(String, Vec<String>)> {
        let row = repo::get_wallet_role(&self.ctx.persist, address).await?;
        match row {
            Some(model) => {
                auth::utils::validate_wallet_status(&model.status)?;
                let scopes = auth::utils::parse_wallet_scopes(address, model.scopes)?;
                debug!(
                    "loaded wallet role: address={}, role={}, status={}, scopes={:?}",
                    address, model.role, model.status, scopes
                );
                Ok((model.role, scopes))
            }
            None => {
                warn!(
                    "wallet role not found: address={}, using defaults role={}, scopes={:?}",
                    address, DEFAULT_ROLE, DEFAULT_SCOPES
                );
                Ok((
                    DEFAULT_ROLE.to_string(),
                    DEFAULT_SCOPES.map(|s| s.to_string()).to_vec(),
                ))
            }
        }
    }

    pub async fn create_auth_nonce(
        &self,
        req: AuthNonceRequest,
    ) -> ServiceResult<AuthNonceResponse> {
        let auth_cfg = &self.ctx.config.auth;
        let address = auth::utils::normalize_wallet_address(&req.address)?;
        let now = Utc::now();
        let expires_at = now + Duration::seconds(auth_cfg.nonce_ttl_secs);
        let nonce = repo::common::new_uuid();

        repo::insert_auth_nonce(&self.ctx.persist, &address, &nonce, expires_at.naive_utc())
            .await?;

        let (domain, uri, statement) = self.build_siwe_context();

        Ok(AuthNonceResponse {
            nonce: nonce.clone(),
            siwe: SiweTemplate {
                domain,
                uri,
                chain_id: self.ctx.config.ethereum_config.chain_id,
                statement,
                expiration: expires_at.to_rfc3339(),
                issued_at: now.to_rfc3339(),
            },
        })
    }

    pub async fn verify_auth(&self, req: AuthVerifyRequest) -> ServiceResult<AuthVerifyResponse> {
        let auth_cfg = &self.ctx.config.auth;
        let parsed = crate::evm::siwe::parse_siwe_message(&req.message)?;
        let expected_address = auth::utils::parse_wallet_address(&req.address)?;

        if parsed.address != expected_address {
            return Err(ServiceError::Unauthorized("address mismatch".into()));
        }

        let address = format!("{expected_address:#x}");

        if parsed.version.trim() != "1" {
            return Err(ServiceError::Unauthorized("invalid siwe version".into()));
        }

        if parsed.chain_id != self.ctx.config.ethereum_config.chain_id {
            return Err(ServiceError::Unauthorized("invalid chain id".into()));
        }

        let (expected_domain, expected_uri, expected_statement) = self.build_siwe_context();
        if !parsed.domain.eq_ignore_ascii_case(&expected_domain) {
            return Err(ServiceError::Unauthorized("siwe domain mismatch".into()));
        }
        if parsed.uri.trim() != expected_uri {
            return Err(ServiceError::Unauthorized("siwe uri mismatch".into()));
        }

        let expected_statement = expected_statement.trim();
        let statement_matches = if expected_statement.is_empty() {
            parsed
                .statement
                .as_deref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
        } else {
            parsed.statement.as_deref().map(|value| value.trim()) == Some(expected_statement)
        };
        if !statement_matches {
            return Err(ServiceError::Unauthorized("siwe statement mismatch".into()));
        }

        let now = Utc::now();
        validate_siwe_issued_at(
            &parsed.issued_at,
            now,
            Duration::seconds(auth_cfg.nonce_ttl_secs),
        )?;
        validate_optional_expiration(parsed.expiration_time.as_deref(), now)?;
        validate_optional_not_before(parsed.not_before.as_deref(), now)?;

        let nonce_row = repo::get_auth_nonce(&self.ctx.persist, &address, &parsed.nonce).await?;
        let nonce_row = nonce_row
            .ok_or_else(|| ServiceError::Unauthorized("nonce not found or expired".into()))?;
        if nonce_row.used_at.is_some() || nonce_row.expires_at < now.naive_utc() {
            return Err(ServiceError::Unauthorized("nonce not valid".into()));
        }

        self.ctx
            .chain
            .verify_siwe_message(&address, &req.message, &req.signature)
            .await?;

        if !repo::mark_auth_nonce_used(&self.ctx.persist, &address, &parsed.nonce).await? {
            return Err(ServiceError::Unauthorized("nonce already used".into()));
        }

        let subject = address;
        let (role, scopes) = self.load_wallet_claims(&subject).await?;
        let access_token = auth::jwt::issue_access_token(
            auth_cfg,
            &self.ctx.config.secrets.jwt_enc_key,
            &subject,
            &role,
            scopes,
            self.ctx.config.ethereum_config.chain_id,
        )?;

        let refresh_token = auth::utils::generate_token("refresh");
        let refresh_hash = auth::utils::hash_refresh_token(&refresh_token);
        let now = Utc::now();
        let expires_at = now + Duration::seconds(auth_cfg.refresh_ttl_secs);

        repo::insert_refresh_token(
            &self.ctx.persist,
            &refresh_hash,
            &subject,
            now.naive_utc(),
            expires_at.naive_utc(),
        )
        .await?;

        Ok(AuthVerifyResponse {
            access_token,
            refresh_token,
            expires_in: auth_cfg.access_ttl_secs,
        })
    }

    pub async fn refresh_auth(
        &self,
        req: AuthRefreshRequest,
    ) -> ServiceResult<AuthRefreshResponse> {
        let auth_cfg = &self.ctx.config.auth;
        let token_hash = auth::utils::hash_refresh_token(&req.refresh_token);
        let refresh_token = auth::utils::generate_token("refresh");
        let refresh_hash = auth::utils::hash_refresh_token(&refresh_token);
        let now = Utc::now();
        let expires_at = now + Duration::seconds(auth_cfg.refresh_ttl_secs);

        let address = repo::rotate_refresh_token(
            &self.ctx.persist,
            &token_hash,
            &refresh_hash,
            now.naive_utc(),
            expires_at.naive_utc(),
        )
        .await?;

        let (role, scopes) = self.load_wallet_claims(&address).await?;
        let access_token = auth::jwt::issue_access_token(
            auth_cfg,
            &self.ctx.config.secrets.jwt_enc_key,
            &address,
            &role,
            scopes,
            self.ctx.config.ethereum_config.chain_id,
        )?;

        Ok(AuthRefreshResponse {
            access_token,
            refresh_token,
            expires_in: auth_cfg.access_ttl_secs,
        })
    }

    pub async fn logout_auth(&self, req: AuthLogoutRequest) -> ServiceResult<AuthLogoutResponse> {
        let token_hash = auth::utils::hash_refresh_token(&req.refresh_token);
        let revoked = repo::revoke_refresh_token(&self.ctx.persist, &token_hash, None).await?;
        Ok(AuthLogoutResponse { revoked })
    }

    /// Suspend or reinstate a user. A suspended user is refused at guarantee issuance.
    pub async fn set_user_suspension(
        &self,
        user_address: String,
        suspended: bool,
    ) -> ServiceResult<UserSuspensionStatus> {
        let updated =
            repo::update_user_suspension(&self.ctx.persist, &user_address, suspended).await?;
        Ok(mapper::user_model_to_suspension_status(updated))
    }
}
