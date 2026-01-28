use crate::auth;
use crate::auth::constants::DEFAULT_SCOPES;
use crate::auth::jwt::AccessTokenClaims;
use crate::error::{ServiceError, ServiceResult};
use crate::persist::repo;
use crate::service::CoreService;
use chrono::{Duration, Utc};
use rpc::{
    AuthLogoutRequest, AuthLogoutResponse, AuthNonceRequest, AuthNonceResponse, AuthRefreshRequest,
    AuthRefreshResponse, AuthVerifyRequest, AuthVerifyResponse, SiweTemplate,
};

impl CoreService {
    fn build_siwe_context(&self) -> (String, String, String) {
        let auth_cfg = &self.inner.config.auth;
        let host = self.inner.config.server_config.host.trim();
        let port = self.inner.config.server_config.port.trim();
        let domain = auth_cfg
            .siwe_domain
            .as_deref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
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
            &self.inner.config.auth,
            self.inner.config.ethereum_config.chain_id,
            token,
        )
    }

    async fn load_wallet_claims(&self, address: &str) -> ServiceResult<(String, Vec<String>)> {
        let row = repo::get_wallet_role(&self.inner.persist_ctx, address).await?;
        match row {
            Some(model) => {
                auth::utils::validate_wallet_status(&model.status)?;
                let scopes = auth::utils::parse_wallet_scopes(address, model.scopes)?;
                Ok((model.role, scopes))
            }
            None => Ok((
                "user".to_string(),
                DEFAULT_SCOPES.map(|s| s.to_string()).to_vec(),
            )),
        }
    }

    pub async fn create_auth_nonce(
        &self,
        req: AuthNonceRequest,
    ) -> ServiceResult<AuthNonceResponse> {
        let auth_cfg = &self.inner.config.auth;
        let address = auth::utils::parse_wallet_address(&req.address)?.to_string();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(auth_cfg.nonce_ttl_secs);
        let nonce = repo::common::new_uuid();

        repo::insert_auth_nonce(
            &self.inner.persist_ctx,
            &address,
            &nonce,
            expires_at.naive_utc(),
        )
        .await?;

        let (domain, uri, statement) = self.build_siwe_context();

        Ok(AuthNonceResponse {
            nonce: nonce.clone(),
            siwe: SiweTemplate {
                domain,
                uri,
                chain_id: self.inner.config.ethereum_config.chain_id,
                statement,
                expiration: expires_at.to_rfc3339(),
                issued_at: now.to_rfc3339(),
            },
        })
    }

    pub async fn verify_auth(&self, req: AuthVerifyRequest) -> ServiceResult<AuthVerifyResponse> {
        let auth_cfg = &self.inner.config.auth;
        let parsed = auth::siwe::parse_siwe_message(&req.message)?;
        let expected_address = auth::utils::parse_wallet_address(&req.address)?;

        if parsed.address != expected_address {
            return Err(ServiceError::Unauthorized("address mismatch".into()));
        }

        let address = expected_address.to_string();

        if parsed.version.trim() != "1" {
            return Err(ServiceError::Unauthorized("invalid siwe version".into()));
        }

        if parsed.chain_id != self.inner.config.ethereum_config.chain_id {
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

        auth::utils::parse_rfc3339_date("issued_at", &parsed.issued_at)?;

        if let Some(expiration) = parsed.expiration_time.as_deref()
            && auth::utils::parse_rfc3339_date("expiration", expiration)? < Utc::now()
        {
            return Err(ServiceError::Unauthorized("message expired".into()));
        }

        if let Some(not_before) = parsed.not_before.as_deref()
            && auth::utils::parse_rfc3339_date("not_before", not_before)? > Utc::now()
        {
            return Err(ServiceError::Unauthorized("message not valid yet".into()));
        }

        let nonce_row =
            repo::get_auth_nonce(&self.inner.persist_ctx, &address, &parsed.nonce).await?;
        let nonce_row = nonce_row
            .ok_or_else(|| ServiceError::Unauthorized("nonce not found or expired".into()))?;
        if nonce_row.used_at.is_some() || nonce_row.expires_at < Utc::now().naive_utc() {
            return Err(ServiceError::Unauthorized("nonce not valid".into()));
        }

        auth::siwe::verify_siwe_message(
            &self.inner.read_provider,
            &address,
            &req.message,
            &req.signature,
        )
        .await?;

        if !repo::mark_auth_nonce_used(&self.inner.persist_ctx, &address, &parsed.nonce).await? {
            return Err(ServiceError::Unauthorized("nonce already used".into()));
        }

        let subject = address;
        let (role, scopes) = self.load_wallet_claims(&subject).await?;
        let access_token = auth::jwt::issue_access_token(
            auth_cfg,
            &subject,
            &role,
            scopes,
            self.inner.config.ethereum_config.chain_id,
        )?;

        let refresh_token = auth::utils::generate_token("refresh");
        let refresh_hash = auth::utils::hash_refresh_token(&refresh_token);
        let now = Utc::now();
        let expires_at = now + Duration::seconds(auth_cfg.refresh_ttl_secs);

        repo::insert_refresh_token(
            &self.inner.persist_ctx,
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
        let auth_cfg = &self.inner.config.auth;
        let token_hash = auth::utils::hash_refresh_token(&req.refresh_token);
        let refresh_token = auth::utils::generate_token("refresh");
        let refresh_hash = auth::utils::hash_refresh_token(&refresh_token);
        let now = Utc::now();
        let expires_at = now + Duration::seconds(auth_cfg.refresh_ttl_secs);

        let address = repo::rotate_refresh_token(
            &self.inner.persist_ctx,
            &token_hash,
            &refresh_hash,
            now.naive_utc(),
            expires_at.naive_utc(),
        )
        .await?;

        let (role, scopes) = self.load_wallet_claims(&address).await?;
        let access_token = auth::jwt::issue_access_token(
            auth_cfg,
            &address,
            &role,
            scopes,
            self.inner.config.ethereum_config.chain_id,
        )?;

        Ok(AuthRefreshResponse {
            access_token,
            refresh_token,
            expires_in: auth_cfg.access_ttl_secs,
        })
    }

    pub async fn logout_auth(&self, req: AuthLogoutRequest) -> ServiceResult<AuthLogoutResponse> {
        let token_hash = auth::utils::hash_refresh_token(&req.refresh_token);
        let revoked =
            repo::revoke_refresh_token(&self.inner.persist_ctx, &token_hash, None).await?;
        Ok(AuthLogoutResponse { revoked })
    }
}
