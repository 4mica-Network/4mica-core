use crate::{
    error::{ServiceError, ServiceResult},
    persist::{mapper, repo},
    service::CoreService,
};
use rand::random;
use rpc::{
    ADMIN_API_KEY_PREFIX, ADMIN_SCOPE_MANAGE_KEYS, ADMIN_SCOPE_SUSPEND_USERS, AdminApiKeyInfo,
    AdminApiKeySecret, CreateAdminApiKeyRequest,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

const VALID_SCOPES: &[&str] = &[ADMIN_SCOPE_MANAGE_KEYS, ADMIN_SCOPE_SUSPEND_USERS];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminApiKeyScope {
    ManageKeys,
    SuspendUsers,
}

impl AdminApiKeyScope {
    pub fn as_str(self) -> &'static str {
        match self {
            AdminApiKeyScope::ManageKeys => ADMIN_SCOPE_MANAGE_KEYS,
            AdminApiKeyScope::SuspendUsers => ADMIN_SCOPE_SUSPEND_USERS,
        }
    }
}

fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

fn generate_secret() -> String {
    let bytes: [u8; 32] = random();
    hex::encode(bytes)
}

fn format_api_key(id: Uuid, secret: &str) -> String {
    format!("{}{}.{}", ADMIN_API_KEY_PREFIX, id.simple(), secret)
}

fn parse_api_key(raw: &str) -> ServiceResult<(Uuid, String)> {
    if !raw.starts_with(ADMIN_API_KEY_PREFIX) {
        return Err(ServiceError::Unauthorized("invalid api key".into()));
    }
    let without_prefix = &raw[ADMIN_API_KEY_PREFIX.len()..];
    let (id_part, secret) = without_prefix
        .split_once('.')
        .ok_or_else(|| ServiceError::Unauthorized("invalid api key".into()))?;
    if secret.is_empty() {
        return Err(ServiceError::Unauthorized("invalid api key".into()));
    }
    let id = Uuid::parse_str(id_part)
        .map_err(|_| ServiceError::Unauthorized("invalid api key".into()))?;
    Ok((id, secret.to_string()))
}

fn canonicalize_scopes(scopes: &[String]) -> ServiceResult<Vec<String>> {
    if scopes.is_empty() {
        return Err(ServiceError::InvalidParams(
            "at least one scope is required".into(),
        ));
    }
    let mut dedup = std::collections::BTreeSet::new();
    for scope in scopes {
        let scope_lower = scope.trim().to_ascii_lowercase();
        if !VALID_SCOPES.contains(&scope_lower.as_str()) {
            return Err(ServiceError::InvalidParams(format!(
                "invalid scope: {scope}"
            )));
        }
        dedup.insert(scope_lower);
    }
    Ok(dedup.into_iter().collect())
}

fn scopes_contains(scopes: &[String], required: &str) -> bool {
    scopes.iter().any(|scope| scope == required)
}

impl CoreService {
    pub async fn create_admin_api_key(
        &self,
        req: CreateAdminApiKeyRequest,
    ) -> ServiceResult<AdminApiKeySecret> {
        if req.name.trim().is_empty() {
            return Err(ServiceError::InvalidParams("name is required".into()));
        }
        let scopes = canonicalize_scopes(&req.scopes)?;
        let id = Uuid::new_v4();
        let secret = generate_secret();
        let api_key = format_api_key(id, &secret);
        let key_hash = hash_secret(&secret);

        let model = repo::insert_admin_api_key(
            &self.inner.persist_ctx,
            id,
            req.name.trim(),
            &key_hash,
            &scopes,
        )
        .await?;
        let info = mapper::admin_api_key_model_to_info(model)?;

        Ok(AdminApiKeySecret {
            id: info.id,
            name: info.name,
            scopes: info.scopes,
            created_at: info.created_at,
            api_key,
        })
    }

    pub async fn list_admin_api_keys(&self) -> ServiceResult<Vec<AdminApiKeyInfo>> {
        let rows = repo::list_admin_api_keys(&self.inner.persist_ctx).await?;
        rows.into_iter()
            .map(mapper::admin_api_key_model_to_info)
            .collect()
    }

    pub async fn revoke_admin_api_key(&self, id: Uuid) -> ServiceResult<AdminApiKeyInfo> {
        let Some(model) = repo::revoke_admin_api_key(&self.inner.persist_ctx, id).await? else {
            return Err(ServiceError::NotFound(format!("api key {id} not found")));
        };
        mapper::admin_api_key_model_to_info(model)
    }

    pub async fn authenticate_admin_api_key(
        &self,
        raw_key: &str,
        scope: AdminApiKeyScope,
    ) -> ServiceResult<()> {
        let (id, secret) = parse_api_key(raw_key)?;
        let Some(model) = repo::get_admin_api_key(&self.inner.persist_ctx, id).await? else {
            return Err(ServiceError::Unauthorized("invalid api key".into()));
        };
        if model.revoked_at.is_some() {
            return Err(ServiceError::Unauthorized("api key revoked".into()));
        }
        let scopes: Vec<String> = serde_json::from_value(model.scopes).map_err(|e| {
            ServiceError::Other(anyhow::anyhow!(
                "invalid scopes for api key {}: {e}",
                model.id
            ))
        })?;
        if !scopes_contains(&scopes, scope.as_str()) {
            return Err(ServiceError::Unauthorized("missing scope".into()));
        }
        let expected_hash = hash_secret(&secret);
        if expected_hash
            .as_bytes()
            .ct_eq(model.key_hash.as_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(ServiceError::Unauthorized("invalid api key".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_scopes_validates_values() {
        let scopes = vec![
            ADMIN_SCOPE_MANAGE_KEYS.to_string(),
            ADMIN_SCOPE_MANAGE_KEYS.to_string(),
            ADMIN_SCOPE_SUSPEND_USERS.to_uppercase(),
        ];
        let result = canonicalize_scopes(&scopes).unwrap();
        assert_eq!(
            result,
            vec![
                ADMIN_SCOPE_MANAGE_KEYS.to_string(),
                ADMIN_SCOPE_SUSPEND_USERS.to_string()
            ]
        );
        let err = canonicalize_scopes(&["bad".into()]).unwrap_err();
        assert!(matches!(err, ServiceError::InvalidParams(_)));
    }

    #[test]
    fn parse_api_key_validates_prefix_and_format() {
        let id = Uuid::new_v4();
        let api_key = format_api_key(id, "secret");
        let (parsed_id, secret) = parse_api_key(&api_key).unwrap();
        assert_eq!(parsed_id, id);
        assert_eq!(secret, "secret");

        assert!(parse_api_key("ak_missing_delim").is_err());
        assert!(parse_api_key("wrongprefix.secret").is_err());
    }
}
