use crate::{
    error::{ServiceError, ServiceResult},
    persist::{mapper, repo},
    service::CoreService,
};
use anyhow::Context;
use rand::random;
use rpc::{
    ADMIN_API_KEY_PREFIX, ADMIN_SCOPE_MANAGE_KEYS, ADMIN_SCOPE_SUSPEND_USERS, AdminApiKeyInfo,
    AdminApiKeySecret, CreateAdminApiKeyRequest,
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, IntoActiveModel};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

mod bootstrap_admin_key {
    pub const NAME: &str = "bootstrap-admin";
    pub const ID_DOMAIN: &str = "4mica:core:bootstrap:id";
    pub const SECRET_DOMAIN: &str = "4mica:core:bootstrap:secret";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminApiKeyScope {
    ManageKeys,
    SuspendUsers,
}

impl AdminApiKeyScope {
    pub const ALL: [&'static str; 2] = [ADMIN_SCOPE_MANAGE_KEYS, ADMIN_SCOPE_SUSPEND_USERS];

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

fn derive_bootstrap_key_material(seed: &str) -> (Uuid, String) {
    let id_input = format!("{}:{seed}", bootstrap_admin_key::ID_DOMAIN);
    let id_hash = Sha256::digest(id_input.as_bytes());
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&id_hash[..16]);
    let id = Uuid::from_bytes(id_bytes);

    let secret_input = format!("{}:{seed}", bootstrap_admin_key::SECRET_DOMAIN);
    let secret_hash = Sha256::digest(secret_input.as_bytes());
    let secret = hex::encode(secret_hash);

    (id, secret)
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
        if !AdminApiKeyScope::ALL.contains(&scope_lower.as_str()) {
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
    pub async fn bootstrap_admin_api_key(&self) -> anyhow::Result<Option<String>> {
        let Some(seed) = self.inner.config.secrets.core_admin_seed_key.clone() else {
            return Ok(None);
        };
        let trimmed = seed.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        let (id, secret) = derive_bootstrap_key_material(trimmed);
        let mut scopes = vec![
            ADMIN_SCOPE_MANAGE_KEYS.to_string(),
            ADMIN_SCOPE_SUSPEND_USERS.to_string(),
        ];
        scopes.sort();
        let scopes_value = serde_json::to_value(&scopes)?;
        let key_hash = hash_secret(&secret);

        let maybe_existing = repo::get_admin_api_key(&self.inner.persist_ctx, id).await?;
        if let Some(model) = maybe_existing {
            let mut needs_update = false;
            let mut active = model.clone().into_active_model();

            if model.name != bootstrap_admin_key::NAME {
                active.name = Set(bootstrap_admin_key::NAME.to_string());
                needs_update = true;
            }

            if model.revoked_at.is_some() {
                active.revoked_at = Set(None);
                needs_update = true;
            }

            let mut stored_scopes: Vec<String> = serde_json::from_value(model.scopes.clone())
                .context("invalid scopes stored for bootstrap admin api key")?;
            stored_scopes.sort();
            if stored_scopes != scopes {
                active.scopes = Set(scopes_value.clone());
                needs_update = true;
            }

            if model.key_hash != key_hash {
                active.key_hash = Set(key_hash.clone());
                needs_update = true;
            }

            if needs_update {
                active.update(self.inner.persist_ctx.db.as_ref()).await?;
            }

            return Ok(Some(format_api_key(id, &secret)));
        }

        repo::insert_admin_api_key(
            &self.inner.persist_ctx,
            id,
            bootstrap_admin_key::NAME,
            &key_hash,
            &scopes,
        )
        .await?;
        Ok(Some(format_api_key(id, &secret)))
    }

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

    #[test]
    fn scope_list_contains_all_variants() {
        assert!(AdminApiKeyScope::ALL.contains(&AdminApiKeyScope::ManageKeys.as_str()));
        assert!(AdminApiKeyScope::ALL.contains(&AdminApiKeyScope::SuspendUsers.as_str()));
        assert_eq!(AdminApiKeyScope::ALL.len(), 2);
    }

    #[test]
    fn bootstrap_constants_are_defined() {
        assert_eq!(bootstrap_admin_key::NAME, "bootstrap-admin");
        assert_eq!(bootstrap_admin_key::ID_DOMAIN, "4mica:core:bootstrap:id");
        assert_eq!(
            bootstrap_admin_key::SECRET_DOMAIN,
            "4mica:core:bootstrap:secret"
        );
    }

    #[test]
    fn bootstrap_key_derivation_is_deterministic() {
        let (id_a, secret_a) = derive_bootstrap_key_material("seed");
        let (id_b, secret_b) = derive_bootstrap_key_material("seed");
        assert_eq!(id_a, id_b);
        assert_eq!(secret_a, secret_b);

        let (_, secret_c) = derive_bootstrap_key_material("another-seed");
        assert_ne!(secret_a, secret_c);
    }
}
