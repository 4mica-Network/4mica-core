use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use entities::admin_api_key;
use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, QueryOrder, Set};
use uuid::Uuid;

use super::common::now;

pub async fn insert_admin_api_key(
    ctx: &PersistCtx,
    id: Uuid,
    name: &str,
    key_hash: &str,
    scopes: &[String],
) -> Result<admin_api_key::Model, PersistDbError> {
    let scopes_value = serde_json::to_value(scopes).map_err(|e| {
        PersistDbError::InvariantViolation(format!("invalid admin api key scopes: {e}"))
    })?;

    let model = admin_api_key::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        key_hash: Set(key_hash.to_owned()),
        scopes: Set(scopes_value),
        created_at: Set(now()),
        revoked_at: Set(None),
    };

    admin_api_key::Entity::insert(model)
        .exec_with_returning(ctx.db.as_ref())
        .await
        .map_err(PersistDbError::from)
}

pub async fn list_admin_api_keys(
    ctx: &PersistCtx,
) -> Result<Vec<admin_api_key::Model>, PersistDbError> {
    admin_api_key::Entity::find()
        .order_by_desc(admin_api_key::Column::CreatedAt)
        .all(ctx.db.as_ref())
        .await
        .map_err(PersistDbError::from)
}

pub async fn revoke_admin_api_key(
    ctx: &PersistCtx,
    id: Uuid,
) -> Result<Option<admin_api_key::Model>, PersistDbError> {
    let Some(model) = admin_api_key::Entity::find_by_id(id)
        .one(ctx.db.as_ref())
        .await?
    else {
        return Ok(None);
    };

    if model.revoked_at.is_some() {
        return Ok(Some(model));
    }

    let mut active = model.into_active_model();
    active.revoked_at = Set(Some(now()));
    let updated = active.update(ctx.db.as_ref()).await?;

    Ok(Some(updated))
}

pub async fn get_admin_api_key(
    ctx: &PersistCtx,
    id: Uuid,
) -> Result<Option<admin_api_key::Model>, PersistDbError> {
    let model = admin_api_key::Entity::find_by_id(id)
        .one(ctx.db.as_ref())
        .await?;
    Ok(model)
}
