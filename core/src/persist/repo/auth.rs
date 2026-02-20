use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use chrono::NaiveDateTime;
use entities::{auth_nonce, auth_refresh_token, wallet_role};
use metrics_4mica::measure;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};

use super::common::{now, parse_address};
use crate::metrics::misc::record_db_time;

#[measure(record_db_time)]
pub async fn insert_auth_nonce(
    ctx: &PersistCtx,
    address: &str,
    nonce: &str,
    expires_at: NaiveDateTime,
) -> Result<auth_nonce::Model, PersistDbError> {
    let address = parse_address(address)?;
    let model = auth_nonce::ActiveModel {
        address: Set(address.into_inner()),
        nonce: Set(nonce.to_string()),
        expires_at: Set(expires_at),
        used_at: Set(None),
    };

    auth_nonce::Entity::insert(model)
        .exec_with_returning(ctx.db.as_ref())
        .await
        .map_err(PersistDbError::from)
}

#[measure(record_db_time)]
pub async fn get_auth_nonce(
    ctx: &PersistCtx,
    address: &str,
    nonce: &str,
) -> Result<Option<auth_nonce::Model>, PersistDbError> {
    let address = parse_address(address)?;
    let row = auth_nonce::Entity::find()
        .filter(auth_nonce::Column::Address.eq(address.as_str()))
        .filter(auth_nonce::Column::Nonce.eq(nonce))
        .one(ctx.db.as_ref())
        .await?;

    Ok(row)
}

#[measure(record_db_time)]
pub async fn mark_auth_nonce_used(
    ctx: &PersistCtx,
    address: &str,
    nonce: &str,
) -> Result<bool, PersistDbError> {
    let address = parse_address(address)?;
    let res = auth_nonce::Entity::update_many()
        .filter(auth_nonce::Column::Address.eq(address.as_str()))
        .filter(auth_nonce::Column::Nonce.eq(nonce))
        .filter(auth_nonce::Column::UsedAt.is_null())
        .col_expr(auth_nonce::Column::UsedAt, Expr::value(now()))
        .exec(ctx.db.as_ref())
        .await?;

    Ok(res.rows_affected > 0)
}

#[measure(record_db_time)]
pub async fn insert_refresh_token(
    ctx: &PersistCtx,
    token_hash: &str,
    address: &str,
    issued_at: NaiveDateTime,
    expires_at: NaiveDateTime,
) -> Result<auth_refresh_token::Model, PersistDbError> {
    let address = parse_address(address)?;
    let model = auth_refresh_token::ActiveModel {
        token_hash: Set(token_hash.to_string()),
        address: Set(address.into_inner()),
        issued_at: Set(issued_at),
        expires_at: Set(expires_at),
        revoked_at: Set(None),
        replaced_by: Set(None),
    };

    auth_refresh_token::Entity::insert(model)
        .exec_with_returning(ctx.db.as_ref())
        .await
        .map_err(PersistDbError::from)
}

#[measure(record_db_time)]
pub async fn get_refresh_token(
    ctx: &PersistCtx,
    token_hash: &str,
) -> Result<Option<auth_refresh_token::Model>, PersistDbError> {
    let row = auth_refresh_token::Entity::find_by_id(token_hash)
        .one(ctx.db.as_ref())
        .await?;
    Ok(row)
}

#[measure(record_db_time)]
pub async fn revoke_refresh_token(
    ctx: &PersistCtx,
    token_hash: &str,
    replaced_by: Option<&str>,
) -> Result<bool, PersistDbError> {
    let res = auth_refresh_token::Entity::update_many()
        .filter(auth_refresh_token::Column::TokenHash.eq(token_hash))
        .filter(auth_refresh_token::Column::RevokedAt.is_null())
        .col_expr(auth_refresh_token::Column::RevokedAt, Expr::value(now()))
        .col_expr(
            auth_refresh_token::Column::ReplacedBy,
            Expr::value(replaced_by.map(|value| value.to_string())),
        )
        .exec(ctx.db.as_ref())
        .await?;

    Ok(res.rows_affected > 0)
}

#[measure(record_db_time)]
pub async fn rotate_refresh_token(
    ctx: &PersistCtx,
    token_hash: &str,
    new_token_hash: &str,
    issued_at: NaiveDateTime,
    expires_at: NaiveDateTime,
) -> Result<String, PersistDbError> {
    let token_hash = token_hash.to_string();
    let new_token_hash = new_token_hash.to_string();

    ctx.db
        .transaction(|txn| {
            let token_hash = token_hash.clone();
            let new_token_hash = new_token_hash.clone();
            Box::pin(async move {
                let row = auth_refresh_token::Entity::find_by_id(&token_hash)
                    .one(txn)
                    .await?
                    .ok_or_else(|| {
                        PersistDbError::AuthTokenInvalid("invalid refresh token".into())
                    })?;

                let now = now();
                if row.revoked_at.is_some() || row.expires_at < now {
                    return Err(PersistDbError::AuthTokenInvalid(
                        "refresh token expired".into(),
                    ));
                }

                let model = auth_refresh_token::ActiveModel {
                    token_hash: Set(new_token_hash.clone()),
                    address: Set(row.address.clone()),
                    issued_at: Set(issued_at),
                    expires_at: Set(expires_at),
                    revoked_at: Set(None),
                    replaced_by: Set(None),
                };

                auth_refresh_token::Entity::insert(model)
                    .exec_without_returning(txn)
                    .await?;

                let res = auth_refresh_token::Entity::update_many()
                    .filter(auth_refresh_token::Column::TokenHash.eq(&token_hash))
                    .filter(auth_refresh_token::Column::RevokedAt.is_null())
                    .col_expr(auth_refresh_token::Column::RevokedAt, Expr::value(now))
                    .col_expr(
                        auth_refresh_token::Column::ReplacedBy,
                        Expr::value(new_token_hash),
                    )
                    .exec(txn)
                    .await?;

                if res.rows_affected == 0 {
                    return Err(PersistDbError::AuthTokenInvalid(
                        "refresh token already used".into(),
                    ));
                }

                Ok(row.address)
            })
        })
        .await
        .map_err(PersistDbError::from)
}

#[measure(record_db_time)]
pub async fn upsert_wallet_role(
    ctx: &PersistCtx,
    address: &str,
    role: &str,
    scopes: &[String],
    status: &str,
) -> Result<wallet_role::Model, PersistDbError> {
    let address = parse_address(address)?;
    let scopes_value = serde_json::to_value(scopes).map_err(|e| {
        PersistDbError::InvariantViolation(format!("invalid wallet role scopes: {e}"))
    })?;

    let model = wallet_role::ActiveModel {
        address: Set(address.into_inner()),
        role: Set(role.to_string()),
        scopes: Set(scopes_value),
        status: Set(status.to_string()),
    };

    wallet_role::Entity::insert(model)
        .on_conflict(
            OnConflict::column(wallet_role::Column::Address)
                .update_columns([
                    wallet_role::Column::Role,
                    wallet_role::Column::Scopes,
                    wallet_role::Column::Status,
                ])
                .to_owned(),
        )
        .exec_with_returning(ctx.db.as_ref())
        .await
        .map_err(PersistDbError::from)
}

#[measure(record_db_time)]
pub async fn get_wallet_role(
    ctx: &PersistCtx,
    address: &str,
) -> Result<Option<wallet_role::Model>, PersistDbError> {
    let address = parse_address(address)?;
    let row = wallet_role::Entity::find_by_id(address.as_str())
        .one(ctx.db.as_ref())
        .await?;
    Ok(row)
}
