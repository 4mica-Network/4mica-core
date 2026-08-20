use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use crate::persist::canonical::Canonical;
use alloy::primitives::Address;
use chrono::Utc;
use entities::user;
use metrics_4mica::measure;
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, IntoActiveModel, Set};

use super::common::now;
use crate::metrics::misc::record_db_time;

#[measure(record_db_time)]
pub async fn get_user(
    ctx: &PersistCtx,
    user_address: Address,
) -> Result<user::Model, PersistDbError> {
    get_user_on(ctx.db.as_ref(), user_address).await
}

#[measure(record_db_time)]
pub async fn get_user_on<C: ConnectionTrait>(
    conn: &C,
    user_address: Address,
) -> Result<user::Model, PersistDbError> {
    user::Entity::find_by_id(user_address.canonical())
        .one(conn)
        .await?
        .ok_or_else(|| PersistDbError::UserNotFound(user_address.canonical()))
}

/// Errors if the user is unknown or suspended.
#[measure(record_db_time)]
pub async fn ensure_user_is_active_on<C: ConnectionTrait>(
    conn: &C,
    user_address: Address,
) -> Result<(), PersistDbError> {
    let user = get_user_on(conn, user_address).await?;
    if user.is_suspended {
        Err(PersistDbError::UserSuspended(user_address.canonical()))
    } else {
        Ok(())
    }
}

/// Errors only if the user is known *and* suspended; an unknown user is fine.
#[measure(record_db_time)]
pub async fn ensure_user_is_active_if_exists_on<C: ConnectionTrait>(
    conn: &C,
    user_address: Address,
) -> Result<(), PersistDbError> {
    let user = match get_user_on(conn, user_address).await {
        Ok(user) => user,
        Err(PersistDbError::UserNotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
    };

    if user.is_suspended {
        Err(PersistDbError::UserSuspended(user_address.canonical()))
    } else {
        Ok(())
    }
}

#[measure(record_db_time)]
pub async fn update_user_suspension(
    ctx: &PersistCtx,
    user_address: Address,
    suspended: bool,
) -> Result<user::Model, PersistDbError> {
    // To make sure the user will be suspended even if they don't exist yet
    ensure_user_exists_on(ctx.db.as_ref(), user_address).await?;

    let mut model = get_user(ctx, user_address).await?.into_active_model();
    let current_version = model
        .version
        .take()
        .expect("version must be set after get_user");
    model.is_suspended = Set(suspended);
    model.version = Set(current_version + 1);
    model.updated_at = Set(now());

    model
        .update(ctx.db.as_ref())
        .await
        .map_err(PersistDbError::from)
}

#[measure(record_db_time)]
pub async fn ensure_user_exists_on<C: ConnectionTrait>(
    conn: &C,
    addr: Address,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();
    let insert_user = user::ActiveModel {
        address: Set(addr.canonical()),
        version: Set(0),
        is_suspended: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };

    user::Entity::insert(insert_user)
        .on_conflict(
            sea_orm::sea_query::OnConflict::column(user::Column::Address)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await?;

    Ok(())
}
