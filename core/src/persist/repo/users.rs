use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use chrono::Utc;
use entities::user;
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, IntoActiveModel, Set};

use super::common::{now, parse_address};

pub async fn get_user<S: AsRef<str> + Send + Sync>(
    ctx: &PersistCtx,
    user_address: S,
) -> Result<user::Model, PersistDbError> {
    let addr = parse_address(user_address)?;
    user::Entity::find_by_id(addr.as_str())
        .one(ctx.db.as_ref())
        .await?
        .ok_or_else(|| PersistDbError::UserNotFound(addr.into_inner()))
}

pub async fn ensure_user_is_active<S: AsRef<str> + Send + Sync>(
    ctx: &PersistCtx,
    user_address: S,
) -> Result<(), PersistDbError> {
    let addr = parse_address(&user_address)?;
    let user = get_user(ctx, addr.as_str()).await?;
    if user.is_suspended {
        Err(PersistDbError::UserSuspended(addr.into_inner()))
    } else {
        Ok(())
    }
}

pub async fn ensure_user_is_active_if_exists<S: AsRef<str> + Send + Sync>(
    ctx: &PersistCtx,
    user_address: S,
) -> Result<(), PersistDbError> {
    let addr = parse_address(&user_address)?;
    let user = match get_user(ctx, addr.as_str()).await {
        Ok(user) => user,
        Err(PersistDbError::UserNotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
    };

    if user.is_suspended {
        Err(PersistDbError::UserSuspended(addr.into_inner()))
    } else {
        Ok(())
    }
}

pub async fn update_user_suspension<S: AsRef<str> + Send + Sync>(
    ctx: &PersistCtx,
    user_address: S,
    suspended: bool,
) -> Result<user::Model, PersistDbError> {
    let addr = parse_address(&user_address)?;

    // To make sure the user will be suspended even if they don't exist yet
    ensure_user_exists_on(ctx.db.as_ref(), addr.as_str()).await?;

    let mut model = get_user(ctx, addr.as_str()).await?.into_active_model();
    model.is_suspended = Set(suspended);
    model.updated_at = Set(now());

    model
        .update(ctx.db.as_ref())
        .await
        .map_err(PersistDbError::from)
}

pub async fn ensure_user_exists_on<C: ConnectionTrait>(
    conn: &C,
    addr: &str,
) -> Result<(), PersistDbError> {
    let addr = parse_address(addr)?;
    let now = Utc::now().naive_utc();
    let insert_user = user::ActiveModel {
        address: Set(addr.into_inner()),
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
