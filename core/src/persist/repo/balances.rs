use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use alloy::primitives::U256;
use entities::user_asset_balance;
use metrics_4mica::measure;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};

use super::common::{now, parse_address};
use crate::metrics::record::record_db_time;

#[measure(record_db_time)]
pub async fn get_user_balance_on<C: ConnectionTrait>(
    conn: &C,
    user_address: &str,
    asset_address: &str,
) -> Result<user_asset_balance::Model, PersistDbError> {
    let user_address = parse_address(user_address)?;
    let asset_address = parse_address(asset_address)?;
    let user_str = user_address.as_str().to_owned();
    let asset_str = asset_address.as_str().to_owned();

    let balance = user_asset_balance::Entity::find()
        .filter(user_asset_balance::Column::UserAddress.eq(&user_str))
        .filter(user_asset_balance::Column::AssetAddress.eq(&asset_str))
        .one(conn)
        .await?;

    if let Some(b) = balance {
        return Ok(b);
    }

    let now = now();
    let new_balance = user_asset_balance::ActiveModel {
        user_address: sea_orm::ActiveValue::Set(user_str.clone()),
        asset_address: sea_orm::ActiveValue::Set(asset_str.clone()),
        total: sea_orm::ActiveValue::Set("0".to_string()),
        locked: sea_orm::ActiveValue::Set("0".to_string()),
        version: sea_orm::ActiveValue::Set(0),
        created_at: sea_orm::ActiveValue::Set(now),
        updated_at: sea_orm::ActiveValue::Set(now),
    };

    user_asset_balance::Entity::insert(new_balance.clone())
        .on_conflict(
            OnConflict::columns([
                user_asset_balance::Column::UserAddress,
                user_asset_balance::Column::AssetAddress,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(conn)
        .await
        .map_err(|err| {
            if super::common::is_foreign_key_violation(&err) {
                PersistDbError::UserNotFound(user_str.clone())
            } else {
                err.into()
            }
        })?;

    user_asset_balance::Entity::find()
        .filter(user_asset_balance::Column::UserAddress.eq(new_balance.user_address.unwrap()))
        .filter(user_asset_balance::Column::AssetAddress.eq(new_balance.asset_address.unwrap()))
        .one(conn)
        .await?
        .ok_or_else(|| {
            PersistDbError::DatabaseFailure(sea_orm::DbErr::Custom(
                "Failed to create or fetch balance".to_string(),
            ))
        })
}

#[measure(record_db_time)]
pub async fn update_user_balance_and_version_on<C: ConnectionTrait>(
    conn: &C,
    user_address: &str,
    asset_address: &str,
    current_version: i32,
    new_total: U256,
    new_locked: U256,
) -> Result<(), PersistDbError> {
    let user_address = parse_address(user_address)?;
    let asset_address = parse_address(asset_address)?;

    let res = user_asset_balance::Entity::update_many()
        .filter(user_asset_balance::Column::UserAddress.eq(user_address.as_str()))
        .filter(user_asset_balance::Column::AssetAddress.eq(asset_address.as_str()))
        .filter(user_asset_balance::Column::Version.eq(current_version))
        .col_expr(
            user_asset_balance::Column::Version,
            Expr::col(user_asset_balance::Column::Version).add(1),
        )
        .col_expr(
            user_asset_balance::Column::Total,
            Expr::value(new_total.to_string()),
        )
        .col_expr(
            user_asset_balance::Column::Locked,
            Expr::value(new_locked.to_string()),
        )
        .col_expr(user_asset_balance::Column::UpdatedAt, Expr::value(now()))
        .exec(conn)
        .await?;

    match res.rows_affected {
        1 => Ok(()),
        0 => Err(PersistDbError::UserBalanceLockConflict {
            user: user_address.into_inner(),
            asset_address: asset_address.into_inner(),
            expected_version: current_version,
        }),
        n => Err(PersistDbError::InvariantViolation(format!(
            "update_user_balance_and_version_on updated {} rows for address {}",
            n,
            user_address.as_str()
        ))),
    }
}

#[measure(record_db_time)]
pub async fn get_user_asset_balance(
    ctx: &PersistCtx,
    user_address: &str,
    asset_address: &str,
) -> Result<Option<user_asset_balance::Model>, PersistDbError> {
    let user_address = parse_address(user_address)?;
    let asset_address = parse_address(asset_address)?;

    let row = user_asset_balance::Entity::find()
        .filter(user_asset_balance::Column::UserAddress.eq(user_address.as_str()))
        .filter(user_asset_balance::Column::AssetAddress.eq(asset_address.as_str()))
        .one(ctx.db.as_ref())
        .await?;
    Ok(row)
}
