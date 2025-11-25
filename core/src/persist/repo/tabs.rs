use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use crate::util::u256_to_string;
use chrono::NaiveDateTime;
use entities::sea_orm_active_enums::{SettlementStatus, TabStatus};
use entities::tabs;
use log::info;
use sea_orm::{ColumnTrait, Condition, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set};

use super::common::{now, parse_address};
use super::users::ensure_user_is_active;

pub async fn create_pending_tab(
    ctx: &PersistCtx,
    tab_id: alloy::primitives::U256,
    user_address: &str,
    server_address: &str,
    asset_address: &str,
    start_ts: NaiveDateTime,
    ttl: i64,
) -> Result<(), PersistDbError> {
    let user_address = parse_address(user_address)?;
    let server_address = parse_address(server_address)?;
    let asset_address = parse_address(asset_address)?;

    ensure_user_is_active(ctx, user_address.as_str()).await?;

    let new_tab = tabs::ActiveModel {
        id: Set(u256_to_string(tab_id)),
        user_address: Set(user_address.into_inner()),
        server_address: Set(server_address.into_inner()),
        asset_address: Set(asset_address.into_inner()),
        start_ts: Set(start_ts),
        ttl: Set(ttl),
        status: Set(TabStatus::Pending),
        settlement_status: Set(SettlementStatus::Pending),
        created_at: Set(now()),
        updated_at: Set(now()),
    };
    info!("Creating new pending tab {}", new_tab.id.as_ref());

    tabs::Entity::insert(new_tab).exec(ctx.db.as_ref()).await?;
    Ok(())
}

pub async fn open_tab(
    ctx: &PersistCtx,
    tab_id: alloy::primitives::U256,
    start_ts: NaiveDateTime,
) -> Result<(), PersistDbError> {
    tabs::Entity::update_many()
        .filter(tabs::Column::Id.eq(u256_to_string(tab_id)))
        .filter(tabs::Column::Status.eq(TabStatus::Pending))
        .set(tabs::ActiveModel {
            status: Set(TabStatus::Open),
            start_ts: Set(start_ts),
            updated_at: Set(now()),
            ..Default::default()
        })
        .exec(ctx.db.as_ref())
        .await?;

    Ok(())
}

pub async fn find_active_tab_by_triplet(
    ctx: &PersistCtx,
    user_address: &str,
    server_address: &str,
    asset_address: &str,
) -> Result<Option<tabs::Model>, PersistDbError> {
    let user_address = parse_address(user_address)?;
    let server_address = parse_address(server_address)?;
    let asset_address = parse_address(asset_address)?;

    let tab = tabs::Entity::find()
        .filter(tabs::Column::UserAddress.eq(user_address.as_str()))
        .filter(tabs::Column::ServerAddress.eq(server_address.as_str()))
        .filter(tabs::Column::AssetAddress.eq(asset_address.as_str()))
        .filter(tabs::Column::Status.eq(TabStatus::Pending))
        .filter(
            Condition::all()
                .add(tabs::Column::SettlementStatus.ne(SettlementStatus::Settled))
                .add(tabs::Column::SettlementStatus.ne(SettlementStatus::Remunerated)),
        )
        .order_by_desc(tabs::Column::UpdatedAt)
        .one(ctx.db.as_ref())
        .await
        .map_err(PersistDbError::DatabaseFailure)?;

    Ok(tab)
}

pub async fn get_tab_by_id(
    ctx: &PersistCtx,
    tab_id: alloy::primitives::U256,
) -> Result<Option<tabs::Model>, PersistDbError> {
    let res = tabs::Entity::find_by_id(u256_to_string(tab_id))
        .one(ctx.db.as_ref())
        .await?;
    Ok(res)
}

pub async fn get_tabs_for_recipient(
    ctx: &PersistCtx,
    recipient_address: &str,
    settlement_statuses: Option<&[SettlementStatus]>,
) -> Result<Vec<tabs::Model>, PersistDbError> {
    let recipient_address = parse_address(recipient_address)?;

    let mut condition =
        Condition::all().add(tabs::Column::ServerAddress.eq(recipient_address.as_str()));

    if let Some(statuses) = settlement_statuses
        && !statuses.is_empty()
    {
        let status_list: Vec<SettlementStatus> = statuses.to_vec();
        condition = condition.add(tabs::Column::SettlementStatus.is_in(status_list));
    }

    let rows = tabs::Entity::find()
        .filter(condition)
        .order_by_desc(tabs::Column::UpdatedAt)
        .all(ctx.db.as_ref())
        .await?;

    Ok(rows)
}

pub async fn get_tab_by_id_on<C: ConnectionTrait>(
    conn: &C,
    tab_id: alloy::primitives::U256,
) -> Result<tabs::Model, PersistDbError> {
    let tab_id = u256_to_string(tab_id);
    tabs::Entity::find_by_id(&tab_id)
        .one(conn)
        .await?
        .ok_or_else(|| PersistDbError::TabNotFound(tab_id))
}

pub async fn get_tab_ttl_seconds(
    ctx: &PersistCtx,
    tab_id: alloy::primitives::U256,
) -> Result<u64, PersistDbError> {
    let tab_id = u256_to_string(tab_id);
    let tab = tabs::Entity::find_by_id(&tab_id)
        .one(ctx.db.as_ref())
        .await?
        .ok_or_else(|| PersistDbError::TabNotFound(tab_id))?;

    Ok(tab.ttl as u64)
}
