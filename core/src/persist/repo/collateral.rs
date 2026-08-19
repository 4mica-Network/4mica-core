use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use crate::persist::canonical::Canonical;
use alloy::primitives::Address;
use alloy::primitives::U256;
use chrono::NaiveDateTime;
use entities::collateral_event;
use entities::sea_orm_active_enums::CollateralEventType;
use metrics_4mica::measure;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{ConnectionTrait, EntityTrait};

use super::balances::{get_user_balance_on, update_user_balance_and_version_on};
use super::common::{new_uuid, now};
use super::users::ensure_user_exists_on;
use crate::ethereum::event_data::EventMeta;
use crate::metrics::misc::record_db_time;

async fn upsert_collateral_event_on<C: ConnectionTrait>(
    conn: &C,
    user_address: Address,
    asset_address: Address,
    amount: U256,
    event_type: CollateralEventType,
    tx_meta: Option<&EventMeta>,
    now: NaiveDateTime,
) -> Result<u64, PersistDbError> {
    let ev = collateral_event::ActiveModel {
        id: Set(new_uuid()),
        user_address: Set(user_address.canonical()),
        asset_address: Set(asset_address.canonical()),
        amount: Set(amount.canonical()),
        event_type: Set(event_type),
        req_id: Set(None),
        tx_id: Set(None),
        event_chain_id: Set(tx_meta.as_ref().map(|e| e.chain_id as i64)),
        event_block_hash: Set(tx_meta.as_ref().map(|e| e.block_hash.clone())),
        event_tx_hash: Set(tx_meta.as_ref().map(|e| e.tx_hash.clone())),
        event_log_index: Set(tx_meta.as_ref().map(|e| e.log_index as i64)),
        created_at: Set(now),
    };

    let insert = collateral_event::Entity::insert(ev);
    let rows_affected = if tx_meta.is_some() {
        insert
            .on_conflict(
                OnConflict::columns([
                    collateral_event::Column::EventChainId,
                    collateral_event::Column::EventBlockHash,
                    collateral_event::Column::EventTxHash,
                    collateral_event::Column::EventLogIndex,
                ])
                .target_and_where(Expr::cust(
                    r#""CollateralEvent"."event_chain_id" IS NOT NULL
                        AND "CollateralEvent"."event_block_hash" IS NOT NULL
                        AND "CollateralEvent"."event_tx_hash" IS NOT NULL
                        AND "CollateralEvent"."event_log_index" IS NOT NULL"#,
                ))
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(conn)
            .await?
    } else {
        insert.exec_without_returning(conn).await?
    };

    Ok(rows_affected)
}

/// Deposit: increment collateral and record a CollateralEvent::Deposit for auditability.
#[measure(record_db_time)]
pub async fn deposit(
    ctx: &PersistCtx,
    user_address: Address,
    asset_address: Address,
    amount: U256,
) -> Result<(), PersistDbError> {
    credit_collateral_with_event_on(
        ctx.db.as_ref(),
        user_address,
        asset_address,
        amount,
        CollateralEventType::Deposit,
        None,
    )
    .await
}

#[measure(record_db_time)]
pub async fn credit_collateral_with_event_on<C: ConnectionTrait>(
    conn: &C,
    user_address: Address,
    asset_address: Address,
    amount: U256,
    event_type: CollateralEventType,
    tx_meta: Option<EventMeta>,
) -> Result<(), PersistDbError> {
    let now = now();
    ensure_user_exists_on(conn, user_address).await?;

    if amount > U256::ZERO {
        let rows_affected = upsert_collateral_event_on(
            conn,
            user_address,
            asset_address,
            amount,
            event_type,
            tx_meta.as_ref(),
            now,
        )
        .await?;

        if tx_meta.is_some() && rows_affected == 0 {
            return Ok::<_, PersistDbError>(());
        }
    }

    let asset_balance = get_user_balance_on(conn, user_address, asset_address).await?;

    let total = asset_balance.total;
    let new_total = total.checked_add(amount).ok_or_else(|| {
        PersistDbError::DatabaseFailure(sea_orm::DbErr::Custom("overflow".to_string()))
    })?;

    let locked = asset_balance.locked;

    update_user_balance_and_version_on(
        conn,
        user_address,
        asset_address,
        asset_balance.version,
        new_total,
        locked,
    )
    .await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn debit_collateral_with_event_on<C: ConnectionTrait>(
    conn: &C,
    user_address: Address,
    asset_address: Address,
    amount: U256,
    event_type: CollateralEventType,
    tx_meta: Option<EventMeta>,
) -> Result<(), PersistDbError> {
    let now = now();
    ensure_user_exists_on(conn, user_address).await?;

    if amount > U256::ZERO {
        let rows_affected = upsert_collateral_event_on(
            conn,
            user_address,
            asset_address,
            amount,
            event_type,
            tx_meta.as_ref(),
            now,
        )
        .await?;

        if tx_meta.is_some() && rows_affected == 0 {
            return Ok::<_, PersistDbError>(());
        }
    }

    let asset_balance = get_user_balance_on(conn, user_address, asset_address).await?;
    let total = asset_balance.total;
    let locked = asset_balance.locked;
    let new_total = total
        .checked_sub(amount)
        .ok_or_else(|| PersistDbError::InvariantViolation("revert deposit underflow".into()))?;

    update_user_balance_and_version_on(
        conn,
        user_address,
        asset_address,
        asset_balance.version,
        new_total,
        locked,
    )
    .await?;

    Ok(())
}
