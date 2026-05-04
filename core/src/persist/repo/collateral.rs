use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use alloy::primitives::U256;
use entities::collateral_event;
use entities::sea_orm_active_enums::CollateralEventType;
use log::info;
use metrics_4mica::measure;
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use std::str::FromStr;

use super::balances::{get_user_balance_on, update_user_balance_and_version_on};
use super::common::{new_uuid, now, parse_address};
use super::users::ensure_user_exists_on;
use crate::ethereum::event_data::EventMeta;
use crate::metrics::misc::record_db_time;

/// Deposit: increment collateral and record a CollateralEvent::Deposit for auditability.
#[measure(record_db_time)]
pub async fn deposit(
    ctx: &PersistCtx,
    user_address: String,
    asset_address: String,
    amount: U256,
) -> Result<(), PersistDbError> {
    deposit_with_event(ctx, user_address, asset_address, amount, None).await
}

#[measure(record_db_time)]
pub async fn deposit_with_event(
    ctx: &PersistCtx,
    user_address: String,
    asset_address: String,
    amount: U256,
    event: Option<&EventMeta>,
) -> Result<(), PersistDbError> {
    let event = event.cloned();
    let now = now();
    let user_address = parse_address(&user_address)?.into_inner();
    let asset_address = parse_address(&asset_address)?.into_inner();
    let user_for_log = user_address.clone();
    let asset_for_log = asset_address.clone();
    info!("persist.deposit start user={user_for_log} asset={asset_for_log} amount={amount}");

    ctx.db
        .transaction(|txn| {
            let user_address = user_address.clone();
            let asset_address = asset_address.clone();
            Box::pin(async move {
                ensure_user_exists_on(txn, &user_address).await?;

                let asset_balance = get_user_balance_on(txn, &user_address, &asset_address).await?;

                let total = U256::from_str(&asset_balance.total)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let new_total = total.checked_add(amount).ok_or_else(|| {
                    PersistDbError::DatabaseFailure(sea_orm::DbErr::Custom("overflow".to_string()))
                })?;

                let locked = U256::from_str(&asset_balance.locked)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                update_user_balance_and_version_on(
                    txn,
                    &user_address,
                    &asset_address,
                    asset_balance.version,
                    new_total,
                    locked,
                )
                .await?;

                if amount > U256::ZERO {
                    let ev = collateral_event::ActiveModel {
                        id: Set(new_uuid()),
                        user_address: Set(user_address),
                        asset_address: Set(asset_address),
                        amount: Set(amount.to_string()),
                        event_type: Set(CollateralEventType::Deposit),
                        req_id: Set(None),
                        tx_id: Set(None),
                        event_chain_id: Set(event.as_ref().map(|e| e.chain_id as i64)),
                        event_block_hash: Set(event.as_ref().map(|e| e.block_hash.clone())),
                        event_tx_hash: Set(event.as_ref().map(|e| e.tx_hash.clone())),
                        event_log_index: Set(event.as_ref().map(|e| e.log_index as i64)),
                        created_at: Set(now),
                    };
                    collateral_event::Entity::insert(ev).exec(txn).await?;
                }

                Ok::<_, PersistDbError>(())
            })
        })
        .await?;

    info!("persist.deposit done user={}", user_for_log);
    Ok(())
}

#[measure(record_db_time)]
pub async fn revert_deposit(
    ctx: &PersistCtx,
    user_address: String,
    asset_address: String,
    amount: U256,
    event: EventMeta,
) -> Result<(), PersistDbError> {
    parse_address(&user_address)?;
    parse_address(&asset_address)?;

    ctx.db
        .transaction(|txn| {
            let user_address = user_address.clone();
            let asset_address = asset_address.clone();
            Box::pin(async move {
                let asset_balance = get_user_balance_on(txn, &user_address, &asset_address).await?;
                let total = U256::from_str(&asset_balance.total)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let locked = U256::from_str(&asset_balance.locked)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let new_total = total.checked_sub(amount).ok_or_else(|| {
                    PersistDbError::InvariantViolation("revert deposit underflow".into())
                })?;

                update_user_balance_and_version_on(
                    txn,
                    &user_address,
                    &asset_address,
                    asset_balance.version,
                    new_total,
                    locked,
                )
                .await?;

                collateral_event::Entity::delete_many()
                    .filter(collateral_event::Column::EventChainId.eq(event.chain_id as i64))
                    .filter(collateral_event::Column::EventBlockHash.eq(event.block_hash.clone()))
                    .filter(collateral_event::Column::EventTxHash.eq(event.tx_hash.clone()))
                    .filter(collateral_event::Column::EventLogIndex.eq(event.log_index as i64))
                    .exec(txn)
                    .await?;

                Ok::<_, PersistDbError>(())
            })
        })
        .await?;

    Ok(())
}
