use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use crate::util::u256_to_string;
use alloy::primitives::{Address as AlloyAddress, U256};
use entities::sea_orm_active_enums::{CollateralEventType, SettlementStatus};
use entities::{collateral_event, tabs};
use log::info;
use sea_orm::ActiveValue::Set;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use std::str::FromStr;

use super::balances::{get_user_balance_on, update_user_balance_and_version_on};
use super::common::{new_uuid, now, parse_address};
use super::settlement::transition_settlement;
use super::tabs::get_tab_by_id_on;
use super::users::ensure_user_exists_on;
use crate::ethereum::event_data::EventMeta;

/// Deposit: increment collateral and record a CollateralEvent::Deposit for auditability.
pub async fn deposit(
    ctx: &PersistCtx,
    user_address: String,
    asset_address: String,
    amount: U256,
) -> Result<(), PersistDbError> {
    deposit_with_event(ctx, user_address, asset_address, amount, None).await
}

pub async fn deposit_with_event(
    ctx: &PersistCtx,
    user_address: String,
    asset_address: String,
    amount: U256,
    event: Option<&EventMeta>,
) -> Result<(), PersistDbError> {
    let event = event.cloned();
    let now = now();
    parse_address(&user_address)?;
    parse_address(&asset_address)?;
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
                        tab_id: Set(None),
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

pub async fn unlock_user_collateral(
    ctx: &PersistCtx,
    tab_id: U256,
    asset_address: String,
    amount: U256,
) -> Result<(), PersistDbError> {
    let now = now();
    parse_address(&asset_address)?;

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let tab = get_tab_by_id_on(txn, tab_id).await?;
                let tab_id_str = u256_to_string(tab_id);

                let tab_asset = AlloyAddress::from_str(&tab.asset_address).map_err(|e| {
                    PersistDbError::InvariantViolation(format!(
                        "invalid tab asset address {} for tab {}: {e}",
                        &tab.asset_address, tab_id_str
                    ))
                })?;
                let unlock_asset = AlloyAddress::from_str(&asset_address).map_err(|e| {
                    PersistDbError::InvariantViolation(format!(
                        "invalid unlock asset address {} for tab {}: {e}",
                        &asset_address, tab_id_str
                    ))
                })?;
                if tab_asset != unlock_asset {
                    return Err(PersistDbError::InvariantViolation(format!(
                        "tab asset does not match unlock asset for tab {}",
                        tab_id_str
                    )));
                }

                if tab.settlement_status != SettlementStatus::Pending {
                    return Ok::<_, PersistDbError>(());
                }

                let total_amount = U256::from_str(&tab.total_amount)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let paid_amount = U256::from_str(&tab.paid_amount)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let new_paid = paid_amount.checked_add(amount).ok_or_else(|| {
                    PersistDbError::DatabaseFailure(sea_orm::DbErr::Custom(
                        "paid_amount overflow".to_string(),
                    ))
                })?;

                let asset_balance =
                    get_user_balance_on(txn, &tab.user_address, &asset_address).await?;
                let total = U256::from_str(&asset_balance.total)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let locked = U256::from_str(&asset_balance.locked)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                if amount > locked {
                    return Err(PersistDbError::InvariantViolation(
                        "unlock amount exceeds locked collateral".into(),
                    ));
                }

                let new_locked = locked
                    .checked_sub(amount)
                    .ok_or_else(|| PersistDbError::InvariantViolation("locked underflow".into()))?;

                update_user_balance_and_version_on(
                    txn,
                    &tab.user_address,
                    &asset_address,
                    asset_balance.version,
                    total,
                    new_locked,
                )
                .await?;

                let mut tab_update = tabs::ActiveModel {
                    paid_amount: Set(new_paid.to_string()),
                    updated_at: Set(now),
                    ..Default::default()
                };
                if tab.settlement_status == SettlementStatus::Pending && new_paid >= total_amount {
                    tab_update.settlement_status = Set(SettlementStatus::Settled);
                }
                tabs::Entity::update_many()
                    .filter(tabs::Column::Id.eq(tab_id_str.clone()))
                    .set(tab_update)
                    .exec(txn)
                    .await?;

                let ev = collateral_event::ActiveModel {
                    id: Set(new_uuid()),
                    user_address: Set(tab.user_address.clone()),
                    asset_address: Set(asset_address),
                    amount: Set(amount.to_string()),
                    event_type: Set(CollateralEventType::Unlock),
                    tab_id: Set(Some(tab_id_str)),
                    req_id: Set(None),
                    tx_id: Set(None),
                    event_chain_id: Set(None),
                    event_block_hash: Set(None),
                    event_tx_hash: Set(None),
                    event_log_index: Set(None),
                    created_at: Set(now),
                };
                collateral_event::Entity::insert(ev).exec(txn).await?;

                Ok::<_, PersistDbError>(())
            })
        })
        .await?;

    Ok(())
}

/// Combined settlement + transfer for remunerating a recipient.
pub async fn remunerate_recipient(
    ctx: &PersistCtx,
    tab_id: U256,
    asset_address: String,
    amount: U256,
) -> Result<(), PersistDbError> {
    remunerate_recipient_with_event(ctx, tab_id, asset_address, amount, None).await
}

/// Combined settlement + transfer for remunerating a recipient.
pub async fn remunerate_recipient_with_event(
    ctx: &PersistCtx,
    tab_id: U256,
    asset_address: String,
    amount: U256,
    event: Option<&EventMeta>,
) -> Result<(), PersistDbError> {
    let event = event.cloned();
    let now = now();
    parse_address(&asset_address)?;

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let tab = get_tab_by_id_on(txn, tab_id).await?;
                let tab_id_str = u256_to_string(tab_id);

                let transitioned =
                    transition_settlement(txn, &tab_id_str, SettlementStatus::Remunerated, now)
                        .await?;
                if !transitioned {
                    return Ok::<_, PersistDbError>(());
                }

                let asset_balance =
                    get_user_balance_on(txn, &tab.user_address, &asset_address).await?;
                let collateral = U256::from_str(&asset_balance.total)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                if collateral < amount {
                    return Err(PersistDbError::InsufficientCollateral);
                }
                if amount > U256::ZERO {
                    let locked = U256::from_str(&asset_balance.locked)
                        .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                    if amount > locked {
                        return Err(PersistDbError::InvariantViolation(
                            "remunerate amount exceeds locked collateral".into(),
                        ));
                    }
                    let new_collateral = collateral
                        .checked_sub(amount)
                        .ok_or(PersistDbError::InsufficientCollateral)?;
                    let new_locked = locked.checked_sub(amount).ok_or_else(|| {
                        PersistDbError::InvariantViolation(
                            "locked collateral underflow during remuneration".into(),
                        )
                    })?;
                    update_user_balance_and_version_on(
                        txn,
                        &tab.user_address,
                        &asset_address,
                        asset_balance.version,
                        new_collateral,
                        new_locked,
                    )
                    .await?;
                }

                let ev = collateral_event::ActiveModel {
                    id: Set(new_uuid()),
                    user_address: Set(tab.user_address),
                    asset_address: Set(asset_address),
                    amount: Set(amount.to_string()),
                    event_type: Set(CollateralEventType::Remunerate),
                    tab_id: Set(Some(tab_id_str)),
                    req_id: Set(None),
                    tx_id: Set(None),
                    event_chain_id: Set(event.as_ref().map(|e| e.chain_id as i64)),
                    event_block_hash: Set(event.as_ref().map(|e| e.block_hash.clone())),
                    event_tx_hash: Set(event.as_ref().map(|e| e.tx_hash.clone())),
                    event_log_index: Set(event.as_ref().map(|e| e.log_index as i64)),
                    created_at: Set(now),
                };
                collateral_event::Entity::insert(ev).exec(txn).await?;

                Ok::<_, PersistDbError>(())
            })
        })
        .await?;

    Ok(())
}

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

pub async fn revert_remuneration(
    ctx: &PersistCtx,
    tab_id: U256,
    asset_address: String,
    amount: U256,
    event: EventMeta,
) -> Result<(), PersistDbError> {
    parse_address(&asset_address)?;
    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let tab = get_tab_by_id_on(txn, tab_id).await?;
                let tab_id_str = u256_to_string(tab_id);

                let asset_balance =
                    get_user_balance_on(txn, &tab.user_address, &asset_address).await?;
                let total = U256::from_str(&asset_balance.total)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let locked = U256::from_str(&asset_balance.locked)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let new_total = total.checked_add(amount).ok_or_else(|| {
                    PersistDbError::InvariantViolation("revert remuneration overflow".into())
                })?;
                let new_locked = locked.checked_add(amount).ok_or_else(|| {
                    PersistDbError::InvariantViolation("revert locked overflow".into())
                })?;

                update_user_balance_and_version_on(
                    txn,
                    &tab.user_address,
                    &asset_address,
                    asset_balance.version,
                    new_total,
                    new_locked,
                )
                .await?;

                tabs::Entity::update_many()
                    .filter(tabs::Column::Id.eq(tab_id_str))
                    .filter(tabs::Column::SettlementStatus.eq(SettlementStatus::Remunerated))
                    .col_expr(
                        tabs::Column::SettlementStatus,
                        sea_orm::sea_query::Expr::value(SettlementStatus::Pending),
                    )
                    .col_expr(
                        tabs::Column::UpdatedAt,
                        sea_orm::sea_query::Expr::value(now()),
                    )
                    .exec(txn)
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
