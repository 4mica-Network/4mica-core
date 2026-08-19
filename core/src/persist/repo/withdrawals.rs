use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use crate::persist::canonical::Canonical;
use alloy::primitives::Address;
use alloy::primitives::U256;
use chrono::{TimeZone, Utc};
use entities::sea_orm_active_enums::WithdrawalStatus;
use entities::withdrawal;
use log::warn;
use metrics_4mica::measure;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, IntoActiveModel, QueryFilter,
    QueryOrder, Set, TransactionTrait,
    sea_query::{Expr, OnConflict},
};

use super::balances::{get_user_balance_on, update_user_balance_and_version_on};
use super::common::{map_pending_withdrawal_err, new_uuid};
use crate::ethereum::event_data::EventMeta;
use crate::metrics::misc::record_db_time;

#[measure(record_db_time)]
pub async fn request_withdrawal(
    ctx: &PersistCtx,
    user_address: Address,
    asset_address: Address,
    when: i64,
    amount: U256,
) -> Result<(), PersistDbError> {
    request_withdrawal_with_event(ctx, user_address, asset_address, when, amount, None).await
}

#[measure(record_db_time)]
pub async fn request_withdrawal_with_event(
    ctx: &PersistCtx,
    user_address: Address,
    asset_address: Address,
    when: i64,
    amount: U256,
    event: Option<&EventMeta>,
) -> Result<(), PersistDbError> {
    let event = event.cloned();

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let asset_balance = get_user_balance_on(txn, user_address, asset_address).await?;

                let total = asset_balance.total;
                let locked = asset_balance.locked;

                let free = total.saturating_sub(locked);
                if amount > free {
                    warn!(
                        "withdrawal request of {amount} for user {user_address} asset {asset_address} exceeds free collateral (total {total} - locked {locked}); recording anyway (already on-chain) — user is exiting guarantee-backing collateral"
                    );
                    crate::metrics::record_withdrawal_exceeds_free(&asset_address.canonical());
                }
                update_user_balance_and_version_on(
                    txn,
                    user_address,
                    asset_address,
                    asset_balance.version,
                    total,
                    locked,
                )
                .await?;

                let now = Utc::now().naive_utc();
                let ts = Utc
                    .timestamp_opt(when, 0)
                    .single()
                    .ok_or_else(|| PersistDbError::InvalidTimestamp(when))?
                    .naive_utc();

                let withdrawal_model = withdrawal::ActiveModel {
                    id: Set(new_uuid()),
                    user_address: Set(user_address.canonical()),
                    asset_address: Set(asset_address.canonical()),
                    requested_amount: Set(amount.to_string()),
                    executed_amount: Set("0".to_owned()),
                    request_ts: Set(ts),
                    status: Set(WithdrawalStatus::Pending),
                    request_event_chain_id: Set(event.as_ref().map(|e| e.chain_id as i64)),
                    request_event_block_hash: Set(event.as_ref().map(|e| e.block_hash.clone())),
                    request_event_tx_hash: Set(event.as_ref().map(|e| e.tx_hash.clone())),
                    request_event_log_index: Set(event.as_ref().map(|e| e.log_index as i64)),
                    cancel_event_chain_id: Set(None),
                    cancel_event_block_hash: Set(None),
                    cancel_event_tx_hash: Set(None),
                    cancel_event_log_index: Set(None),
                    execute_event_chain_id: Set(None),
                    execute_event_block_hash: Set(None),
                    execute_event_tx_hash: Set(None),
                    execute_event_log_index: Set(None),
                    created_at: Set(now),
                    updated_at: Set(now),
                };

                // We have a partial unique index on (user_address, asset_address) where status = 'PENDING'
                // which means that a user can only have one pending withdrawal per asset,
                //   so we need to handle the conflict here.
                // And we can't throw here because this request has been already updated on the chain.
                withdrawal::Entity::insert(withdrawal_model)
                    .on_conflict(
                        OnConflict::columns([
                            withdrawal::Column::UserAddress,
                            withdrawal::Column::AssetAddress,
                        ])
                        // Must use a literal 'PENDING' here so Postgres can match our partial unique index.
                        // Otherwise, SeaORM will use a bind param and Postgres complains that there's no unique index covering the predicate.
                        .target_and_where(Expr::cust(r#""Withdrawal"."status" = 'PENDING'"#))
                        .update_columns([
                            withdrawal::Column::RequestedAmount,
                            withdrawal::Column::ExecutedAmount,
                            withdrawal::Column::RequestTs,
                            withdrawal::Column::Status,
                            withdrawal::Column::UpdatedAt,
                        ])
                        .to_owned(),
                    )
                    .exec(txn)
                    .await
                    .map_err(|e| map_pending_withdrawal_err(e, user_address, asset_address))?;
                Ok::<_, PersistDbError>(())
            })
        })
        .await?;
    Ok(())
}

#[measure(record_db_time)]
pub async fn cancel_withdrawal(
    ctx: &PersistCtx,
    user_address: Address,
    asset_address: Address,
) -> Result<(), PersistDbError> {
    cancel_withdrawal_with_event(ctx, user_address, asset_address, None).await
}

#[measure(record_db_time)]
pub async fn cancel_withdrawal_with_event(
    ctx: &PersistCtx,
    user_address: Address,
    asset_address: Address,
    event: Option<&EventMeta>,
) -> Result<(), PersistDbError> {
    let event = event.cloned();
    match withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_address.canonical()))
        .filter(withdrawal::Column::AssetAddress.eq(asset_address.canonical()))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .one(ctx.db.as_ref())
        .await?
    {
        Some(rec) => {
            let mut active_model = rec.into_active_model();
            active_model.status = Set(WithdrawalStatus::Cancelled);
            active_model.cancel_event_chain_id = Set(event.as_ref().map(|e| e.chain_id as i64));
            active_model.cancel_event_block_hash =
                Set(event.as_ref().map(|e| e.block_hash.clone()));
            active_model.cancel_event_tx_hash = Set(event.as_ref().map(|e| e.tx_hash.clone()));
            active_model.cancel_event_log_index = Set(event.as_ref().map(|e| e.log_index as i64));
            active_model.updated_at = Set(Utc::now().naive_utc());
            active_model.update(ctx.db.as_ref()).await?;
            Ok(())
        }
        None => Ok(()),
    }
}

#[measure(record_db_time)]
pub async fn finalize_withdrawal(
    ctx: &PersistCtx,
    user_address: Address,
    asset_address: Address,
    executed_amount: U256,
) -> Result<(), PersistDbError> {
    finalize_withdrawal_with_event(ctx, user_address, asset_address, executed_amount, None).await
}

#[measure(record_db_time)]
pub async fn finalize_withdrawal_with_event(
    ctx: &PersistCtx,
    user_address: Address,
    asset_address: Address,
    executed_amount: U256,
    event: Option<&EventMeta>,
) -> Result<(), PersistDbError> {
    let event = event.cloned();
    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let now = Utc::now().naive_utc();

                let pending = withdrawal::Entity::find()
                    .filter(withdrawal::Column::UserAddress.eq(user_address.canonical()))
                    .filter(withdrawal::Column::AssetAddress.eq(asset_address.canonical()))
                    .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
                    .order_by_desc(withdrawal::Column::CreatedAt)
                    .all(txn)
                    .await?;

                if pending.is_empty() {
                    return Err(PersistDbError::WithdrawalNotFound {
                        user: user_address.clone().canonical(),
                        asset: asset_address.clone().canonical(),
                    });
                }
                // This should never happen!
                if pending.len() > 1 {
                    return Err(PersistDbError::MultiplePendingWithdrawals {
                        user: user_address.clone().canonical(),
                        asset: asset_address.clone().canonical(),
                        count: pending.len(),
                    });
                }
                let withdrawal = pending
                    .into_iter()
                    .next()
                    .expect("invariant: exactly one pending withdrawal after length checks");

                let requested = U256::from_canonical(&withdrawal.requested_amount)?;

                // `executed_amount` and `requested` should be the same, but if not, we take the minimum as a best effort.
                //  We can't throw here because it's been already executed on the chain.
                let executed_amount = std::cmp::min(executed_amount, requested);

                let asset_balance = get_user_balance_on(
                    txn,
                    user_address,
                    Address::from_canonical(&withdrawal.asset_address)?,
                )
                .await?;
                let current_total = asset_balance.total;
                let locked = asset_balance.locked;

                let new_total = current_total
                    .checked_sub(executed_amount)
                    .ok_or(PersistDbError::InsufficientCollateral)?;

                update_user_balance_and_version_on(
                    txn,
                    user_address,
                    Address::from_canonical(&withdrawal.asset_address)?,
                    asset_balance.version,
                    new_total,
                    locked,
                )
                .await?;

                let mut am_w = withdrawal.into_active_model();
                am_w.status = Set(WithdrawalStatus::Executed);
                am_w.executed_amount = Set(executed_amount.canonical());
                am_w.execute_event_chain_id = Set(event.as_ref().map(|e| e.chain_id as i64));
                am_w.execute_event_block_hash = Set(event.as_ref().map(|e| e.block_hash.clone()));
                am_w.execute_event_tx_hash = Set(event.as_ref().map(|e| e.tx_hash.clone()));
                am_w.execute_event_log_index = Set(event.as_ref().map(|e| e.log_index as i64));
                am_w.updated_at = Set(now);
                am_w.update(txn).await?;

                Ok::<_, PersistDbError>(())
            })
        })
        .await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn mark_withdrawal_executed_with_event(
    ctx: &PersistCtx,
    user_address: Address,
    asset_address: Address,
    executed_amount: U256,
    event: Option<&EventMeta>,
) -> Result<(), PersistDbError> {
    let event = event.cloned();

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let now = Utc::now().naive_utc();

                let pending = withdrawal::Entity::find()
                    .filter(withdrawal::Column::UserAddress.eq(user_address.canonical()))
                    .filter(withdrawal::Column::AssetAddress.eq(asset_address.canonical()))
                    .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
                    .order_by_desc(withdrawal::Column::CreatedAt)
                    .all(txn)
                    .await?;

                if pending.is_empty() {
                    return Err(PersistDbError::WithdrawalNotFound {
                        user: user_address.clone().canonical(),
                        asset: asset_address.clone().canonical(),
                    });
                }
                if pending.len() > 1 {
                    return Err(PersistDbError::MultiplePendingWithdrawals {
                        user: user_address.clone().canonical(),
                        asset: asset_address.clone().canonical(),
                        count: pending.len(),
                    });
                }

                let withdrawal = pending
                    .into_iter()
                    .next()
                    .expect("invariant: exactly one pending withdrawal after length checks");
                let requested = U256::from_canonical(&withdrawal.requested_amount)?;
                let executed_amount = std::cmp::min(executed_amount, requested);

                let mut am_w = withdrawal.into_active_model();
                am_w.status = Set(WithdrawalStatus::Executed);
                am_w.executed_amount = Set(executed_amount.canonical());
                am_w.execute_event_chain_id = Set(event.as_ref().map(|e| e.chain_id as i64));
                am_w.execute_event_block_hash = Set(event.as_ref().map(|e| e.block_hash.clone()));
                am_w.execute_event_tx_hash = Set(event.as_ref().map(|e| e.tx_hash.clone()));
                am_w.execute_event_log_index = Set(event.as_ref().map(|e| e.log_index as i64));
                am_w.updated_at = Set(now);
                am_w.update(txn).await?;

                Ok::<_, PersistDbError>(())
            })
        })
        .await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn revert_withdrawal_request(
    ctx: &PersistCtx,
    event: EventMeta,
) -> Result<(), PersistDbError> {
    let result = withdrawal::Entity::delete_many()
        .filter(withdrawal::Column::RequestEventChainId.eq(event.chain_id as i64))
        .filter(withdrawal::Column::RequestEventBlockHash.eq(event.block_hash.clone()))
        .filter(withdrawal::Column::RequestEventTxHash.eq(event.tx_hash.clone()))
        .filter(withdrawal::Column::RequestEventLogIndex.eq(event.log_index as i64))
        .exec(ctx.db.as_ref())
        .await?;
    if result.rows_affected == 0 {
        return Ok(());
    }
    Ok(())
}

#[measure(record_db_time)]
pub async fn revert_withdrawal_cancel(
    ctx: &PersistCtx,
    event: EventMeta,
) -> Result<(), PersistDbError> {
    withdrawal::Entity::update_many()
        .filter(withdrawal::Column::CancelEventChainId.eq(event.chain_id as i64))
        .filter(withdrawal::Column::CancelEventBlockHash.eq(event.block_hash.clone()))
        .filter(withdrawal::Column::CancelEventTxHash.eq(event.tx_hash.clone()))
        .filter(withdrawal::Column::CancelEventLogIndex.eq(event.log_index as i64))
        .col_expr(
            withdrawal::Column::Status,
            withdrawal::Column::Status
                .save_as(sea_orm::sea_query::Expr::val(WithdrawalStatus::Pending)),
        )
        .col_expr(
            withdrawal::Column::CancelEventChainId,
            sea_orm::sea_query::Expr::value::<Option<i64>>(None),
        )
        .col_expr(
            withdrawal::Column::CancelEventBlockHash,
            sea_orm::sea_query::Expr::value::<Option<String>>(None),
        )
        .col_expr(
            withdrawal::Column::CancelEventTxHash,
            sea_orm::sea_query::Expr::value::<Option<String>>(None),
        )
        .col_expr(
            withdrawal::Column::CancelEventLogIndex,
            sea_orm::sea_query::Expr::value::<Option<i64>>(None),
        )
        .col_expr(
            withdrawal::Column::UpdatedAt,
            sea_orm::sea_query::Expr::value(Utc::now().naive_utc()),
        )
        .exec(ctx.db.as_ref())
        .await?;
    Ok(())
}

#[measure(record_db_time)]
pub async fn revert_withdrawal_execution(
    ctx: &PersistCtx,
    event: EventMeta,
    user_address: Address,
    asset_address: Address,
    executed_amount: U256,
) -> Result<(), PersistDbError> {
    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let asset_balance = get_user_balance_on(txn, user_address, asset_address).await?;
                let current_total = asset_balance.total;
                let locked = asset_balance.locked;
                let new_total = current_total.checked_add(executed_amount).ok_or_else(|| {
                    PersistDbError::InvariantViolation("revert execute overflow".into())
                })?;
                update_user_balance_and_version_on(
                    txn,
                    user_address,
                    asset_address,
                    asset_balance.version,
                    new_total,
                    locked,
                )
                .await?;

                withdrawal::Entity::update_many()
                    .filter(withdrawal::Column::ExecuteEventChainId.eq(event.chain_id as i64))
                    .filter(withdrawal::Column::ExecuteEventBlockHash.eq(event.block_hash.clone()))
                    .filter(withdrawal::Column::ExecuteEventTxHash.eq(event.tx_hash.clone()))
                    .filter(withdrawal::Column::ExecuteEventLogIndex.eq(event.log_index as i64))
                    .col_expr(
                        withdrawal::Column::Status,
                        withdrawal::Column::Status
                            .save_as(sea_orm::sea_query::Expr::val(WithdrawalStatus::Pending)),
                    )
                    .col_expr(
                        withdrawal::Column::ExecutedAmount,
                        sea_orm::sea_query::Expr::value("0".to_string()),
                    )
                    .col_expr(
                        withdrawal::Column::ExecuteEventChainId,
                        sea_orm::sea_query::Expr::value::<Option<i64>>(None),
                    )
                    .col_expr(
                        withdrawal::Column::ExecuteEventBlockHash,
                        sea_orm::sea_query::Expr::value::<Option<String>>(None),
                    )
                    .col_expr(
                        withdrawal::Column::ExecuteEventTxHash,
                        sea_orm::sea_query::Expr::value::<Option<String>>(None),
                    )
                    .col_expr(
                        withdrawal::Column::ExecuteEventLogIndex,
                        sea_orm::sea_query::Expr::value::<Option<i64>>(None),
                    )
                    .col_expr(
                        withdrawal::Column::UpdatedAt,
                        sea_orm::sea_query::Expr::value(Utc::now().naive_utc()),
                    )
                    .exec(txn)
                    .await?;

                Ok::<_, PersistDbError>(())
            })
        })
        .await?;
    Ok(())
}

#[measure(record_db_time)]
pub async fn get_pending_withdrawal_on<C: ConnectionTrait>(
    conn: &C,
    user_address: Address,
    asset_address: Address,
) -> Result<Option<withdrawal::Model>, PersistDbError> {
    let user_str = user_address.canonical().to_owned();
    let asset_str = asset_address.canonical().to_owned();

    let rows = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(&user_str))
        .filter(withdrawal::Column::AssetAddress.eq(&asset_str))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .order_by_desc(withdrawal::Column::CreatedAt)
        .all(conn)
        .await?;

    match rows.len() {
        0 => Ok(None),
        1 => Ok(rows.into_iter().next()),
        count => Err(PersistDbError::MultiplePendingWithdrawals {
            user: user_str,
            asset: asset_str,
            count,
        }),
    }
}

#[measure(record_db_time)]
pub async fn get_pending_withdrawals_for_user(
    ctx: &PersistCtx,
    user_address: Address,
) -> Result<Vec<withdrawal::Model>, PersistDbError> {
    let rows = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_address.canonical()))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}
