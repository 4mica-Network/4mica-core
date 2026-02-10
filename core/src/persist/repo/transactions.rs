use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use alloy::primitives::U256;
use entities::user_transaction;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use std::str::FromStr;

use super::balances::{get_user_balance_on, update_user_balance_and_version_on};
use super::common::{now, parse_address};
use super::users::ensure_user_exists_on;

pub async fn submit_payment_transaction(
    ctx: &PersistCtx,
    user_address: String,
    recipient_address: String,
    asset_address: String,
    transaction_id: String,
    amount: U256,
) -> Result<u64, PersistDbError> {
    parse_address(&user_address)?;
    parse_address(&recipient_address)?;
    parse_address(&asset_address)?;
    ensure_user_exists_on(ctx.db.as_ref(), &user_address).await?;

    let tx = user_transaction::ActiveModel {
        tx_id: Set(transaction_id),
        user_address: Set(user_address),
        recipient_address: Set(recipient_address),
        asset_address: Set(asset_address),
        amount: Set(amount.to_string()),
        tab_id: Set(None),
        block_number: Set(None),
        block_hash: Set(None),
        status: Set("confirmed".to_string()),
        confirmed_at: Set(None),
        verified: Set(false),
        finalized: Set(false),
        failed: Set(false),
        created_at: Set(now()),
        updated_at: Set(now()),
    };

    let rows_affected = user_transaction::Entity::insert(tx)
        .on_conflict(
            OnConflict::column(user_transaction::Column::TxId)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(ctx.db.as_ref())
        .await?;

    Ok(rows_affected)
}

#[allow(clippy::too_many_arguments)]
pub struct PendingPaymentInput {
    pub user_address: String,
    pub recipient_address: String,
    pub asset_address: String,
    pub transaction_id: String,
    pub amount: U256,
    pub tab_id: String,
    pub block_number: u64,
    pub block_hash: Option<String>,
}

pub async fn submit_pending_payment_transaction(
    ctx: &PersistCtx,
    pending: PendingPaymentInput,
) -> Result<u64, PersistDbError> {
    parse_address(&pending.user_address)?;
    parse_address(&pending.recipient_address)?;
    parse_address(&pending.asset_address)?;
    ensure_user_exists_on(ctx.db.as_ref(), &pending.user_address).await?;

    let tx = user_transaction::ActiveModel {
        tx_id: Set(pending.transaction_id),
        user_address: Set(pending.user_address),
        recipient_address: Set(pending.recipient_address),
        asset_address: Set(pending.asset_address),
        amount: Set(pending.amount.to_string()),
        tab_id: Set(Some(pending.tab_id)),
        block_number: Set(Some(pending.block_number as i64)),
        block_hash: Set(pending.block_hash),
        status: Set("pending".to_string()),
        confirmed_at: Set(None),
        verified: Set(false),
        finalized: Set(false),
        failed: Set(false),
        created_at: Set(now()),
        updated_at: Set(now()),
    };

    let rows_affected = user_transaction::Entity::insert(tx)
        .on_conflict(
            OnConflict::column(user_transaction::Column::TxId)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(ctx.db.as_ref())
        .await?;

    Ok(rows_affected)
}

pub async fn get_pending_transactions_upto(
    ctx: &PersistCtx,
    max_block_number: u64,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::Status.eq("pending"))
        .filter(user_transaction::Column::BlockNumber.lte(max_block_number as i64))
        .order_by_asc(user_transaction::Column::BlockNumber)
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

pub async fn mark_payment_transaction_confirmed(
    ctx: &PersistCtx,
    transaction_id: &str,
) -> Result<(), PersistDbError> {
    user_transaction::Entity::update_many()
        .filter(user_transaction::Column::TxId.eq(transaction_id))
        .filter(user_transaction::Column::Status.eq("pending"))
        .col_expr(
            user_transaction::Column::Status,
            sea_orm::sea_query::Expr::value("confirmed"),
        )
        .col_expr(
            user_transaction::Column::ConfirmedAt,
            sea_orm::sea_query::Expr::value(now()),
        )
        .col_expr(
            user_transaction::Column::UpdatedAt,
            sea_orm::sea_query::Expr::value(now()),
        )
        .exec(ctx.db.as_ref())
        .await?;
    Ok(())
}

pub async fn mark_payment_transaction_reverted(
    ctx: &PersistCtx,
    transaction_id: &str,
) -> Result<(), PersistDbError> {
    user_transaction::Entity::update_many()
        .filter(user_transaction::Column::TxId.eq(transaction_id))
        .col_expr(
            user_transaction::Column::Status,
            sea_orm::sea_query::Expr::value("reverted"),
        )
        .col_expr(
            user_transaction::Column::UpdatedAt,
            sea_orm::sea_query::Expr::value(now()),
        )
        .exec(ctx.db.as_ref())
        .await?;
    Ok(())
}

pub async fn delete_unfinalized_payment_transaction(
    ctx: &PersistCtx,
    transaction_id: &str,
) -> Result<(), PersistDbError> {
    user_transaction::Entity::delete_many()
        .filter(user_transaction::Column::TxId.eq(transaction_id))
        .filter(user_transaction::Column::Finalized.eq(false))
        .exec(ctx.db.as_ref())
        .await?;

    Ok(())
}

pub async fn mark_payment_transaction_finalized(
    ctx: &PersistCtx,
    transaction_id: &str,
) -> Result<(), PersistDbError> {
    user_transaction::Entity::update_many()
        .filter(user_transaction::Column::TxId.eq(transaction_id))
        .filter(user_transaction::Column::Finalized.eq(false))
        .col_expr(
            user_transaction::Column::Finalized,
            sea_orm::sea_query::Expr::value(true),
        )
        .col_expr(
            user_transaction::Column::Verified,
            sea_orm::sea_query::Expr::value(true),
        )
        .col_expr(
            user_transaction::Column::UpdatedAt,
            sea_orm::sea_query::Expr::value(now()),
        )
        .exec(ctx.db.as_ref())
        .await?;
    Ok(())
}

pub async fn fail_transaction(
    ctx: &PersistCtx,
    user_address: String,
    transaction_id: String,
) -> Result<(), PersistDbError> {
    parse_address(&user_address)?;

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let Some(tx_row) = user_transaction::Entity::find_by_id(transaction_id.clone())
                    .one(txn)
                    .await?
                else {
                    return Err(PersistDbError::TransactionNotFound(transaction_id));
                };

                if tx_row.user_address != user_address {
                    return Err(PersistDbError::UserNotFound(user_address));
                }

                if tx_row.failed {
                    return Ok(());
                }

                let mut active_model = tx_row.clone().into_active_model();
                active_model.finalized = Set(true);
                active_model.failed = Set(true);
                active_model.updated_at = Set(now());
                active_model.update(txn).await?;

                let asset_balance =
                    get_user_balance_on(txn, &user_address, &tx_row.asset_address).await?;

                let current_collateral = U256::from_str(&asset_balance.total)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let delta = U256::from_str(&tx_row.amount)
                    .map_err(|e| PersistDbError::InvalidTxAmount(e.to_string()))?;

                let new_collateral = current_collateral
                    .checked_sub(delta)
                    .ok_or(PersistDbError::InsufficientCollateral)?;

                let locked = U256::from_str(&asset_balance.locked)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                update_user_balance_and_version_on(
                    txn,
                    &user_address,
                    &tx_row.asset_address,
                    asset_balance.version,
                    new_collateral,
                    locked,
                )
                .await?;

                Ok::<_, PersistDbError>(())
            })
        })
        .await?;

    Ok(())
}

pub async fn get_transactions_by_hash(
    ctx: &PersistCtx,
    hashes: Vec<String>,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.is_in(hashes))
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

pub async fn get_unfinalized_transactions(
    ctx: &PersistCtx,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::Finalized.eq(false))
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

pub async fn get_user_transactions(
    ctx: &PersistCtx,
    user_address: &str,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let user_address = parse_address(user_address)?;

    let rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::UserAddress.eq(user_address.as_str()))
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

pub async fn get_recipient_transactions(
    ctx: &PersistCtx,
    recipient_address: &str,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let recipient_address = parse_address(recipient_address)?;

    let rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::RecipientAddress.eq(recipient_address.as_str()))
        .order_by_desc(user_transaction::Column::CreatedAt)
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}
