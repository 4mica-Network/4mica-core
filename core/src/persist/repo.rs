use crate::persist::PersistCtx;
use chrono::Utc;
use entities::{user, user_transaction};
use rpc::common::TransactionVerificationResult;
use sea_orm::sea_query::Expr;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseTransaction, EntityTrait, IntoActiveModel, QueryFilter,
    Set, TransactionTrait,
};
use thiserror::Error;

pub async fn register_user(ctx: &PersistCtx, user_addr: String) -> anyhow::Result<()> {
    // Provide sane defaults since your SeaORM User model has several NOT NULL columns.
    let now = Utc::now().naive_utc();

    let am = user::ActiveModel {
        address: Set(user_addr.clone()),
        revenue: Set(0.0),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        collateral: Set(0.0),
        locked_collateral: Set(0.0),
    };

    // Upsert behavior: insert and do nothing on conflict.
    user::Entity::insert(am)
        .on_conflict(
            OnConflict::column(user::Column::Address)
                .do_nothing()
                .to_owned(),
        )
        .exec(&*ctx.db)
        .await?;

    Ok(())
}

pub async fn get_user(ctx: &PersistCtx, user_addr: String) -> anyhow::Result<Option<user::Model>> {
    let user = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?;
    Ok(user)
}

pub async fn register_user_with_deposit(
    ctx: &PersistCtx,
    user_addr: String,
    deposit: f64,
) -> anyhow::Result<()> {
    let now = Utc::now().naive_utc();

    // Try to find the user
    if let Some(found) = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
    {
        // Update: set collateral to `deposit`, bump version, touch updated_at
        let mut am = found.into_active_model();
        am.collateral = Set(deposit);
        am.version = Set(am.version.take().unwrap_or_default() + 1);
        am.updated_at = Set(now);
        am.update(&*ctx.db).await?;
    } else {
        // Insert with initial collateral
        let am = user::ActiveModel {
            address: Set(user_addr),
            revenue: Set(0.0),
            version: Set(0),
            created_at: Set(now),
            updated_at: Set(now),
            collateral: Set(deposit),
            locked_collateral: Set(0.0),
        };
        user::Entity::insert(am).exec(&*ctx.db).await?;
    }

    Ok(())
}

pub async fn add_user_deposit(
    ctx: &PersistCtx,
    user_addr: String,
    deposit: f64,
) -> anyhow::Result<()> {
    // Increment collateral by `deposit`
    user::Entity::update_many()
        .col_expr(
            user::Column::Collateral,
            Expr::col(user::Column::Collateral).add(deposit),
        )
        .col_expr(user::Column::UpdatedAt, Expr::value(Utc::now().naive_utc()))
        .filter(user::Column::Address.eq(user_addr))
        .exec(&*ctx.db)
        .await?;

    Ok(())
}

pub async fn get_transactions_by_hash(
    ctx: &PersistCtx,
    hashes: Vec<String>,
) -> anyhow::Result<Vec<user_transaction::Model>> {
    let transactions = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.is_in(hashes))
        .all(&*ctx.db)
        .await?;
    Ok(transactions)
}

pub async fn get_unfinalized_transactions(
    ctx: &PersistCtx,
) -> anyhow::Result<Vec<user_transaction::Model>> {
    let transactions = user_transaction::Entity::find()
        .filter(user_transaction::Column::Finalized.eq(false))
        .all(&*ctx.db)
        .await?;
    Ok(transactions)
}

pub async fn confirm_transaction(ctx: &PersistCtx, transaction_hash: String) -> anyhow::Result<()> {
    if let Some(mut tx) = user_transaction::Entity::find_by_id(transaction_hash)
        .one(&*ctx.db)
        .await?
        .map(IntoActiveModel::into_active_model)
    {
        tx.finalized = Set(true);
        tx.updated_at = Set(Utc::now().naive_utc());
        tx.update(&*ctx.db).await?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum SubmitPaymentTxnError {
    #[error("Database error: {0:?}")]
    Db(#[from] sea_orm::DbErr),

    #[error("User is not registered yet!")]
    UserNotRegistered,

    #[error("Not enough deposit available!")]
    NotEnoughDeposit,

    #[error("Found conflicting transactions!")]
    ConflictingTransactions,
}

pub async fn submit_payment_transaction(
    ctx: &PersistCtx,
    user_addr: String,
    recipient_address: String,
    transaction_id: String,
    amount: f64,
    cert: String,
) -> Result<(), SubmitPaymentTxnError> {
    ctx.db
        .transaction::<_, (), SubmitPaymentTxnError>(|txn| {
            Box::pin(async move {
                // Load user
                let Some(user_row) = user::Entity::find()
                    .filter(user::Column::Address.eq(user_addr.clone()))
                    .one(txn)
                    .await?
                else {
                    return Err(SubmitPaymentTxnError::UserNotRegistered);
                };

                // Load user's other unfinalized txs (excluding this tx_id)
                let pending = user_transaction::Entity::find()
                    .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
                    .filter(user_transaction::Column::Finalized.eq(false))
                    .filter(user_transaction::Column::TxId.ne(transaction_id.clone()))
                    .all(txn)
                    .await?;

                let not_usable_deposit: f64 = pending.iter().map(|tx| tx.amount).sum();

                // Compare against user's available collateral
                if not_usable_deposit + amount > user_row.collateral {
                    return Err(SubmitPaymentTxnError::NotEnoughDeposit);
                }

                // Upsert tx: insert if missing, do nothing if exists
                let now = Utc::now().naive_utc();
                let tx_am = user_transaction::ActiveModel {
                    tx_id: Set(transaction_id.clone()),
                    user_address: Set(user_addr.clone()),
                    recipient_address: Set(recipient_address),
                    amount: Set(amount),
                    cert: Set(Some(cert)),
                    verified: Set(false),
                    finalized: Set(false),
                    failed: Set(false),
                    created_at: Set(now),
                    updated_at: Set(now),
                };

                user_transaction::Entity::insert(tx_am)
                    .on_conflict(
                        OnConflict::column(user_transaction::Column::TxId)
                            .do_nothing()
                            .to_owned(),
                    )
                    .exec(txn)
                    .await?;

                // Optimistic concurrency via conditional version bump:
                // UPDATE user SET version = version + 1, updated_at=now
                // WHERE address = ? AND version = ?
                let update_res = user::Entity::update_many()
                    .col_expr(
                        user::Column::Version,
                        Expr::col(user::Column::Version).add(1),
                    )
                    .col_expr(user::Column::UpdatedAt, Expr::value(now))
                    .filter(user::Column::Address.eq(user_addr.clone()))
                    .filter(user::Column::Version.eq(user_row.version))
                    .exec(txn)
                    .await?;

                if update_res.rows_affected != 1 {
                    return Err(SubmitPaymentTxnError::ConflictingTransactions);
                }

                Ok(())
            })
        })
        .await
        .map_err(|e| match e {
            sea_orm::TransactionError::Transaction(err) => err,
            sea_orm::TransactionError::Connection(err) => SubmitPaymentTxnError::Db(err),
        })?;

    Ok(())
}

pub async fn fail_transaction(
    ctx: &PersistCtx,
    user_addr: String,
    transaction_id: String,
) -> anyhow::Result<()> {
    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                // Find the transaction first to get the amount
                let Some(tx_row) = user_transaction::Entity::find_by_id(transaction_id.clone())
                    .one(txn)
                    .await?
                else {
                    // Nothing to do if it doesn't exist
                    return Ok(());
                };

                // Mark as finalized & failed
                let mut am = tx_row.clone().into_active_model();
                am.finalized = Set(true);
                am.failed = Set(true);
                am.updated_at = Set(Utc::now().naive_utc());
                am.update(txn).await?;

                // Decrement user's collateral by tx.amount
                user::Entity::update_many()
                    .col_expr(
                        user::Column::Collateral,
                        Expr::col(user::Column::Collateral).sub(tx_row.amount),
                    )
                    .col_expr(user::Column::UpdatedAt, Expr::value(Utc::now().naive_utc()))
                    .filter(user::Column::Address.eq(user_addr))
                    .exec(txn)
                    .await?;

                Ok::<_, sea_orm::DbErr>(())
            })
        })
        .await?;

    Ok(())
}

pub async fn verify_transaction(
    ctx: &PersistCtx,
    transaction_id: String,
) -> anyhow::Result<TransactionVerificationResult> {
    let result = ctx
        .db
        .transaction::<_, TransactionVerificationResult, sea_orm::DbErr>(|txn| {
            Box::pin(async move {
                let tx = user_transaction::Entity::find_by_id(transaction_id.clone())
                    .one(txn)
                    .await?;

                let Some(tx) = tx else {
                    return Ok(TransactionVerificationResult::NotFound);
                };

                if tx.verified {
                    return Ok(TransactionVerificationResult::AlreadyVerified);
                }

                let mut am = tx.into_active_model();
                am.verified = Set(true);
                am.updated_at = Set(Utc::now().naive_utc());
                am.update(txn).await?;

                Ok(TransactionVerificationResult::Verified)
            })
        })
        .await?;

    Ok(result)
}
