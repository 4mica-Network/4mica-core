use crate::persist::PersistCtx;
use anyhow::Result;
use chrono::{TimeZone, Utc};
use entities::{
    collateral_event, guarantee,
    sea_orm_active_enums::{CollateralEventType, WithdrawalStatus},
    user, user_transaction, withdrawal,
};
use rpc::common::TransactionVerificationResult;
use sea_orm::QueryOrder;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set, TransactionTrait,
};
use thiserror::Error;

//
// ────────────────────── USER FUNCTIONS ──────────────────────
//

pub async fn get_user(ctx: &PersistCtx, user_addr: String) -> anyhow::Result<Option<user::Model>> {
    Ok(user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?)
}

//
// ────────────────────── COLLATERAL EVENTS ──────────────────────
//

/// Deposit: increment collateral and record a CollateralEvent::Deposit for auditability.
pub async fn deposit(ctx: &PersistCtx, user_addr: String, amount: f64) -> anyhow::Result<()> {
    use sea_orm::ActiveValue::Set;
    let now = Utc::now().naive_utc();
    if amount < 0.0 {
        return Err(anyhow::anyhow!("negative deposit not allowed"));
    }
    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                // Ensure the user row exists
                let insert_user = user::ActiveModel {
                    address: Set(user_addr.clone()),
                    revenue: Set(0.0),
                    version: Set(0),
                    created_at: Set(now),
                    updated_at: Set(now),
                    collateral: Set(0.0),
                    locked_collateral: Set(0.0),
                };
                let _ = user::Entity::insert(insert_user)
                    .on_conflict(
                        OnConflict::column(user::Column::Address)
                            .do_nothing()
                            .to_owned(),
                    )
                    .exec(txn)
                    .await;
                if amount == 0.0 {
                    return Ok(());
                }
                // Increment collateral
                user::Entity::update_many()
                    .col_expr(
                        user::Column::Collateral,
                        Expr::col(user::Column::Collateral).add(amount),
                    )
                    .col_expr(user::Column::UpdatedAt, Expr::value(now))
                    .filter(user::Column::Address.eq(user_addr.clone()))
                    .exec(txn)
                    .await?;

                // Insert ledger event
                let ev = collateral_event::ActiveModel {
                    id: Set(uuid::Uuid::new_v4().to_string()),
                    user_address: Set(user_addr),
                    amount: Set(amount),
                    event_type: Set(CollateralEventType::Deposit),
                    tab_id: Set(None),
                    req_id: Set(None),
                    tx_id: Set(None),
                    created_at: Set(now),
                };
                collateral_event::Entity::insert(ev).exec(txn).await?;

                Ok::<_, sea_orm::DbErr>(())
            })
        })
        .await?;

    Ok(())
}

//
// ────────────────────── WITHDRAWALS ──────────────────────
//

pub async fn request_withdrawal(
    ctx: &PersistCtx,
    user_addr: String,
    when: i64,
    amount: f64,
) -> Result<()> {
    if amount <= 0.0 {
        return Err(anyhow::anyhow!("withdrawal amount must be positive"));
    }

    // Ensure user exists and has enough collateral
    let Some(u) = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
    else {
        return Err(anyhow::anyhow!("user not found"));
    };

    if amount > u.collateral {
        return Err(anyhow::anyhow!("insufficient collateral"));
    }

    let now = Utc::now().naive_utc();
    let ts = Utc
        .timestamp_opt(when, 0)
        .single()
        .ok_or_else(|| anyhow::anyhow!("invalid timestamp: {}", when))?
        .naive_utc();

    let am = withdrawal::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        user_address: Set(user_addr),
        amount: Set(amount),
        ts: Set(ts),
        status: Set(WithdrawalStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
    };
    withdrawal::Entity::insert(am).exec(&*ctx.db).await?;
    Ok(())
}

pub async fn cancel_withdrawal(ctx: &PersistCtx, user_addr: String) -> Result<()> {
    let records = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending)) // ✅ fix
        .all(&*ctx.db)
        .await?;

    for rec in records {
        let mut am = rec.into_active_model();
        am.status = Set(WithdrawalStatus::Cancelled);
        am.updated_at = Set(Utc::now().naive_utc());
        am.update(&*ctx.db).await?;
    }
    Ok(())
}

pub async fn finalize_withdrawal(ctx: &PersistCtx, user_addr: String, amount: f64) -> Result<()> {
    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                // decrement collateral
                user::Entity::update_many()
                    .col_expr(
                        user::Column::Collateral,
                        Expr::col(user::Column::Collateral).sub(amount),
                    )
                    .col_expr(user::Column::UpdatedAt, Expr::value(Utc::now().naive_utc()))
                    .filter(user::Column::Address.eq(user_addr.clone()))
                    .exec(txn)
                    .await?;

                // mark most recent withdrawal as completed
                if let Some(w) = withdrawal::Entity::find()
                    .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
                    .order_by_desc(withdrawal::Column::CreatedAt)
                    .one(txn)
                    .await?
                {
                    let mut am = w.into_active_model();
                    am.status = Set(WithdrawalStatus::Executed);
                    am.updated_at = Set(Utc::now().naive_utc());
                    am.update(txn).await?;
                }
                Ok::<_, sea_orm::DbErr>(())
            })
        })
        .await?;
    Ok(())
}

//
// ────────────────────── TRANSACTIONS ──────────────────────
//

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
                // Ensure the user exists
                let Some(user_row) = user::Entity::find()
                    .filter(user::Column::Address.eq(user_addr.clone()))
                    .one(txn)
                    .await?
                else {
                    return Err(SubmitPaymentTxnError::UserNotRegistered);
                };

                // Reserve deposit for other unfinalized txs
                let pending = user_transaction::Entity::find()
                    .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
                    .filter(user_transaction::Column::Finalized.eq(false))
                    .filter(user_transaction::Column::TxId.ne(transaction_id.clone()))
                    .all(txn)
                    .await?;

                let not_usable_deposit: f64 = pending.iter().map(|tx| tx.amount).sum();

                if not_usable_deposit + amount > user_row.collateral {
                    return Err(SubmitPaymentTxnError::NotEnoughDeposit);
                }

                // Upsert tx row
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

                // Important: use exec_without_returning so duplicate inserts are no-op
                let _ = user_transaction::Entity::insert(tx_am)
                    .on_conflict(
                        OnConflict::column(user_transaction::Column::TxId)
                            .do_nothing()
                            .to_owned(),
                    )
                    .exec_without_returning(txn)
                    .await?;

                // Optimistic version bump
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
                let Some(tx_row) = user_transaction::Entity::find_by_id(transaction_id.clone())
                    .one(txn)
                    .await?
                else {
                    return Ok(());
                };

                if tx_row.failed {
                    // Already failed → idempotent
                    return Ok(());
                }

                let mut am = tx_row.clone().into_active_model();
                am.finalized = Set(true);
                am.failed = Set(true);
                am.updated_at = Set(Utc::now().naive_utc());
                am.update(txn).await?;

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

//
// ────────────────────── TRANSACTION QUERIES ──────────────────────
//

pub async fn get_transactions_by_hash(
    ctx: &PersistCtx,
    hashes: Vec<String>,
) -> anyhow::Result<Vec<user_transaction::Model>> {
    Ok(user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.is_in(hashes))
        .all(&*ctx.db)
        .await?)
}

pub async fn get_unfinalized_transactions(
    ctx: &PersistCtx,
) -> anyhow::Result<Vec<user_transaction::Model>> {
    Ok(user_transaction::Entity::find()
        .filter(user_transaction::Column::Finalized.eq(false))
        .all(&*ctx.db)
        .await?)
}

//
// ────────────────────── GUARANTEES / CERTIFICATES ──────────────────────
//

pub async fn store_certificate(
    ctx: &PersistCtx,
    tab_id: String,
    req_id: i32,
    from_addr: String,
    to_addr: String,
    value: f64,
    start_ts: chrono::NaiveDateTime,
    cert: String,
) -> anyhow::Result<()> {
    let now = Utc::now().naive_utc();

    // Ensure foreign keys exist
    for addr in [&from_addr, &to_addr] {
        let insert_user = user::ActiveModel {
            address: Set(addr.clone()),
            revenue: Set(0.0),
            version: Set(0),
            created_at: Set(now),
            updated_at: Set(now),
            collateral: Set(0.0),
            locked_collateral: Set(0.0),
        };
        let _ = user::Entity::insert(insert_user)
            .on_conflict(
                OnConflict::column(user::Column::Address)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(&*ctx.db)
            .await;
    }

    let am = guarantee::ActiveModel {
        tab_id: Set(tab_id),
        req_id: Set(req_id),
        from_address: Set(from_addr),
        to_address: Set(to_addr),
        value: Set(value),
        start_ts: Set(start_ts),
        cert: Set(Some(cert)),
        created_at: Set(now),
        updated_at: Set(now),
    };

    // Use exec_without_returning to avoid "RecordNotInserted"
    let _ = guarantee::Entity::insert(am)
        .on_conflict(
            OnConflict::columns([guarantee::Column::TabId, guarantee::Column::ReqId])
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&*ctx.db)
        .await?;

    Ok(())
}

pub async fn get_certificate(
    ctx: &PersistCtx,
    tab_id: String,
    req_id: i32,
) -> anyhow::Result<Option<guarantee::Model>> {
    Ok(guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(tab_id))
        .filter(guarantee::Column::ReqId.eq(req_id))
        .one(&*ctx.db)
        .await?)
}

//
// ────────────────────── REMUNERATION / PAYMENTS ──────────────────────
//

pub async fn remunerate_recipient(
    ctx: &PersistCtx,
    tab_id: String,
    req_id: i64,
    amount: f64,
) -> Result<()> {
    let now = Utc::now().naive_utc();

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let tab = entities::tabs::Entity::find_by_id(tab_id.clone())
                    .one(txn)
                    .await?
                    .ok_or_else(|| sea_orm::DbErr::Custom(format!("Tab not found: {tab_id}")))?;

                // Idempotency: if an event already exists for this (tab_id, req_id, Remunerate), do nothing
                let existing = collateral_event::Entity::find()
                    .filter(collateral_event::Column::TabId.eq(tab_id.clone()))
                    .filter(collateral_event::Column::ReqId.eq(req_id as i32))
                    .filter(collateral_event::Column::EventType.eq(CollateralEventType::Remunerate))
                    .one(txn)
                    .await?;

                if existing.is_some() {
                    return Ok::<_, sea_orm::DbErr>(());
                }

                let ev = collateral_event::ActiveModel {
                    id: Set(uuid::Uuid::new_v4().to_string()),
                    user_address: Set(tab.user_address),
                    amount: Set(amount),
                    event_type: Set(CollateralEventType::Remunerate),
                    tab_id: Set(Some(tab_id)),
                    req_id: Set(Some(req_id as i32)),
                    tx_id: Set(None),
                    created_at: Set(now),
                };
                collateral_event::Entity::insert(ev).exec(txn).await?;
                Ok(())
            })
        })
        .await?;

    Ok(())
}
