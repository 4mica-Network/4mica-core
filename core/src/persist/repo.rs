use crate::persist::PersistCtx;
use alloy::primitives::U256;
use anyhow::Result;
use chrono::{TimeZone, Utc};
use entities::{
    collateral_event, guarantee,
    sea_orm_active_enums::{CollateralEventType, WithdrawalStatus},
    user, user_transaction, withdrawal,
};
use log::error;
use rpc::common::TransactionVerificationResult;
use sea_orm::QueryOrder;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set, TransactionTrait,
};
use std::str::FromStr;
use thiserror::Error;
//
// ────────────────────── USER FUNCTIONS ──────────────────────
//

pub async fn get_user(
    ctx: &PersistCtx,
    user_address: String,
) -> anyhow::Result<Option<user::Model>> {
    Ok(user::Entity::find()
        .filter(user::Column::Address.eq(user_address))
        .one(&*ctx.db)
        .await?)
}

//
// ────────────────────── COLLATERAL EVENTS ──────────────────────
//

/// Deposit: increment collateral and record a CollateralEvent::Deposit for auditability.
pub async fn deposit(ctx: &PersistCtx, user_address: String, amount: U256) -> anyhow::Result<()> {
    use sea_orm::ActiveValue::Set;
    let now = Utc::now().naive_utc();

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                // Try to fetch existing user
                if let Some(mut user) = user::Entity::find()
                    .filter(user::Column::Address.eq(user_address.clone()))
                    .one(txn)
                    .await?
                {
                    // Already exists → update
                    let current = U256::from_str(&user.collateral).map_err(|e| {
                        sea_orm::DbErr::Custom(format!("invalid collateral value: {e}"))
                    })?;

                    let new_collateral = current
                        .checked_add(amount)
                        .ok_or(sea_orm::DbErr::Custom("overflow".to_string()))?;

                    user.collateral = new_collateral.to_string();
                    user.updated_at = now;

                    let mut active_model = user.into_active_model();
                    active_model.collateral = Set(new_collateral.to_string());
                    active_model.updated_at = Set(now);
                    active_model.update(txn).await?;
                } else {
                    // First time → insert
                    let insert_user = user::ActiveModel {
                        address: Set(user_address.clone()),
                        revenue: Set(U256::from(0).to_string()),
                        version: Set(0),
                        created_at: Set(now),
                        updated_at: Set(now),
                        collateral: Set(amount.to_string()),
                        locked_collateral: Set(U256::from(0).to_string()),
                    };
                    user::Entity::insert(insert_user).exec(txn).await?;
                }

                // Insert collateral event (even for 0 deposits if you want to log them)
                if amount > U256::from(0) {
                    let ev = collateral_event::ActiveModel {
                        id: Set(uuid::Uuid::new_v4().to_string()),
                        user_address: Set(user_address),
                        amount: Set(amount.to_string()),
                        event_type: Set(CollateralEventType::Deposit),
                        tab_id: Set(None),
                        req_id: Set(None),
                        tx_id: Set(None),
                        created_at: Set(now),
                    };
                    collateral_event::Entity::insert(ev).exec(txn).await?;
                }

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
    user_address: String,
    when: i64,
    amount: U256,
) -> Result<()> {
    // Ensure user exists and has enough collateral
    let Some(u) = user::Entity::find()
        .filter(user::Column::Address.eq(user_address.clone()))
        .one(&*ctx.db)
        .await?
    else {
        return Err(anyhow::anyhow!("user not found"));
    };

    let user_collateral = U256::from_str(&u.collateral)
        .map_err(|e| anyhow::anyhow!("invalid collateral value: {}", e))?;
    if amount > user_collateral {
        return Err(anyhow::anyhow!("insufficient collateral"));
    }

    let now = Utc::now().naive_utc();
    let ts = Utc
        .timestamp_opt(when, 0)
        .single()
        .ok_or_else(|| anyhow::anyhow!("invalid timestamp: {}", when))?
        .naive_utc();

    let active_model = withdrawal::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        user_address: Set(user_address),
        requested_amount: Set(amount.to_string()),
        executed_amount: Set("0".to_string()),
        ts: Set(ts),
        status: Set(WithdrawalStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
    };
    withdrawal::Entity::insert(active_model)
        .exec(&*ctx.db)
        .await?;
    Ok(())
}

pub async fn cancel_withdrawal(ctx: &PersistCtx, user_address: String) -> Result<()> {
    let records = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_address.clone()))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .all(&*ctx.db)
        .await?;

    match records.len() {
        0 => {
            return Ok(());
        }
        1 => {
            let rec = records.into_iter().next().unwrap();
            let mut active_model = rec.into_active_model();
            active_model.status = Set(WithdrawalStatus::Cancelled);
            active_model.updated_at = Set(Utc::now().naive_utc());
            active_model.update(&*ctx.db).await?;
        }
        n => {
            error!(
                "Expected exactly one pending withdrawal for user {}, but found {}",
                user_address, n
            );
        }
    }

    Ok(())
}

pub async fn finalize_withdrawal(
    ctx: &PersistCtx,
    user_address: String,
    executed_amount: U256,
) -> anyhow::Result<()> {
    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let user = user::Entity::find()
                    .filter(user::Column::Address.eq(user_address.clone()))
                    .one(txn)
                    .await?
                    .ok_or(sea_orm::DbErr::Custom("user not found".into()))?;

                if let Some(withdrawal) = withdrawal::Entity::find()
                    .filter(withdrawal::Column::UserAddress.eq(user_address.clone()))
                    .filter(
                        withdrawal::Column::Status
                            .is_in(vec![WithdrawalStatus::Pending, WithdrawalStatus::Cancelled]),
                    )
                    .order_by_desc(withdrawal::Column::CreatedAt)
                    .one(txn)
                    .await?
                {
                    // subtract only the executed amount
                    let current = U256::from_str(&user.collateral)
                        .map_err(|e| sea_orm::DbErr::Custom(format!("invalid collateral: {e}")))?;
                    let new_collateral = current
                        .checked_sub(executed_amount)
                        .ok_or(sea_orm::DbErr::Custom("underflow on withdrawal".into()))?;

                    let mut am_user = user.into_active_model();
                    am_user.collateral = Set(new_collateral.to_string());
                    am_user.updated_at = Set(Utc::now().naive_utc());
                    am_user.update(txn).await?;

                    // record executed amount
                    let mut active_model_withdrawal = withdrawal.into_active_model();
                    active_model_withdrawal.status = Set(WithdrawalStatus::Executed);
                    active_model_withdrawal.executed_amount = Set(executed_amount.to_string());
                    active_model_withdrawal.updated_at = Set(Utc::now().naive_utc());
                    active_model_withdrawal.update(txn).await?;
                }

                Ok::<_, sea_orm::DbErr>(())
            })
        })
        .await?;

    Ok(())
}

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
    user_address: String,
    recipient_address: String,
    transaction_id: String,
    amount: U256,
    cert: String,
) -> Result<(), SubmitPaymentTxnError> {
    ctx.db
        .transaction::<_, (), SubmitPaymentTxnError>(|txn| {
            Box::pin(async move {
                // Ensure the user exists
                let Some(user_row) = user::Entity::find()
                    .filter(user::Column::Address.eq(user_address.clone()))
                    .one(txn)
                    .await?
                else {
                    return Err(SubmitPaymentTxnError::UserNotRegistered);
                };

                // Reserve deposit for other unfinalized txs
                let pending = user_transaction::Entity::find()
                    .filter(user_transaction::Column::UserAddress.eq(user_address.clone()))
                    .filter(user_transaction::Column::Finalized.eq(false))
                    .filter(user_transaction::Column::TxId.ne(transaction_id.clone()))
                    .all(txn)
                    .await?;
                let locked_deposit: U256 = pending
                    .iter()
                    .map(|tx| U256::from_str(&tx.amount).unwrap_or(U256::from(0)))
                    .fold(U256::from(0), |acc, x| acc.saturating_add(x));

                let user_collateral = U256::from_str(&user_row.collateral).map_err(|_| {
                    SubmitPaymentTxnError::Db(sea_orm::DbErr::Custom(
                        "invalid collateral value".to_string(),
                    ))
                })?;
                if locked_deposit.saturating_add(amount) > user_collateral {
                    return Err(SubmitPaymentTxnError::NotEnoughDeposit);
                }
                let now = Utc::now().naive_utc();
                let tx_active_model = user_transaction::ActiveModel {
                    tx_id: Set(transaction_id.clone()),
                    user_address: Set(user_address.clone()),
                    recipient_address: Set(recipient_address),
                    amount: Set(amount.to_string()),
                    cert: Set(Some(cert)),
                    verified: Set(false),
                    finalized: Set(false),
                    failed: Set(false),
                    created_at: Set(now),
                    updated_at: Set(now),
                };

                // Important: use exec_without_returning so duplicate inserts are no-op
                let _ = user_transaction::Entity::insert(tx_active_model)
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
                    .filter(user::Column::Address.eq(user_address.clone()))
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
    user_address: String,
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

                // mark as failed + finalized
                let mut active_model = tx_row.clone().into_active_model();
                active_model.finalized = Set(true);
                active_model.failed = Set(true);
                active_model.updated_at = Set(Utc::now().naive_utc());
                active_model.update(txn).await?;

                // subtract collateral only once
                let user_row = user::Entity::find()
                    .filter(user::Column::Address.eq(user_address.clone()))
                    .one(txn)
                    .await?
                    .ok_or(sea_orm::DbErr::Custom("user not found".into()))?;

                let current = U256::from_str(&user_row.collateral).map_err(|e| {
                    sea_orm::DbErr::Custom(format!("invalid collateral value: {e}"))
                })?;
                let delta = U256::from_str(&tx_row.amount)
                    .map_err(|e| sea_orm::DbErr::Custom(format!("invalid tx amount: {e}")))?;
                let new_collateral = current.checked_sub(delta).ok_or(sea_orm::DbErr::Custom(
                    "underflow on fail_transaction".into(),
                ))?;

                let mut user_active_model = user_row.into_active_model();
                user_active_model.collateral = Set(new_collateral.to_string());
                user_active_model.updated_at = Set(Utc::now().naive_utc());
                user_active_model.update(txn).await?;

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

                let mut active_model = tx.into_active_model();
                active_model.verified = Set(true);
                active_model.updated_at = Set(Utc::now().naive_utc());
                active_model.update(txn).await?;

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
    req_id: String,
    from_addr: String,
    to_addr: String,
    value: U256,
    start_ts: chrono::NaiveDateTime,
    cert: String,
) -> anyhow::Result<()> {
    let now = Utc::now().naive_utc();

    // Ensure foreign keys exist
    for addr in [&from_addr, &to_addr] {
        let insert_user = user::ActiveModel {
            address: Set(addr.clone()),
            revenue: Set(value.to_string()),
            version: Set(0),
            created_at: Set(now),
            updated_at: Set(now),
            collateral: Set("0".to_string()),
            locked_collateral: Set("0".to_string()),
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

    let active_model = guarantee::ActiveModel {
        tab_id: Set(tab_id),
        req_id: Set(req_id),
        from_address: Set(from_addr),
        to_address: Set(to_addr),
        value: Set(value.to_string()),
        start_ts: Set(start_ts),
        cert: Set(Some(cert)),
        created_at: Set(now),
        updated_at: Set(now),
    };

    // Use exec_without_returning to avoid "RecordNotInserted"
    let _ = guarantee::Entity::insert(active_model)
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
    req_id: String,
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

pub async fn remunerate_recipient(ctx: &PersistCtx, tab_id: String, amount: U256) -> Result<()> {
    let now = Utc::now().naive_utc();

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                // ── 1️⃣ Locate the tab (gives us the user address)
                let tab = entities::tabs::Entity::find_by_id(tab_id.clone())
                    .one(txn)
                    .await?
                    .ok_or_else(|| sea_orm::DbErr::Custom(format!("Tab not found: {tab_id}")))?;

                // ── 2️⃣ Idempotency: if this tab already has a Remunerate event → exit
                let existing = collateral_event::Entity::find()
                    .filter(collateral_event::Column::TabId.eq(tab_id.clone()))
                    .filter(
                        collateral_event::Column::EventType
                            .eq(entities::sea_orm_active_enums::CollateralEventType::Remunerate),
                    )
                    .one(txn)
                    .await?;

                if existing.is_some() {
                    return Ok::<_, sea_orm::DbErr>(());
                }

                // ── 3️⃣ Try to decrement the user’s collateral only if possible
                if let Some(user_row) = user::Entity::find()
                    .filter(user::Column::Address.eq(tab.user_address.clone()))
                    .one(txn)
                    .await?
                {
                    let current = U256::from_str(&user_row.collateral).map_err(|e| {
                        sea_orm::DbErr::Custom(format!("Invalid collateral value: {e}"))
                    })?;

                    // subtract only if there is enough; otherwise leave as is
                    if current >= amount {
                        let new_collateral = current - amount;
                        let mut user_active_model = user_row.into_active_model();
                        user_active_model.collateral = Set(new_collateral.to_string());
                        user_active_model.updated_at = Set(now);
                        user_active_model.update(txn).await?;
                    }
                }

                // ── 4️⃣ Always record the remuneration event
                let ev = collateral_event::ActiveModel {
                    id: Set(uuid::Uuid::new_v4().to_string()),
                    user_address: Set(tab.user_address),
                    amount: Set(amount.to_string()),
                    event_type: Set(
                        entities::sea_orm_active_enums::CollateralEventType::Remunerate,
                    ),
                    tab_id: Set(Some(tab_id)),
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
