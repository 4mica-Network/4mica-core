use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use alloy::primitives::U256;
use chrono::{TimeZone, Utc};
use entities::{
    collateral_event, guarantee,
    sea_orm_active_enums::{CollateralEventType, WithdrawalStatus},
    user, user_transaction, withdrawal,
};
use sea_orm::QueryOrder;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set, TransactionTrait,
};
use std::str::FromStr;

//
// ────────────────────── USER FUNCTIONS ──────────────────────
//

pub async fn get_user(ctx: &PersistCtx, user_address: &str) -> Result<user::Model, PersistDbError> {
    user::Entity::find_by_id(user_address)
        .one(&*ctx.db)
        .await?
        .ok_or_else(|| PersistDbError::UserNotFound(user_address.to_owned()))
}

use sea_orm::ConnectionTrait;

pub async fn get_user_on<C: ConnectionTrait>(
    conn: &C,
    user_address: &str,
) -> Result<user::Model, PersistDbError> {
    user::Entity::find()
        .filter(user::Column::Address.eq(user_address))
        .one(conn)
        .await?
        .ok_or_else(|| PersistDbError::UserNotFound(user_address.to_owned()))
}

//
// ────────────────────── COLLATERAL EVENTS ──────────────────────
//

/// Deposit: increment collateral and record a CollateralEvent::Deposit for auditability.
pub async fn deposit(
    ctx: &PersistCtx,
    user_address: String,
    amount: U256,
) -> Result<(), PersistDbError> {
    use sea_orm::ActiveValue::Set as AvSet;
    let now = Utc::now().naive_utc();

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                // 🔒 Must exist
                let mut u = get_user_on(txn, &user_address).await?;

                let current = U256::from_str(&u.collateral)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                let new_collateral = current.checked_add(amount).ok_or_else(|| {
                    PersistDbError::DatabaseFailure(sea_orm::DbErr::Custom("overflow".to_string()))
                })?;

                u.collateral = new_collateral.to_string();
                u.updated_at = now;

                let mut active_model = u.into_active_model();
                active_model.collateral = AvSet(new_collateral.to_string());
                active_model.updated_at = AvSet(now);
                active_model.update(txn).await?;

                // Record the deposit event (0-amount still recorded if desired)
                if amount > U256::ZERO {
                    let ev = collateral_event::ActiveModel {
                        id: AvSet(uuid::Uuid::new_v4().to_string()),
                        user_address: AvSet(user_address),
                        amount: AvSet(amount.to_string()),
                        event_type: AvSet(CollateralEventType::Deposit),
                        tab_id: AvSet(None),
                        req_id: AvSet(None),
                        tx_id: AvSet(None),
                        created_at: AvSet(now),
                    };
                    collateral_event::Entity::insert(ev).exec(txn).await?;
                }

                Ok::<_, PersistDbError>(())
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
) -> Result<(), PersistDbError> {
    // Ensure user exists and has enough collateral
    let u = get_user_on(&*ctx.db, &user_address).await?;

    let user_collateral = U256::from_str(&u.collateral)
        .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
    if amount > user_collateral {
        return Err(PersistDbError::InsufficientCollateral);
    }

    let now = Utc::now().naive_utc();
    let ts = Utc
        .timestamp_opt(when, 0)
        .single()
        .ok_or_else(|| PersistDbError::InvalidTimestamp(when))?
        .naive_utc();

    let withdrawal_model = withdrawal::ActiveModel {
        id: Set(uuid::Uuid::new_v4().to_string()),
        user_address: Set(user_address),
        requested_amount: Set(amount.to_string()),
        executed_amount: Set("0".to_string()),
        request_ts: Set(ts),
        status: Set(WithdrawalStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
    };
    withdrawal::Entity::insert(withdrawal_model)
        .exec(&*ctx.db)
        .await?;
    Ok(())
}

pub async fn cancel_withdrawal(
    ctx: &PersistCtx,
    user_address: String,
) -> Result<(), PersistDbError> {
    let records = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_address.clone()))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .all(&*ctx.db)
        .await?;

    match records.len() {
        0 => Ok(()),
        1 => {
            let rec = records.into_iter().next().unwrap();
            let mut active_model = rec.into_active_model();
            active_model.status = Set(WithdrawalStatus::Cancelled);
            active_model.updated_at = Set(Utc::now().naive_utc());
            active_model.update(&*ctx.db).await?;
            Ok(())
        }
        n => Err(PersistDbError::MultiplePendingWithdrawals {
            user: user_address,
            count: n,
        }),
    }
}

pub async fn finalize_withdrawal(
    ctx: &PersistCtx,
    user_address: String,
    executed_amount: U256,
) -> Result<(), PersistDbError> {
    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let user = get_user_on(txn, &user_address).await?;

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
                        .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                    if executed_amount > current {
                        return Err(PersistDbError::InsufficientCollateral);
                    }
                    let new_collateral = current - executed_amount;

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

                Ok::<_, PersistDbError>(())
            })
        })
        .await?;

    Ok(())
}

// ────────────────────── TRANSACTIONS ──────────────────────
//

pub async fn submit_payment_transaction(
    ctx: &PersistCtx,
    user_address: String,
    recipient_address: String,
    transaction_id: String,
    amount: U256,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();

    // Ensure user row exists (strict)
    let _ = get_user_on(&*ctx.db, &user_address).await?;

    let tx = user_transaction::ActiveModel {
        tx_id: Set(transaction_id),
        user_address: Set(user_address),
        recipient_address: Set(recipient_address),
        amount: Set(amount.to_string()),
        verified: Set(false),
        finalized: Set(false),
        failed: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };

    // Duplicate tx_id → no-op
    user_transaction::Entity::insert(tx)
        .on_conflict(
            OnConflict::column(user_transaction::Column::TxId)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&*ctx.db)
        .await?;

    Ok(())
}

pub async fn fail_transaction(
    ctx: &PersistCtx,
    user_address: String,
    transaction_id: String,
) -> Result<(), PersistDbError> {
    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let tx_row = match user_transaction::Entity::find_by_id(transaction_id.clone())
                    .one(txn)
                    .await?
                {
                    Some(row) => row,
                    None => {
                        // ← Proper domain error instead of silent success
                        return Err(PersistDbError::TransactionNotFound(transaction_id));
                    }
                };

                if tx_row.user_address != user_address {
                    return Err(PersistDbError::UserNotFound(user_address));
                    // or define a dedicated TransactionUserMismatch(...) error
                }

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

                // subtract collateral only once (strict fetch)
                let user_row = get_user_on(txn, &user_address).await?;

                let current = U256::from_str(&user_row.collateral)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let delta = U256::from_str(&tx_row.amount)
                    .map_err(|e| PersistDbError::InvalidTxAmount(e.to_string()))?;

                if delta > current {
                    return Err(PersistDbError::InsufficientCollateral);
                }
                let new_collateral = current - delta;

                let mut user_active_model = user_row.into_active_model();
                user_active_model.collateral = Set(new_collateral.to_string());
                user_active_model.updated_at = Set(Utc::now().naive_utc());
                user_active_model.update(txn).await?;

                Ok::<_, PersistDbError>(())
            })
        })
        .await?;

    Ok(())
}

//
// ────────────────────── TRANSACTION QUERIES ──────────────────────
//

pub async fn get_transactions_by_hash(
    ctx: &PersistCtx,
    hashes: Vec<String>,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.is_in(hashes))
        .all(&*ctx.db)
        .await?;
    Ok(rows)
}

pub async fn get_unfinalized_transactions(
    ctx: &PersistCtx,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::Finalized.eq(false))
        .all(&*ctx.db)
        .await?;
    Ok(rows)
}

//
// ────────────────────── GUARANTEES / CERTIFICATES ──────────────────────
//

pub async fn store_guarantee(
    ctx: &PersistCtx,
    tab_id: String,
    req_id: String,
    from_addr: String,
    to_addr: String,
    value: U256,
    start_ts: chrono::NaiveDateTime,
    cert: String,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();

    // Ensure foreign keys exist
    for addr in [&from_addr, &to_addr] {
        let insert_user = user::ActiveModel {
            address: Set(addr.clone()),
            version: Set(0),
            created_at: Set(now),
            updated_at: Set(now),
            collateral: Set("0".to_string()),
            locked_collateral: Set("0".to_string()),
        };
        user::Entity::insert(insert_user)
            .on_conflict(
                OnConflict::column(user::Column::Address)
                    .do_nothing()
                    .to_owned(),
            )
            .exec_without_returning(&*ctx.db)
            .await?;
    }

    let active_model = guarantee::ActiveModel {
        tab_id: Set(tab_id),
        req_id: Set(req_id),
        from_address: Set(from_addr),
        to_address: Set(to_addr),
        value: Set(value.to_string()),
        start_ts: Set(start_ts),
        cert: Set(cert),
        created_at: Set(now),
        updated_at: Set(now),
    };

    // Use exec_without_returning to avoid "RecordNotInserted"
    guarantee::Entity::insert(active_model)
        .on_conflict(
            OnConflict::columns([guarantee::Column::TabId, guarantee::Column::ReqId])
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&*ctx.db)
        .await?;

    Ok(())
}

pub async fn get_guarantee(
    ctx: &PersistCtx,
    tab_id: String,
    req_id: String,
) -> Result<Option<guarantee::Model>, PersistDbError> {
    let res = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(tab_id))
        .filter(guarantee::Column::ReqId.eq(req_id))
        .one(&*ctx.db)
        .await?;
    Ok(res)
}

//
// ────────────────────── REMUNERATION / PAYMENTS ──────────────────────
//

/// Remunerate the recipient for a tab.
pub async fn remunerate_recipient(
    ctx: &PersistCtx,
    tab_id: String,
    amount: U256,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                // 1) Locate tab (strict)
                let tab = entities::tabs::Entity::find_by_id(tab_id.clone())
                    .one(txn)
                    .await?
                    .ok_or_else(|| PersistDbError::TabNotFound(tab_id.clone()))?;

                // 2) Idempotency: if a Remunerate event already exists → exit early
                let existing = collateral_event::Entity::find()
                    .filter(collateral_event::Column::TabId.eq(tab_id.clone()))
                    .filter(collateral_event::Column::EventType.eq(CollateralEventType::Remunerate))
                    .one(txn)
                    .await?;
                if existing.is_some() {
                    return Ok::<_, PersistDbError>(());
                }

                // 3) User must exist AND have sufficient collateral
                let user_row = get_user_on(txn, &tab.user_address).await?;
                let current = U256::from_str(&user_row.collateral)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                if current < amount {
                    return Err(PersistDbError::InsufficientCollateral);
                }

                let new_collateral = current - amount;
                let mut user_active_model = user_row.into_active_model();
                user_active_model.collateral = Set(new_collateral.to_string());
                user_active_model.updated_at = Set(now);
                user_active_model.update(txn).await?;

                // 4) Record the remuneration event
                let ev = collateral_event::ActiveModel {
                    id: Set(uuid::Uuid::new_v4().to_string()),
                    user_address: Set(tab.user_address),
                    amount: Set(amount.to_string()),
                    event_type: Set(CollateralEventType::Remunerate),
                    tab_id: Set(Some(tab_id)),
                    req_id: Set(None),
                    tx_id: Set(None),
                    created_at: Set(now),
                };
                collateral_event::Entity::insert(ev).exec(txn).await?;

                Ok::<_, PersistDbError>(())
            })
        })
        .await?;

    Ok(())
}

// ────────────────────── EXTRA HELPERS FOR SERVICE ──────────────────────

/// Fetch user transactions for a user (optionally only unfinalized)
pub async fn get_user_transactions(
    ctx: &PersistCtx,
    user_address: &str,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::UserAddress.eq(user_address))
        .all(&*ctx.db)
        .await?;
    Ok(rows)
}

/// Fetch unfinalized transactions for a user
pub async fn get_unfinalized_transactions_for_user(
    ctx: &PersistCtx,
    user_address: &str,
    exclude_tx_id: Option<&str>,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let mut query = user_transaction::Entity::find()
        .filter(user_transaction::Column::UserAddress.eq(user_address))
        .filter(user_transaction::Column::Finalized.eq(false));

    if let Some(exclude) = exclude_tx_id {
        query = query.filter(user_transaction::Column::TxId.ne(exclude));
    }

    let rows = query.all(&*ctx.db).await?;
    Ok(rows)
}

/// Fetch pending withdrawals for a user
pub async fn get_pending_withdrawals_for_user(
    ctx: &PersistCtx,
    user_address: &str,
) -> Result<Vec<withdrawal::Model>, PersistDbError> {
    let rows = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_address))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .all(&*ctx.db)
        .await?;
    Ok(rows)
}

/// Optimistic version bump – returns true if bumped, false if conflict
pub async fn bump_user_version(
    ctx: &PersistCtx,
    user_address: &str,
    current_version: i32,
) -> Result<bool, PersistDbError> {
    use sea_orm::sea_query::Expr;
    let now = chrono::Utc::now().naive_utc();
    let res = user::Entity::update_many()
        .col_expr(
            user::Column::Version,
            Expr::col(user::Column::Version).add(1),
        )
        .col_expr(user::Column::UpdatedAt, Expr::value(now))
        .filter(user::Column::Address.eq(user_address))
        .filter(user::Column::Version.eq(current_version))
        .exec(&*ctx.db)
        .await?;
    Ok(res.rows_affected == 1)
}

/// Get a single tab by id
pub async fn get_tab_by_id(
    ctx: &PersistCtx,
    tab_id: &str,
) -> Result<Option<entities::tabs::Model>, PersistDbError> {
    let res = entities::tabs::Entity::find_by_id(tab_id.to_string())
        .one(&*ctx.db)
        .await?;
    Ok(res)
}

/// Check if a Remunerate event already exists for a tab
pub async fn has_remunerate_event_for_tab(
    ctx: &PersistCtx,
    tab_id: &str,
) -> Result<bool, PersistDbError> {
    let existing = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(tab_id))
        .filter(collateral_event::Column::EventType.eq(CollateralEventType::Remunerate))
        .one(&*ctx.db)
        .await?;
    Ok(existing.is_some())
}

pub async fn update_user_lock_and_version(
    ctx: &PersistCtx,
    user_address: &str,
    current_version: i32,
    new_locked: U256,
) -> Result<bool, PersistDbError> {
    use sea_orm::sea_query::Expr;
    let now = chrono::Utc::now().naive_utc();

    let res = user::Entity::update_many()
        .col_expr(
            user::Column::Version,
            Expr::col(user::Column::Version).add(1),
        )
        .col_expr(
            user::Column::LockedCollateral,
            Expr::value(new_locked.to_string()),
        )
        .col_expr(user::Column::UpdatedAt, Expr::value(now))
        .filter(user::Column::Address.eq(user_address))
        .filter(user::Column::Version.eq(current_version))
        .exec(&*ctx.db)
        .await?;

    Ok(res.rows_affected == 1)
}
