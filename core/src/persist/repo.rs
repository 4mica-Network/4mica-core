use crate::error::PersistDbError;
use crate::persist::PersistCtx;
use alloy::primitives::U256;
use chrono::{TimeZone, Utc};
use entities::sea_orm_active_enums::SettlementStatus;
use entities::{
    collateral_event, guarantee,
    sea_orm_active_enums::{CollateralEventType, WithdrawalStatus},
    user, user_transaction, withdrawal,
};
use sea_orm::ConnectionTrait;
use sea_orm::QueryOrder;
use std::str::FromStr;

use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set, TransactionTrait,
};
//
// ────────────────────── USER FUNCTIONS ──────────────────────
//

pub async fn get_user(ctx: &PersistCtx, user_address: &str) -> Result<user::Model, PersistDbError> {
    user::Entity::find_by_id(user_address)
        .one(ctx.db.as_ref())
        .await?
        .ok_or_else(|| PersistDbError::UserNotFound(user_address.to_owned()))
}

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

async fn ensure_user_exists_on<C: ConnectionTrait>(
    conn: &C,
    addr: &str,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();
    let insert_user = user::ActiveModel {
        address: Set(addr.to_owned()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        collateral: Set("0".to_string()),
        locked_collateral: Set("0".to_string()),
    };

    // Idempotent insert; avoids "RecordNotInserted" on DO NOTHING
    user::Entity::insert(insert_user)
        .on_conflict(
            OnConflict::column(user::Column::Address)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await?;

    Ok(())
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

                let current_collateral = U256::from_str(&u.collateral)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                let new_collateral = current_collateral.checked_add(amount).ok_or_else(|| {
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
    let u = get_user_on(ctx.db.as_ref(), &user_address).await?;

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
        .exec(ctx.db.as_ref())
        .await?;
    Ok(())
}

pub async fn cancel_withdrawal(
    ctx: &PersistCtx,
    user_address: String,
) -> Result<(), PersistDbError> {
    match withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_address.clone()))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .one(ctx.db.as_ref())
        .await?
    {
        Some(rec) => {
            let mut active_model = rec.into_active_model();
            active_model.status = Set(WithdrawalStatus::Cancelled);
            active_model.updated_at = Set(Utc::now().naive_utc());
            active_model.update(ctx.db.as_ref()).await?;
            Ok(())
        }
        None => Ok(()),
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
                let now = Utc::now().naive_utc();

                // strict user fetch
                let user = get_user_on(txn, &user_address).await?;
                let current_collateral = U256::from_str(&user.collateral)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                // most recent Pending withdrawal; if none => error
                let withdrawal = withdrawal::Entity::find()
                    .filter(withdrawal::Column::UserAddress.eq(&user_address))
                    .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
                    .order_by_desc(withdrawal::Column::CreatedAt)
                    .one(txn)
                    .await?
                    .ok_or(PersistDbError::WithdrawalNotFound {
                        user: user_address.clone(),
                    })?;

                // ensure we never execute more than requested
                let requested = U256::from_str(&withdrawal.requested_amount)
                    .map_err(|e| PersistDbError::InvalidTxAmount(e.to_string()))?;
                if executed_amount > requested {
                    return Err(PersistDbError::InvalidTxAmount(
                        "executed_amount exceeds requested_amount".into(),
                    ));
                }

                if executed_amount > current_collateral {
                    return Err(PersistDbError::InsufficientCollateral);
                }

                // update user balance
                let new_collateral = current_collateral - executed_amount;
                let mut am_user = user.into_active_model();
                am_user.collateral = Set(new_collateral.to_string());
                am_user.updated_at = Set(now);
                am_user.update(txn).await?;

                // mark withdrawal executed
                let mut am_w = withdrawal.into_active_model();
                am_w.status = Set(WithdrawalStatus::Executed);
                am_w.executed_amount = Set(executed_amount.to_string());
                am_w.updated_at = Set(now);
                am_w.update(txn).await?;

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
    let _ = get_user_on(ctx.db.as_ref(), &user_address).await?;

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
        .exec_without_returning(ctx.db.as_ref())
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

                let current_collateral = U256::from_str(&user_row.collateral)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let delta = U256::from_str(&tx_row.amount)
                    .map_err(|e| PersistDbError::InvalidTxAmount(e.to_string()))?;

                if delta > current_collateral {
                    return Err(PersistDbError::InsufficientCollateral);
                }
                let new_collateral = current_collateral - delta;

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

    // Ensure foreign keys exist (idempotent, race-safe)
    ensure_user_exists_on(ctx.db.as_ref(), &from_addr).await?;
    ensure_user_exists_on(ctx.db.as_ref(), &to_addr).await?;

    let active_model = guarantee::ActiveModel {
        tab_id: Set(tab_id.clone()),
        req_id: Set(req_id),
        from_address: Set(from_addr),
        to_address: Set(to_addr),
        value: Set(value.to_string()),
        start_ts: Set(start_ts),
        cert: Set(cert),
        created_at: Set(now),
        updated_at: Set(now),
    };

    guarantee::Entity::insert(active_model)
        .on_conflict(
            OnConflict::columns([guarantee::Column::TabId, guarantee::Column::ReqId])
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(ctx.db.as_ref())
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
        .one(ctx.db.as_ref())
        .await?;
    Ok(res)
}

//
// ────────────────────── REMUNERATION / PAYMENTS ──────────────────────
//

pub async fn remunerate_recipient(
    ctx: &PersistCtx,
    tab_id: String,
    amount: U256,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                // strict fetch (same txn)
                let tab = get_tab_by_id_on(txn, &tab_id).await?;

                // Compare-and-set using typed `.set(ActiveModel { ... })`
                let cas = entities::tabs::Entity::update_many()
                    .filter(entities::tabs::Column::Id.eq(tab_id.clone()))
                    .filter(entities::tabs::Column::SettlementStatus.ne(SettlementStatus::Settled))
                    .set(entities::tabs::ActiveModel {
                        settlement_status: Set(SettlementStatus::Settled),
                        updated_at: Set(now),
                        ..Default::default()
                    })
                    .exec(txn)
                    .await?;

                if cas.rows_affected == 0 {
                    // already settled → idempotent no-op
                    return Ok::<_, PersistDbError>(());
                }

                // debit if needed
                let user_row = get_user_on(txn, &tab.user_address).await?;
                let current_collateral = U256::from_str(&user_row.collateral)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                if current_collateral < amount {
                    // whole txn rolls back (CAS included)
                    return Err(PersistDbError::InsufficientCollateral);
                }
                if amount > U256::ZERO {
                    let mut user_am = user_row.into_active_model();
                    user_am.collateral = Set((current_collateral - amount).to_string());
                    user_am.updated_at = Set(now);
                    user_am.update(txn).await?;
                }

                // audit event
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
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

/// Return the most recent guarantee for a tab (by created_at DESC)
pub async fn get_last_guarantee_for_tab(
    ctx: &PersistCtx,
    tab_id: &str,
) -> Result<Option<guarantee::Model>, PersistDbError> {
    let row = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(tab_id))
        .order_by_desc(guarantee::Column::CreatedAt)
        .one(ctx.db.as_ref())
        .await?;
    Ok(row)
}

/// Read TTL (in seconds) from `tabs.ttl`. Returns Err(TabNotFound) if the tab doesn't exist.
pub async fn get_tab_ttl_seconds(ctx: &PersistCtx, tab_id: &str) -> Result<u64, PersistDbError> {
    let tab = entities::tabs::Entity::find_by_id(tab_id.to_string())
        .one(ctx.db.as_ref())
        .await?
        .ok_or_else(|| PersistDbError::TabNotFound(tab_id.to_owned()))?;

    let ttl = tab.ttl as u64;
    Ok(ttl)
}

/// Fetch unfinalized transactions for a user
pub async fn get_unfinalized_transactions_for_user(
    ctx: &PersistCtx,
    user_address: &str,
    exclude_tx_id: Option<&str>,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let exclude =
        exclude_tx_id.ok_or_else(|| PersistDbError::TransactionNotFound("None".to_string()))?;

    let rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::UserAddress.eq(user_address))
        .filter(user_transaction::Column::Finalized.eq(false))
        .filter(user_transaction::Column::TxId.ne(exclude))
        .all(ctx.db.as_ref())
        .await?;

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
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

/// Optimistic version bump – returns true if bumped, false if conflict
/// Atomically bump the user's version if `current_version` matches.
/// Returns `Ok(())` on success; `Err(PersistDbError::OptimisticLockConflict{..})` if stale.
pub async fn bump_user_version(
    ctx: &PersistCtx,
    user_address: &str,
    current_version: i32,
) -> Result<(), PersistDbError> {
    use chrono::Utc;
    use sea_orm::sea_query::Expr;

    let now = Utc::now().naive_utc();

    let res = user::Entity::update_many()
        // Prefer filters first for readability; SQL is identical
        .filter(user::Column::Address.eq(user_address))
        .filter(user::Column::Version.eq(current_version))
        // Atomic increment + timestamp
        .col_expr(
            user::Column::Version,
            Expr::col(user::Column::Version).add(1),
        )
        .col_expr(user::Column::UpdatedAt, Expr::value(now))
        .exec(ctx.db.as_ref())
        .await?;

    match res.rows_affected {
        1 => Ok(()),
        0 => Err(PersistDbError::OptimisticLockConflict {
            user: user_address.to_owned(),
            expected_version: current_version,
        }),
        n => Err(PersistDbError::InvariantViolation(format!(
            "bump_user_version updated {} rows for address {}",
            n, user_address
        ))),
    }
}

/// Get a single tab by id
pub async fn get_tab_by_id(
    ctx: &PersistCtx,
    tab_id: &str,
) -> Result<Option<entities::tabs::Model>, PersistDbError> {
    let res = entities::tabs::Entity::find_by_id(tab_id.to_string())
        .one(ctx.db.as_ref())
        .await?;
    Ok(res)
}

pub async fn get_tab_by_id_on<C: ConnectionTrait>(
    conn: &C,
    tab_id: &str,
) -> Result<entities::tabs::Model, PersistDbError> {
    entities::tabs::Entity::find_by_id(tab_id.to_string())
        .one(conn)
        .await?
        .ok_or_else(|| PersistDbError::TabNotFound(tab_id.to_owned()))
}

/// Check if a Remunerate event already exists for a tab
pub async fn ensure_remunerate_event_for_tab(
    ctx: &PersistCtx,
    tab_id: &str,
) -> Result<(), PersistDbError> {
    use sea_orm::QuerySelect;

    let some_id = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(tab_id))
        .filter(collateral_event::Column::EventType.eq(CollateralEventType::Remunerate))
        .select_only()
        .column(collateral_event::Column::Id)
        .limit(1)
        .into_tuple::<String>()
        .one(ctx.db.as_ref())
        .await?;

    match some_id {
        Some(_) => Ok(()),
        None => Err(PersistDbError::RemunerateEventNotFound(tab_id.to_owned())),
    }
}
/// Optimistic lock + version bump for `locked_collateral`.
/// Atomically sets `LockedCollateral` to `new_locked` and bumps the user's version
/// if `current_version` matches.
/// Returns `Ok(())` on success; `Err(PersistDbError::OptimisticLockConflict{..})` if stale.
pub async fn update_user_lock_and_version(
    ctx: &PersistCtx,
    user_address: &str,
    current_version: i32,
    new_locked: U256,
) -> Result<(), PersistDbError> {
    use chrono::Utc;
    use sea_orm::sea_query::Expr;

    let now = Utc::now().naive_utc();

    let res = user::Entity::update_many()
        // Prefer filters first for readability; SQL is identical
        .filter(user::Column::Address.eq(user_address))
        .filter(user::Column::Version.eq(current_version))
        // Atomic increment + field write + timestamp
        .col_expr(
            user::Column::Version,
            Expr::col(user::Column::Version).add(1),
        )
        .col_expr(
            user::Column::LockedCollateral,
            Expr::value(new_locked.to_string()),
        )
        .col_expr(user::Column::UpdatedAt, Expr::value(now))
        .exec(ctx.db.as_ref())
        .await?;

    match res.rows_affected {
        1 => Ok(()),
        0 => Err(PersistDbError::OptimisticLockConflict {
            user: user_address.to_owned(),
            expected_version: current_version,
        }),
        n => Err(PersistDbError::InvariantViolation(format!(
            "update_user_lock_and_version updated {} rows for address {}",
            n, user_address
        ))),
    }
}
