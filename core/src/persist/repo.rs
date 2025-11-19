use crate::error::PersistDbError;
use crate::persist::*;
use crate::util::u256_to_string;
use alloy::primitives::U256;
use chrono::{TimeZone, Utc};
use crypto::bls::BLSCert;
use entities::sea_orm_active_enums::{SettlementStatus, TabStatus};
use entities::user_asset_balance;
use entities::{
    admin_api_key, collateral_event, guarantee,
    sea_orm_active_enums::{CollateralEventType, WithdrawalStatus},
    tabs, user, user_transaction, withdrawal,
};
use log::info;
use rpc::PaymentGuaranteeClaims;
use sea_orm::ConnectionTrait;
use sea_orm::QueryOrder;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DbErr, EntityTrait, IntoActiveModel, QueryFilter,
    Set, TransactionTrait,
};
use std::str::FromStr;
use uuid::Uuid;

//
// ────────────────────── USER FUNCTIONS ──────────────────────
//

pub async fn get_user(ctx: &PersistCtx, user_address: &str) -> Result<user::Model, PersistDbError> {
    user::Entity::find_by_id(user_address)
        .one(ctx.db.as_ref())
        .await?
        .ok_or_else(|| PersistDbError::UserNotFound(user_address.to_owned()))
}

pub async fn ensure_user_is_active(
    ctx: &PersistCtx,
    user_address: &str,
) -> Result<(), PersistDbError> {
    let user = get_user(ctx, user_address).await?;
    if user.is_suspended {
        Err(PersistDbError::UserSuspended(user_address.to_owned()))
    } else {
        Ok(())
    }
}

pub async fn update_user_suspension(
    ctx: &PersistCtx,
    user_address: &str,
    suspended: bool,
) -> Result<user::Model, PersistDbError> {
    let mut model = get_user(ctx, user_address).await?.into_active_model();
    model.is_suspended = Set(suspended);
    model.updated_at = Set(Utc::now().naive_utc());

    model
        .update(ctx.db.as_ref())
        .await
        .map_err(PersistDbError::from)
}

pub async fn ensure_user_exists_on<C: ConnectionTrait>(
    conn: &C,
    addr: &str,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();
    let insert_user = user::ActiveModel {
        address: Set(addr.to_owned()),
        version: Set(0),
        is_suspended: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
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

pub async fn get_user_balance_on<C: ConnectionTrait>(
    conn: &C,
    user_address: &str,
    asset_address: &str,
) -> Result<user_asset_balance::Model, PersistDbError> {
    // First, try to find existing balance
    let balance = user_asset_balance::Entity::find()
        .filter(user_asset_balance::Column::UserAddress.eq(user_address))
        .filter(user_asset_balance::Column::AssetAddress.eq(asset_address))
        .one(conn)
        .await?;

    if let Some(b) = balance {
        return Ok(b);
    }

    let now = Utc::now().naive_utc();
    let new_balance = user_asset_balance::ActiveModel {
        user_address: Set(user_address.to_owned()),
        asset_address: Set(asset_address.to_owned()),
        total: Set("0".to_string()),
        locked: Set("0".to_string()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
    };

    // Idempotent insert; avoids "RecordNotInserted" on DO NOTHING
    match user_asset_balance::Entity::insert(new_balance.clone())
        .on_conflict(
            OnConflict::columns([
                user_asset_balance::Column::UserAddress,
                user_asset_balance::Column::AssetAddress,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(conn)
        .await
    {
        Ok(_) => {}
        Err(sea_orm::DbErr::Exec(err))
            if err.to_string().contains("FOREIGN KEY constraint failed")
                || err.to_string().contains("foreign key constraint") =>
        {
            return Err(PersistDbError::UserNotFound(user_address.to_owned()));
        }
        Err(e) => return Err(e.into()),
    }

    // Fetch and return the record (in case it was inserted by another concurrent transaction)
    user_asset_balance::Entity::find()
        .filter(user_asset_balance::Column::UserAddress.eq(user_address))
        .filter(user_asset_balance::Column::AssetAddress.eq(asset_address))
        .one(conn)
        .await?
        .ok_or_else(|| {
            PersistDbError::DatabaseFailure(sea_orm::DbErr::Custom(format!(
                "Failed to create or fetch balance for user {} and asset {}",
                user_address, asset_address
            )))
        })
}

fn validate_address(addr: &str) -> Result<(), PersistDbError> {
    if !addr.starts_with("0x") || addr.len() != 42 {
        return Err(PersistDbError::InvariantViolation("invalid address".into()));
    }
    Ok(())
}

//
// ────────────────────── COLLATERAL EVENTS ──────────────────────
//

/// Deposit: increment collateral and record a CollateralEvent::Deposit for auditability.
pub async fn deposit(
    ctx: &PersistCtx,
    user_address: String,
    asset_address: String,
    amount: U256,
) -> Result<(), PersistDbError> {
    use sea_orm::ActiveValue::Set as AvSet;
    let now = Utc::now().naive_utc();
    validate_address(&user_address)?;

    ctx.db
        .transaction(|txn| {
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

                // Record the deposit event
                if amount > U256::ZERO {
                    let ev = collateral_event::ActiveModel {
                        id: AvSet(uuid::Uuid::new_v4().to_string()),
                        user_address: AvSet(user_address),
                        asset_address: AvSet(asset_address),
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

pub async fn unlock_user_collateral(
    ctx: &PersistCtx,
    tab_id: U256,
    asset_address: String,
    amount: U256,
) -> Result<(), PersistDbError> {
    use sea_orm::ActiveValue::Set;
    let now = Utc::now().naive_utc();

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                // strict fetch (same txn)
                let tab = get_tab_by_id_on(txn, tab_id).await?;

                let tab_id = u256_to_string(tab_id);
                // CAS: mark tab as Settled once (idempotent)
                let cas = entities::tabs::Entity::update_many()
                    .filter(entities::tabs::Column::Id.eq(&tab_id))
                    .filter(entities::tabs::Column::SettlementStatus.ne(SettlementStatus::Settled))
                    .set(entities::tabs::ActiveModel {
                        settlement_status: Set(SettlementStatus::Settled),
                        updated_at: Set(now),
                        ..Default::default()
                    })
                    .exec(txn)
                    .await?;

                // If already settled, do nothing (idempotent)
                if cas.rows_affected == 0 {
                    return Ok::<_, PersistDbError>(());
                }

                // Decrease user's locked_collateral (does not touch total collateral)
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

                // optimistic lock bump + write new locked value
                update_user_balance_and_version_on(
                    txn,
                    &tab.user_address,
                    &asset_address,
                    asset_balance.version,
                    total,
                    new_locked,
                )
                .await?;

                // Audit trail: Unlock event (see NOTE below if enum variant differs)
                let ev = collateral_event::ActiveModel {
                    id: Set(uuid::Uuid::new_v4().to_string()),
                    user_address: Set(tab.user_address.clone()),
                    asset_address: Set(asset_address),
                    amount: Set(amount.to_string()),
                    event_type: Set(CollateralEventType::Unlock),
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

//
// ────────────────────── WITHDRAWALS ──────────────────────
//

pub async fn request_withdrawal(
    ctx: &PersistCtx,
    user_address: String,
    asset_address: String,
    when: i64,
    amount: U256,
) -> Result<(), PersistDbError> {
    // Ensure user exists and has enough collateral
    let asset_balance = get_user_balance_on(ctx.db.as_ref(), &user_address, &asset_address).await?;

    let user_collateral = U256::from_str(&asset_balance.total)
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
        asset_address: Set(asset_address),
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
    asset_address: String,
) -> Result<(), PersistDbError> {
    match withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_address))
        .filter(withdrawal::Column::AssetAddress.eq(asset_address))
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
    asset_address: String,
    executed_amount: U256,
) -> Result<(), PersistDbError> {
    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                let now = Utc::now().naive_utc();

                // most recent Pending withdrawal for this asset; if none => error
                let withdrawal = withdrawal::Entity::find()
                    .filter(withdrawal::Column::UserAddress.eq(&user_address))
                    .filter(withdrawal::Column::AssetAddress.eq(&asset_address))
                    .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
                    .order_by_desc(withdrawal::Column::CreatedAt)
                    .one(txn)
                    .await?
                    .ok_or(PersistDbError::WithdrawalNotFound {
                        user: user_address.clone(),
                        asset: asset_address.clone(),
                    })?;

                // ensure we never execute more than requested
                let requested = U256::from_str(&withdrawal.requested_amount)
                    .map_err(|e| PersistDbError::InvalidTxAmount(e.to_string()))?;
                if executed_amount > requested {
                    return Err(PersistDbError::InvalidTxAmount(
                        "executed_amount exceeds requested_amount".into(),
                    ));
                }

                // get user's balance for this asset
                let asset_balance =
                    get_user_balance_on(txn, &user_address, &withdrawal.asset_address).await?;
                let current_total = U256::from_str(&asset_balance.total)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
                let locked = U256::from_str(&asset_balance.locked)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                // update user balance
                let new_total = current_total
                    .checked_sub(executed_amount)
                    .ok_or(PersistDbError::InsufficientCollateral)?;

                update_user_balance_and_version_on(
                    txn,
                    &user_address,
                    &withdrawal.asset_address,
                    asset_balance.version,
                    new_total,
                    locked,
                )
                .await?;

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
    asset_address: String,
    transaction_id: String,
    amount: U256,
) -> Result<u64, PersistDbError> {
    let now = Utc::now().naive_utc();

    validate_address(&user_address)?;
    ensure_user_exists_on(ctx.db.as_ref(), &user_address).await?;
    let tx = user_transaction::ActiveModel {
        tx_id: Set(transaction_id),
        user_address: Set(user_address),
        recipient_address: Set(recipient_address),
        asset_address: Set(asset_address),
        amount: Set(amount.to_string()),
        verified: Set(false),
        finalized: Set(false),
        failed: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
    };

    // Duplicate tx_id → no-op
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

pub async fn fail_transaction(
    ctx: &PersistCtx,
    user_address: String,
    transaction_id: String,
) -> Result<(), PersistDbError> {
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
                let now = Utc::now().naive_utc();
                active_model.updated_at = Set(now);
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

/// Atomically:
///   1. Check the user has enough *free* collateral
///   2. Increment `locked_collateral` and bump version
///   3. Insert the guarantee row
///   4. Returns the serialized BLS cert string you passed in on success.
pub async fn lock_and_store_guarantee(
    ctx: &PersistCtx,
    promise: &PaymentGuaranteeClaims,
    cert: &BLSCert,
) -> Result<(), PersistDbError> {
    use chrono::Utc;
    use std::str::FromStr;

    let cert_str = serde_json::to_string(cert)
        .map_err(|e| PersistDbError::InvariantViolation(e.to_string()))?;

    let start_dt = Utc
        .timestamp_opt(promise.timestamp as i64, 0)
        .single()
        .ok_or_else(|| PersistDbError::InvalidTimestamp(promise.timestamp as i64))?
        .naive_utc();

    ctx.db
        .transaction(|txn| {
            let promise = promise.clone();
            let cert_str = cert_str.clone();
            Box::pin(async move {
                // --- 1. fetch + collateral math
                let asset_balance =
                    get_user_balance_on(txn, &promise.user_address, &promise.asset_address).await?;
                let total = U256::from_str(&asset_balance.total)
                    .map_err(|_| PersistDbError::InvalidCollateral("invalid collateral".into()))?;
                let locked = U256::from_str(&asset_balance.locked).map_err(|_| {
                    PersistDbError::InvalidCollateral("invalid locked collateral".into())
                })?;

                let free = total.saturating_sub(locked);
                if free < promise.amount {
                    return Err(PersistDbError::InsufficientCollateral);
                }

                let new_locked = locked
                    .checked_add(promise.amount)
                    .ok_or_else(|| PersistDbError::InvariantViolation("locked overflow".into()))?;

                // --- 2. bump version + write locked_collateral
                update_user_balance_and_version_on(
                    txn,
                    &promise.user_address,
                    &promise.asset_address,
                    asset_balance.version,
                    total,
                    new_locked,
                )
                .await?;

                // --- 3. insert guarantee
                let data = GuaranteeData {
                    tab_id: promise.tab_id,
                    req_id: promise.req_id,
                    from: promise.user_address.clone(),
                    to: promise.recipient_address.clone(),
                    asset: promise.asset_address.clone(),
                    value: promise.amount,
                    start_ts: start_dt,
                    cert: cert_str.clone(),
                };
                store_guarantee_on(txn, data).await?;

                Ok::<_, PersistDbError>(())
            })
        })
        .await
        .map_err(|e| match e {
            sea_orm::TransactionError::Transaction(inner) => inner,
            sea_orm::TransactionError::Connection(err) => PersistDbError::DatabaseFailure(err),
        })
}

/// Insert a guarantee row using the given transaction/connection.
/// Ensures the from/to user rows exist (idempotently) inside the same txn.
/// If a (tab_id, req_id) row already exists → no-op.
pub async fn store_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    data: GuaranteeData,
) -> Result<(), PersistDbError> {
    let now = chrono::Utc::now().naive_utc();

    // Make sure both user records exist in the same transaction.
    ensure_user_exists_on(conn, &data.from).await?;
    ensure_user_exists_on(conn, &data.to).await?;

    let active_model = guarantee::ActiveModel {
        tab_id: Set(u256_to_string(data.tab_id)),
        req_id: Set(u256_to_string(data.req_id)),
        from_address: Set(data.from),
        to_address: Set(data.to),
        asset_address: Set(data.asset),
        value: Set(data.value.to_string()),
        start_ts: Set(data.start_ts),
        cert: Set(data.cert),
        created_at: Set(now),
        updated_at: Set(now),
    };

    guarantee::Entity::insert(active_model)
        .on_conflict(
            OnConflict::columns([guarantee::Column::TabId, guarantee::Column::ReqId])
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await?;

    Ok(())
}

pub async fn get_guarantee(
    ctx: &PersistCtx,
    tab_id: U256,
    req_id: U256,
) -> Result<Option<guarantee::Model>, PersistDbError> {
    let res = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(u256_to_string(tab_id)))
        .filter(guarantee::Column::ReqId.eq(u256_to_string(req_id)))
        .one(ctx.db.as_ref())
        .await?;
    Ok(res)
}

pub async fn get_guarantees_for_tab(
    ctx: &PersistCtx,
    tab_id: U256,
) -> Result<Vec<guarantee::Model>, PersistDbError> {
    let rows = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(u256_to_string(tab_id)))
        .order_by_asc(guarantee::Column::ReqId)
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

//
// ────────────────────── REMUNERATION / PAYMENTS ──────────────────────
//

/// The CAS and the balance check run inside the same SQL transaction (ctx.db.transaction).
/// If the balance check fails and an error is returned, the whole transaction, including the CAS, rolls back automatically.
/// It also avoids race condition.
/// If we check the user balance before the CAS, there’s a small window where another concurrent transaction could settle the tab first.
pub async fn remunerate_recipient(
    ctx: &PersistCtx,
    tab_id: U256,
    asset_address: String,
    amount: U256,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();

    ctx.db
        .transaction(|txn| {
            Box::pin(async move {
                // strict fetch (same txn)
                let tab = get_tab_by_id_on(txn, tab_id).await?;

                let tab_id = u256_to_string(tab_id);

                // Compare-and-set using typed `.set(ActiveModel { ... })`
                let cas = entities::tabs::Entity::update_many()
                    .filter(entities::tabs::Column::Id.eq(&tab_id))
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

                let asset_balance =
                    get_user_balance_on(txn, &tab.user_address, &asset_address).await?;
                let collateral = U256::from_str(&asset_balance.total)
                    .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;

                if collateral < amount {
                    // whole txn rolls back (CAS included)
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

                // audit event
                let ev = collateral_event::ActiveModel {
                    id: Set(uuid::Uuid::new_v4().to_string()),
                    user_address: Set(tab.user_address),
                    asset_address: Set(asset_address),
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

pub async fn get_recipient_transactions(
    ctx: &PersistCtx,
    recipient_address: &str,
) -> Result<Vec<user_transaction::Model>, PersistDbError> {
    let rows = user_transaction::Entity::find()
        .filter(user_transaction::Column::RecipientAddress.eq(recipient_address))
        .order_by_desc(user_transaction::Column::CreatedAt)
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

/// Return the most recent guarantee for a tab (by created_at DESC)
pub async fn get_last_guarantee_for_tab(
    ctx: &PersistCtx,
    tab_id: U256,
) -> Result<Option<guarantee::Model>, PersistDbError> {
    let tab_id = u256_to_string(tab_id);
    info!("Fetching last guarantee for tab {}", tab_id);
    let row = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(tab_id))
        .order_by_desc(guarantee::Column::ReqId)
        .one(ctx.db.as_ref())
        .await?;
    Ok(row)
}

/// Read TTL (in seconds) from `tabs.ttl`. Returns Err(TabNotFound) if the tab doesn't exist.
pub async fn get_tab_ttl_seconds(ctx: &PersistCtx, tab_id: U256) -> Result<u64, PersistDbError> {
    let tab_id = u256_to_string(tab_id);
    let tab = entities::tabs::Entity::find_by_id(&tab_id)
        .one(ctx.db.as_ref())
        .await?
        .ok_or_else(|| PersistDbError::TabNotFound(tab_id))?;

    let ttl = tab.ttl as u64;
    Ok(ttl)
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

pub async fn get_collateral_events_for_tab(
    ctx: &PersistCtx,
    tab_id: U256,
) -> Result<Vec<collateral_event::Model>, PersistDbError> {
    let rows = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(u256_to_string(tab_id)))
        .order_by_desc(collateral_event::Column::CreatedAt)
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

pub async fn get_user_asset_balance(
    ctx: &PersistCtx,
    user_address: &str,
    asset_address: &str,
) -> Result<Option<user_asset_balance::Model>, PersistDbError> {
    let row = user_asset_balance::Entity::find()
        .filter(user_asset_balance::Column::UserAddress.eq(user_address))
        .filter(user_asset_balance::Column::AssetAddress.eq(asset_address))
        .one(ctx.db.as_ref())
        .await?;
    Ok(row)
}

pub async fn create_pending_tab(
    ctx: &PersistCtx,
    tab_id: U256,
    user_address: &str,
    server_address: &str,
    asset_address: &str,
    start_ts: chrono::NaiveDateTime,
    ttl: i64,
) -> Result<(), PersistDbError> {
    ensure_user_is_active(ctx, user_address).await?;

    use sea_orm::ActiveValue::Set;
    let now = Utc::now().naive_utc();
    let new_tab = tabs::ActiveModel {
        id: Set(u256_to_string(tab_id)),
        user_address: Set(user_address.to_owned()),
        server_address: Set(server_address.to_owned()),
        asset_address: Set(asset_address.to_owned()),
        start_ts: Set(start_ts),
        ttl: Set(ttl),
        status: Set(TabStatus::Pending),
        settlement_status: Set(SettlementStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
    };
    info!("Creating new pending tab {}", new_tab.id.as_ref());

    tabs::Entity::insert(new_tab).exec(ctx.db.as_ref()).await?;

    Ok(())
}

pub async fn open_tab(
    ctx: &PersistCtx,
    tab_id: U256,
    start_ts: chrono::NaiveDateTime,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();

    // Idempotent update
    tabs::Entity::update_many()
        .filter(tabs::Column::Id.eq(u256_to_string(tab_id)))
        .filter(tabs::Column::Status.eq(TabStatus::Pending))
        .set(tabs::ActiveModel {
            status: Set(TabStatus::Open),
            start_ts: Set(start_ts),
            updated_at: Set(now),
            ..Default::default()
        })
        .exec(ctx.db.as_ref())
        .await?;

    Ok(())
}

/// Get a single tab by id
pub async fn get_tab_by_id(
    ctx: &PersistCtx,
    tab_id: U256,
) -> Result<Option<entities::tabs::Model>, PersistDbError> {
    let res = entities::tabs::Entity::find_by_id(u256_to_string(tab_id))
        .one(ctx.db.as_ref())
        .await?;
    Ok(res)
}

/// Fetch tabs for a recipient, optionally filtering by settlement status.
pub async fn get_tabs_for_recipient(
    ctx: &PersistCtx,
    recipient_address: &str,
    settlement_statuses: Option<&[SettlementStatus]>,
) -> Result<Vec<entities::tabs::Model>, PersistDbError> {
    let mut condition =
        Condition::all().add(entities::tabs::Column::ServerAddress.eq(recipient_address));

    if let Some(statuses) = settlement_statuses
        && !statuses.is_empty()
    {
        let status_list: Vec<SettlementStatus> = statuses.to_vec();
        condition = condition.add(entities::tabs::Column::SettlementStatus.is_in(status_list));
    }

    let rows = entities::tabs::Entity::find()
        .filter(condition)
        .order_by_desc(entities::tabs::Column::UpdatedAt)
        .all(ctx.db.as_ref())
        .await?;

    Ok(rows)
}

pub async fn get_tab_by_id_on<C: ConnectionTrait>(
    conn: &C,
    tab_id: U256,
) -> Result<entities::tabs::Model, PersistDbError> {
    let tab_id = u256_to_string(tab_id);
    entities::tabs::Entity::find_by_id(&tab_id)
        .one(conn)
        .await?
        .ok_or_else(|| PersistDbError::TabNotFound(tab_id))
}

/// Optimistic-lock update:
///   • Bumps the user's `version` by 1
///   • Sets `locked_collateral` to `new_locked`
///   • Updates `updated_at`
/// Succeeds only if `current_version` matches (classic CAS).
///
/// Pass in any `ConnectionTrait` (a Transaction or DatabaseConnection).
pub async fn update_user_balance_and_version_on<C: ConnectionTrait>(
    conn: &C,
    user_address: &str,
    asset_address: &str,
    current_version: i32,
    new_total: U256,
    new_locked: U256,
) -> Result<(), PersistDbError> {
    use chrono::Utc;
    use sea_orm::sea_query::Expr;

    let now = Utc::now().naive_utc();

    let res = user_asset_balance::Entity::update_many()
        // filter on address + current version for optimistic locking
        .filter(user_asset_balance::Column::UserAddress.eq(user_address))
        .filter(user_asset_balance::Column::AssetAddress.eq(asset_address))
        .filter(user_asset_balance::Column::Version.eq(current_version))
        // atomic: bump version, set locked_collateral and updated_at
        .col_expr(
            user_asset_balance::Column::Version,
            Expr::col(user_asset_balance::Column::Version).add(1),
        )
        .col_expr(
            user_asset_balance::Column::Total,
            Expr::value(new_total.to_string()),
        )
        .col_expr(
            user_asset_balance::Column::Locked,
            Expr::value(new_locked.to_string()),
        )
        .col_expr(user_asset_balance::Column::UpdatedAt, Expr::value(now))
        .exec(conn)
        .await?;

    match res.rows_affected {
        1 => Ok(()),
        0 => Err(PersistDbError::OptimisticLockConflict {
            user: user_address.to_owned(),
            asset_address: asset_address.to_owned(),
            expected_version: current_version,
        }),
        n => Err(PersistDbError::InvariantViolation(format!(
            "update_user_balance_and_version_on updated {} rows for address {}",
            n, user_address
        ))),
    }
}

//
// ────────────────────── ADMIN API KEYS ──────────────────────
//

pub async fn insert_admin_api_key(
    ctx: &PersistCtx,
    id: Uuid,
    name: &str,
    key_hash: &str,
    scopes: &[String],
) -> Result<admin_api_key::Model, PersistDbError> {
    let scopes_json = serde_json::to_value(scopes).map_err(|e| {
        PersistDbError::DatabaseFailure(DbErr::Custom(format!("failed to serialize scopes: {e}")))
    })?;
    let now = Utc::now().naive_utc();
    let model = admin_api_key::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        key_hash: Set(key_hash.to_owned()),
        scopes: Set(scopes_json),
        created_at: Set(now),
        revoked_at: Set(None),
    };

    model
        .insert(ctx.db.as_ref())
        .await
        .map_err(PersistDbError::from)
}

pub async fn list_admin_api_keys(
    ctx: &PersistCtx,
) -> Result<Vec<admin_api_key::Model>, PersistDbError> {
    let rows = admin_api_key::Entity::find()
        .order_by_desc(admin_api_key::Column::CreatedAt)
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

pub async fn get_admin_api_key(
    ctx: &PersistCtx,
    id: Uuid,
) -> Result<Option<admin_api_key::Model>, PersistDbError> {
    let row = admin_api_key::Entity::find_by_id(id)
        .one(ctx.db.as_ref())
        .await?;
    Ok(row)
}

pub async fn revoke_admin_api_key(
    ctx: &PersistCtx,
    id: Uuid,
) -> Result<Option<admin_api_key::Model>, PersistDbError> {
    let Some(model) = get_admin_api_key(ctx, id).await? else {
        return Ok(None);
    };
    if model.revoked_at.is_some() {
        return Ok(Some(model));
    }

    let mut active = model.into_active_model();
    active.revoked_at = Set(Some(Utc::now().naive_utc()));

    let updated = active
        .update(ctx.db.as_ref())
        .await
        .map_err(PersistDbError::from)?;
    Ok(Some(updated))
}
