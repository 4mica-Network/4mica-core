use std::str::FromStr;

use crate::error::PersistDbError;
use crate::persist::{CycleGuaranteeData, GuaranteeData, PersistCtx};
use crate::util::u256_to_string;
use alloy::primitives::U256;
use chrono::{NaiveDateTime, TimeZone, Utc};
use crypto::bls::BLSCert;
use entities::sea_orm_active_enums::{GuaranteeSettlementStatus, SettlementCycleStatus, TabStatus};
use entities::{guarantee, settlement_cycle};
use metrics_4mica::measure;
use rpc::{
    PaymentGuaranteeClaims, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestClaimsV1, PaymentGuaranteeRequestEssentials,
};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set};

use super::balances::{get_user_balance_on, update_user_balance_and_version_on};
use super::common::parse_address;
use super::tabs::{get_tab_by_id_on, lock_and_update_tab_on, open_tab_on};
use super::users::ensure_user_exists_on;
use super::withdrawals::get_pending_withdrawal_on;
use crate::metrics::misc::record_db_time;
use entities::tabs;

pub struct PrepareCycleGuaranteeInput<'a> {
    pub claims: &'a PaymentGuaranteeClaims,
    pub cert: &'a BLSCert,
    pub request: &'a PaymentGuaranteeRequest,
    pub cycle_id: String,
    pub guarantee_id: String,
    pub settlement_status: GuaranteeSettlementStatus,
}

/// Returns the new total amount of the tab.
#[measure(record_db_time)]
pub async fn update_user_balance_and_tab_for_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    tab_id: U256,
    claims: &PaymentGuaranteeRequestClaimsV1,
    guarantee_version: u64,
) -> Result<U256, PersistDbError> {
    let user_address = parse_address(&claims.user_address)?.into_inner();
    let recipient_address = parse_address(&claims.recipient_address)?.into_inner();
    let asset_address = parse_address(&claims.asset_address)?.into_inner();

    ensure_user_exists_on(conn, &user_address).await?;
    ensure_user_exists_on(conn, &recipient_address).await?;

    let start_dt = Utc
        .timestamp_opt(claims.timestamp as i64, 0)
        .single()
        .ok_or_else(|| PersistDbError::InvalidTimestamp(claims.timestamp as i64))?
        .naive_utc();

    let asset_balance = get_user_balance_on(conn, &user_address, &asset_address).await?;
    let total = U256::from_str(&asset_balance.total)
        .map_err(|_| PersistDbError::InvalidCollateral("invalid collateral".into()))?;
    let locked = U256::from_str(&asset_balance.locked)
        .map_err(|_| PersistDbError::InvalidCollateral("invalid locked collateral".into()))?;

    let pending_amount =
        match get_pending_withdrawal_on(conn, &user_address, &asset_address).await? {
            Some(withdrawal) => U256::from_str(&withdrawal.requested_amount)
                .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?,
            None => U256::ZERO,
        };

    let free = total.saturating_sub(locked).saturating_sub(pending_amount);
    if free < claims.amount {
        return Err(PersistDbError::InsufficientCollateral);
    }

    let new_locked = locked
        .checked_add(claims.amount)
        .ok_or_else(|| PersistDbError::InvariantViolation("locked overflow".into()))?;

    update_user_balance_and_version_on(
        conn,
        &user_address,
        &asset_address,
        asset_balance.version,
        total,
        new_locked,
    )
    .await?;

    let tab = get_tab_by_id_on(conn, tab_id).await?;

    let current_total = U256::from_str(&tab.total_amount)
        .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
    let new_total = current_total
        .checked_add(claims.amount)
        .ok_or_else(|| PersistDbError::InvariantViolation("total amount overflow".into()))?;

    let accepted_guarantee_version = tab.accepted_guarantee_version.ok_or_else(|| {
        PersistDbError::InvariantViolation(format!(
            "tab {} missing accepted guarantee version",
            u256_to_string(tab_id)
        ))
    })?;
    if accepted_guarantee_version as u64 != guarantee_version {
        return Err(PersistDbError::TabGuaranteeVersionMismatch {
            tab_id: u256_to_string(tab_id),
            expected_version: accepted_guarantee_version as u64,
            actual_version: guarantee_version,
        });
    }

    lock_and_update_tab_on(
        conn,
        tab_id,
        tab.version,
        tabs::ActiveModel {
            total_amount: Set(new_total.to_string()),
            ..Default::default()
        },
    )
    .await?;

    if tab.status == TabStatus::Pending {
        open_tab_on(conn, tab_id, start_dt).await?;
    }

    Ok(new_total)
}

/// Locks payer collateral for a cycle-native guarantee without mutating tab totals.
#[measure(record_db_time)]
pub async fn lock_user_balance_for_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    claims: &PaymentGuaranteeRequestClaims,
) -> Result<(), PersistDbError> {
    let user_address = parse_address(claims.user_address())?.into_inner();
    let recipient_address = parse_address(claims.recipient_address())?.into_inner();
    let asset_address = parse_address(claims.asset_address())?.into_inner();

    ensure_user_exists_on(conn, &user_address).await?;
    ensure_user_exists_on(conn, &recipient_address).await?;

    let asset_balance = get_user_balance_on(conn, &user_address, &asset_address).await?;
    let total = U256::from_str(&asset_balance.total)
        .map_err(|_| PersistDbError::InvalidCollateral("invalid collateral".into()))?;
    let locked = U256::from_str(&asset_balance.locked)
        .map_err(|_| PersistDbError::InvalidCollateral("invalid locked collateral".into()))?;

    let pending_amount =
        match get_pending_withdrawal_on(conn, &user_address, &asset_address).await? {
            Some(withdrawal) => U256::from_str(&withdrawal.requested_amount)
                .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?,
            None => U256::ZERO,
        };

    let free = total.saturating_sub(locked).saturating_sub(pending_amount);
    if free < claims.amount() {
        return Err(PersistDbError::InsufficientCollateral);
    }

    let new_locked = locked
        .checked_add(claims.amount())
        .ok_or_else(|| PersistDbError::InvariantViolation("locked overflow".into()))?;

    update_user_balance_and_version_on(
        conn,
        &user_address,
        &asset_address,
        asset_balance.version,
        total,
        new_locked,
    )
    .await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn prepare_and_store_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    tab_id: U256,
    claims: &PaymentGuaranteeClaims,
    cert: &BLSCert,
    request: &PaymentGuaranteeRequest,
) -> Result<(), PersistDbError> {
    let cert_str = serde_json::to_string(cert)
        .map_err(|e| PersistDbError::InvariantViolation(e.to_string()))?;

    let request_str = serde_json::to_string(request)
        .map_err(|e| PersistDbError::InvariantViolation(e.to_string()))?;

    let start_dt = Utc
        .timestamp_opt(claims.timestamp as i64, 0)
        .single()
        .ok_or_else(|| PersistDbError::InvalidTimestamp(claims.timestamp as i64))?
        .naive_utc();
    let from = parse_address(&claims.user_address)?.into_inner();
    let to = parse_address(&claims.recipient_address)?.into_inner();
    let asset = parse_address(&claims.asset_address)?.into_inner();

    let data = GuaranteeData {
        tab_id,
        req_id: claims.req_id,
        version: claims.version,
        from,
        to,
        asset,
        value: claims.amount,
        start_ts: start_dt,
        cert: cert_str,
        request: Some(request_str),
    };
    store_guarantee_on(conn, data).await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn prepare_and_store_cycle_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    input: PrepareCycleGuaranteeInput<'_>,
) -> Result<(), PersistDbError> {
    let cert_str = serde_json::to_string(input.cert)
        .map_err(|e| PersistDbError::InvariantViolation(e.to_string()))?;

    let request_str = serde_json::to_string(input.request)
        .map_err(|e| PersistDbError::InvariantViolation(e.to_string()))?;

    let start_dt = Utc
        .timestamp_opt(input.claims.timestamp as i64, 0)
        .single()
        .ok_or_else(|| PersistDbError::InvalidTimestamp(input.claims.timestamp as i64))?
        .naive_utc();
    let from = parse_address(&input.claims.user_address)?.into_inner();
    let to = parse_address(&input.claims.recipient_address)?.into_inner();
    let asset = parse_address(&input.claims.asset_address)?.into_inner();

    let data = CycleGuaranteeData {
        guarantee_id: input.guarantee_id,
        cycle_id: input.cycle_id,
        req_id: input.claims.req_id,
        version: input.claims.version,
        from,
        to,
        asset,
        value: input.claims.amount,
        start_ts: start_dt,
        cert: cert_str,
        request: Some(request_str),
        settlement_status: input.settlement_status,
    };
    store_cycle_guarantee_on(conn, data).await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn store_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    data: GuaranteeData,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();
    let legacy_cycle_id = format!("legacy:{}", u256_to_string(data.tab_id));

    ensure_user_exists_on(conn, &data.from).await?;
    ensure_user_exists_on(conn, &data.to).await?;
    ensure_legacy_cycle_on(conn, &legacy_cycle_id, &data.asset, data.start_ts).await?;

    let active_model = guarantee::ActiveModel {
        guarantee_id: Set(legacy_guarantee_id_for(
            data.tab_id,
            data.req_id,
            data.version,
        )),
        legacy_tab_id: Set(Some(u256_to_string(data.tab_id))),
        cycle_id: Set(legacy_cycle_id),
        req_id: Set(u256_to_string(data.req_id)),
        version: Set(i32::try_from(data.version).map_err(|_| {
            PersistDbError::InvariantViolation(format!(
                "guarantee version {} does not fit in i32",
                data.version
            ))
        })?),
        from_address: Set(data.from),
        to_address: Set(data.to),
        asset_address: Set(data.asset),
        value: Set(data.value.to_string()),
        start_ts: Set(data.start_ts),
        cert: Set(data.cert),
        request: Set(data.request),
        settlement_status: Set(GuaranteeSettlementStatus::Issued),
        dispute_deadline: Set(None),
        finalized_at: Set(None),
        netted_at: Set(None),
        settled_at: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    guarantee::Entity::insert(active_model)
        .on_conflict(
            OnConflict::column(guarantee::Column::GuaranteeId)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn store_cycle_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    data: CycleGuaranteeData,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();

    ensure_user_exists_on(conn, &data.from).await?;
    ensure_user_exists_on(conn, &data.to).await?;

    let active_model = guarantee::ActiveModel {
        guarantee_id: Set(data.guarantee_id.clone()),
        legacy_tab_id: Set(Some(format!("cycle:{}", data.guarantee_id))),
        cycle_id: Set(data.cycle_id),
        req_id: Set(u256_to_string(data.req_id)),
        version: Set(i32::try_from(data.version).map_err(|_| {
            PersistDbError::InvariantViolation(format!(
                "guarantee version {} does not fit in i32",
                data.version
            ))
        })?),
        from_address: Set(data.from),
        to_address: Set(data.to),
        asset_address: Set(data.asset),
        value: Set(data.value.to_string()),
        start_ts: Set(data.start_ts),
        cert: Set(data.cert),
        request: Set(data.request),
        settlement_status: Set(data.settlement_status),
        dispute_deadline: Set(None),
        finalized_at: Set(None),
        netted_at: Set(None),
        settled_at: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    };

    guarantee::Entity::insert(active_model)
        .exec_without_returning(conn)
        .await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn get_guarantee_by_id_on<C: ConnectionTrait>(
    conn: &C,
    guarantee_id: &str,
) -> Result<Option<guarantee::Model>, PersistDbError> {
    let row = guarantee::Entity::find()
        .filter(guarantee::Column::GuaranteeId.eq(guarantee_id))
        .one(conn)
        .await?;
    Ok(row)
}

#[measure(record_db_time)]
pub async fn transition_guarantee_settlement_status_on<C: ConnectionTrait>(
    conn: &C,
    guarantee_id: &str,
    allowed_from: &[GuaranteeSettlementStatus],
    target: GuaranteeSettlementStatus,
    now: NaiveDateTime,
) -> Result<bool, PersistDbError> {
    let mut update = guarantee::ActiveModel {
        settlement_status: Set(target.clone()),
        updated_at: Set(now),
        ..Default::default()
    };
    if target == GuaranteeSettlementStatus::FinalizedPayable {
        update.finalized_at = Set(Some(now));
    }

    let result = guarantee::Entity::update_many()
        .filter(guarantee::Column::GuaranteeId.eq(guarantee_id))
        .filter(guarantee::Column::SettlementStatus.is_in(allowed_from.iter().cloned()))
        .set(update)
        .exec(conn)
        .await?;

    Ok(result.rows_affected == 1)
}

#[measure(record_db_time)]
pub async fn release_locked_collateral_for_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    guarantee: &guarantee::Model,
) -> Result<(), PersistDbError> {
    let amount = U256::from_str(&guarantee.value)
        .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
    if amount == U256::ZERO {
        return Ok(());
    }

    let asset_balance =
        get_user_balance_on(conn, &guarantee.from_address, &guarantee.asset_address).await?;
    let total = U256::from_str(&asset_balance.total)
        .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
    let locked = U256::from_str(&asset_balance.locked)
        .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
    if amount > locked {
        return Err(PersistDbError::InvariantViolation(format!(
            "guarantee {} release amount exceeds locked collateral",
            guarantee.guarantee_id
        )));
    }

    update_user_balance_and_version_on(
        conn,
        &guarantee.from_address,
        &guarantee.asset_address,
        asset_balance.version,
        total,
        locked - amount,
    )
    .await
}

#[measure(record_db_time)]
pub async fn get_guarantee(
    ctx: &PersistCtx,
    tab_id: U256,
    req_id: U256,
) -> Result<Option<guarantee::Model>, PersistDbError> {
    let res = guarantee::Entity::find()
        .filter(guarantee::Column::LegacyTabId.eq(u256_to_string(tab_id)))
        .filter(guarantee::Column::ReqId.eq(u256_to_string(req_id)))
        .one(ctx.db.as_ref())
        .await?;
    Ok(res)
}

#[measure(record_db_time)]
pub async fn get_guarantees_for_tab(
    ctx: &PersistCtx,
    tab_id: U256,
) -> Result<Vec<guarantee::Model>, PersistDbError> {
    let rows = guarantee::Entity::find()
        .filter(guarantee::Column::LegacyTabId.eq(u256_to_string(tab_id)))
        .order_by_asc(guarantee::Column::CreatedAt)
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

#[measure(record_db_time)]
pub async fn get_last_guarantee_for_tab(
    ctx: &PersistCtx,
    tab_id: U256,
) -> Result<Option<guarantee::Model>, PersistDbError> {
    let tab_id = u256_to_string(tab_id);
    let row = guarantee::Entity::find()
        .filter(guarantee::Column::LegacyTabId.eq(tab_id))
        .order_by_desc(guarantee::Column::CreatedAt)
        .one(ctx.db.as_ref())
        .await?;
    Ok(row)
}

#[measure(record_db_time)]
pub async fn list_finalized_payable_guarantees_for_cycle_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
) -> Result<Vec<guarantee::Model>, PersistDbError> {
    let rows = guarantee::Entity::find()
        .filter(guarantee::Column::CycleId.eq(cycle_id))
        .filter(guarantee::Column::SettlementStatus.eq(GuaranteeSettlementStatus::FinalizedPayable))
        .order_by_asc(guarantee::Column::FromAddress)
        .order_by_asc(guarantee::Column::ToAddress)
        .order_by_asc(guarantee::Column::AssetAddress)
        .order_by_asc(guarantee::Column::ReqId)
        .all(conn)
        .await?;
    Ok(rows)
}

fn legacy_guarantee_id_for(tab_id: U256, req_id: U256, version: u64) -> String {
    format!(
        "legacy:{}:{}:{}",
        u256_to_string(tab_id),
        u256_to_string(req_id),
        version
    )
}

async fn ensure_legacy_cycle_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    asset_address: &str,
    at: chrono::NaiveDateTime,
) -> Result<(), PersistDbError> {
    let model = settlement_cycle::ActiveModel {
        id: Set(cycle_id.to_string()),
        asset_address: Set(asset_address.to_string()),
        period_start: Set(at),
        period_end: Set(at),
        resolution_cutoff: Set(at),
        clearing_commit_deadline: Set(at),
        payment_submission_deadline: Set(at),
        payment_finality_deadline: Set(at),
        status: Set(SettlementCycleStatus::Finalized),
        gross_payable_amount: Set("0".to_string()),
        gross_receivable_amount: Set("0".to_string()),
        net_settlement_amount: Set("0".to_string()),
        clearing_batch_hash: Set(None),
        commit_tx_hash: Set(None),
        created_at: Set(at),
        updated_at: Set(at),
    };

    settlement_cycle::Entity::insert(model)
        .on_conflict(
            OnConflict::column(settlement_cycle::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await?;

    Ok(())
}
