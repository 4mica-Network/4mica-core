use std::str::FromStr;

use crate::error::PersistDbError;
use crate::persist::CycleGuaranteeData;
use crate::util::u256_to_string;
use alloy::primitives::U256;
use chrono::{NaiveDateTime, TimeZone, Utc};
use crypto::bls::BLSCert;
use entities::guarantee;
use entities::sea_orm_active_enums::GuaranteeSettlementStatus;
use metrics_4mica::measure;
use rpc::{
    PaymentGuaranteeClaims, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestEssentials,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set};

use super::balances::{get_user_balance_on, update_user_balance_and_version_on};
use super::common::parse_address;
use super::users::ensure_user_exists_on;
use super::withdrawals::get_pending_withdrawal_on;
use crate::metrics::misc::record_db_time;

pub struct PrepareCycleGuaranteeInput<'a> {
    pub claims: &'a PaymentGuaranteeClaims,
    pub cert: &'a BLSCert,
    pub request: &'a PaymentGuaranteeRequest,
    pub cycle_id: String,
    pub guarantee_id: String,
    pub settlement_status: GuaranteeSettlementStatus,
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
pub async fn store_cycle_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    data: CycleGuaranteeData,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();

    ensure_user_exists_on(conn, &data.from).await?;
    ensure_user_exists_on(conn, &data.to).await?;

    let active_model = guarantee::ActiveModel {
        guarantee_id: Set(data.guarantee_id.clone()),
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
pub async fn mark_cycle_guarantees_netted_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    now: NaiveDateTime,
) -> Result<u64, PersistDbError> {
    let result = guarantee::Entity::update_many()
        .filter(guarantee::Column::CycleId.eq(cycle_id))
        .filter(guarantee::Column::SettlementStatus.eq(GuaranteeSettlementStatus::FinalizedPayable))
        .set(guarantee::ActiveModel {
            settlement_status: Set(GuaranteeSettlementStatus::Netted),
            netted_at: Set(Some(now)),
            updated_at: Set(now),
            ..Default::default()
        })
        .exec(conn)
        .await?;
    Ok(result.rows_affected)
}

#[measure(record_db_time)]
pub async fn list_netted_guarantees_for_cycle_payer_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    payer: &str,
) -> Result<Vec<guarantee::Model>, PersistDbError> {
    let rows = guarantee::Entity::find()
        .filter(guarantee::Column::CycleId.eq(cycle_id))
        .filter(guarantee::Column::FromAddress.eq(payer))
        .filter(guarantee::Column::SettlementStatus.eq(GuaranteeSettlementStatus::Netted))
        .all(conn)
        .await?;
    Ok(rows)
}

#[measure(record_db_time)]
pub async fn list_netted_guarantees_for_cycle_payee_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    payee: &str,
) -> Result<Vec<guarantee::Model>, PersistDbError> {
    let rows = guarantee::Entity::find()
        .filter(guarantee::Column::CycleId.eq(cycle_id))
        .filter(guarantee::Column::ToAddress.eq(payee))
        .filter(guarantee::Column::SettlementStatus.eq(GuaranteeSettlementStatus::Netted))
        .all(conn)
        .await?;
    Ok(rows)
}

#[measure(record_db_time)]
pub async fn transition_netted_guarantees_for_cycle_payer_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    payer: &str,
    target: GuaranteeSettlementStatus,
    now: NaiveDateTime,
) -> Result<u64, PersistDbError> {
    let mut update = guarantee::ActiveModel {
        settlement_status: Set(target.clone()),
        updated_at: Set(now),
        ..Default::default()
    };
    if matches!(
        target,
        GuaranteeSettlementStatus::Settled | GuaranteeSettlementStatus::DefaultRemunerated
    ) {
        update.settled_at = Set(Some(now));
    }

    let result = guarantee::Entity::update_many()
        .filter(guarantee::Column::CycleId.eq(cycle_id))
        .filter(guarantee::Column::FromAddress.eq(payer))
        .filter(guarantee::Column::SettlementStatus.eq(GuaranteeSettlementStatus::Netted))
        .set(update)
        .exec(conn)
        .await?;
    Ok(result.rows_affected)
}

#[measure(record_db_time)]
pub async fn transition_netted_guarantees_for_cycle_payee_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
    payee: &str,
    target: GuaranteeSettlementStatus,
    now: NaiveDateTime,
) -> Result<u64, PersistDbError> {
    let mut update = guarantee::ActiveModel {
        settlement_status: Set(target.clone()),
        updated_at: Set(now),
        ..Default::default()
    };
    if matches!(
        target,
        GuaranteeSettlementStatus::Settled | GuaranteeSettlementStatus::DefaultRemunerated
    ) {
        update.settled_at = Set(Some(now));
    }

    let result = guarantee::Entity::update_many()
        .filter(guarantee::Column::CycleId.eq(cycle_id))
        .filter(guarantee::Column::ToAddress.eq(payee))
        .filter(guarantee::Column::SettlementStatus.eq(GuaranteeSettlementStatus::Netted))
        .set(update)
        .exec(conn)
        .await?;
    Ok(result.rows_affected)
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
