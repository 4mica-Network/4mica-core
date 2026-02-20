use std::str::FromStr;

use crate::error::PersistDbError;
use crate::persist::{GuaranteeData, PersistCtx};
use crate::util::u256_to_string;
use alloy::primitives::U256;
use chrono::{TimeZone, Utc};
use crypto::bls::BLSCert;
use entities::guarantee;
use entities::sea_orm_active_enums::TabStatus;
use metrics_4mica::measure;
use rpc::{PaymentGuaranteeClaims, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaimsV1};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set};

use super::balances::{get_user_balance_on, update_user_balance_and_version_on};
use super::common::parse_address;
use super::tabs::{get_tab_by_id_on, lock_and_update_tab_on, open_tab_on};
use super::users::ensure_user_exists_on;
use super::withdrawals::get_pending_withdrawal_on;
use crate::metrics::misc::record_db_time;
use entities::tabs;

/// Returns the new total amount of the tab.
#[measure(record_db_time)]
pub async fn update_user_balance_and_tab_for_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    claims: &PaymentGuaranteeRequestClaimsV1,
) -> Result<U256, PersistDbError> {
    parse_address(&claims.user_address)?;
    parse_address(&claims.recipient_address)?;
    parse_address(&claims.asset_address)?;

    ensure_user_exists_on(conn, &claims.user_address).await?;
    ensure_user_exists_on(conn, &claims.recipient_address).await?;

    let start_dt = Utc
        .timestamp_opt(claims.timestamp as i64, 0)
        .single()
        .ok_or_else(|| PersistDbError::InvalidTimestamp(claims.timestamp as i64))?
        .naive_utc();

    let asset_balance =
        get_user_balance_on(conn, &claims.user_address, &claims.asset_address).await?;
    let total = U256::from_str(&asset_balance.total)
        .map_err(|_| PersistDbError::InvalidCollateral("invalid collateral".into()))?;
    let locked = U256::from_str(&asset_balance.locked)
        .map_err(|_| PersistDbError::InvalidCollateral("invalid locked collateral".into()))?;

    let pending_amount =
        match get_pending_withdrawal_on(conn, &claims.user_address, &claims.asset_address).await? {
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
        &claims.user_address,
        &claims.asset_address,
        asset_balance.version,
        total,
        new_locked,
    )
    .await?;

    let tab = get_tab_by_id_on(conn, claims.tab_id).await?;

    let current_total = U256::from_str(&tab.total_amount)
        .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?;
    let new_total = current_total
        .checked_add(claims.amount)
        .ok_or_else(|| PersistDbError::InvariantViolation("total amount overflow".into()))?;

    lock_and_update_tab_on(
        conn,
        claims.tab_id,
        tab.version,
        tabs::ActiveModel {
            total_amount: Set(new_total.to_string()),
            ..Default::default()
        },
    )
    .await?;

    if tab.status == TabStatus::Pending {
        open_tab_on(conn, claims.tab_id, start_dt).await?;
    }

    Ok(new_total)
}

#[measure(record_db_time)]
pub async fn prepare_and_store_guarantee_on<C: ConnectionTrait>(
    conn: &C,
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

    let data = GuaranteeData {
        tab_id: claims.tab_id,
        req_id: claims.req_id,
        from: claims.user_address.clone(),
        to: claims.recipient_address.clone(),
        asset: claims.asset_address.clone(),
        value: claims.amount,
        start_ts: start_dt,
        cert: cert_str,
        request: Some(request_str),
    };
    store_guarantee_on(conn, data).await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn store_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    data: GuaranteeData,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();

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
        request: Set(data.request),
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

#[measure(record_db_time)]
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

#[measure(record_db_time)]
pub async fn get_guarantees_for_tab(
    ctx: &PersistCtx,
    tab_id: U256,
) -> Result<Vec<guarantee::Model>, PersistDbError> {
    let rows = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(u256_to_string(tab_id)))
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
        .filter(guarantee::Column::TabId.eq(tab_id))
        .order_by_desc(guarantee::Column::CreatedAt)
        .one(ctx.db.as_ref())
        .await?;
    Ok(row)
}
