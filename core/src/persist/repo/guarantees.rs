use crate::error::PersistDbError;
use crate::persist::{GuaranteeData, PersistCtx};
use crate::util::u256_to_string;
use alloy::primitives::U256;
use chrono::{TimeZone, Utc};
use crypto::bls::BLSCert;
use entities::guarantee;
use log::info;
use rpc::PaymentGuaranteeClaims;
use sea_orm::prelude::Expr;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set, TransactionTrait,
};

use super::balances::{get_user_balance_on, update_user_balance_and_version_on};
use super::common::parse_address;
use super::users::ensure_user_exists_on;
use super::withdrawals::get_pending_withdrawal_on;

pub async fn lock_and_store_guarantee(
    ctx: &PersistCtx,
    promise: &PaymentGuaranteeClaims,
    cert: &BLSCert,
) -> Result<(), PersistDbError> {
    use std::str::FromStr;

    parse_address(&promise.user_address)?;
    parse_address(&promise.recipient_address)?;
    parse_address(&promise.asset_address)?;

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
                ensure_user_exists_on(txn, &promise.user_address).await?;
                ensure_user_exists_on(txn, &promise.recipient_address).await?;

                let asset_balance =
                    get_user_balance_on(txn, &promise.user_address, &promise.asset_address).await?;
                let total = U256::from_str(&asset_balance.total)
                    .map_err(|_| PersistDbError::InvalidCollateral("invalid collateral".into()))?;
                let locked = U256::from_str(&asset_balance.locked).map_err(|_| {
                    PersistDbError::InvalidCollateral("invalid locked collateral".into())
                })?;

                let pending_amount = match get_pending_withdrawal_on(
                    txn,
                    &promise.user_address,
                    &promise.asset_address,
                )
                .await?
                {
                    Some(withdrawal) => U256::from_str(&withdrawal.requested_amount)
                        .map_err(|e| PersistDbError::InvalidCollateral(e.to_string()))?,
                    None => U256::ZERO,
                };

                let free = total.saturating_sub(locked).saturating_sub(pending_amount);
                if free < promise.amount {
                    return Err(PersistDbError::InsufficientCollateral);
                }

                let new_locked = locked
                    .checked_add(promise.amount)
                    .ok_or_else(|| PersistDbError::InvariantViolation("locked overflow".into()))?;

                update_user_balance_and_version_on(
                    txn,
                    &promise.user_address,
                    &promise.asset_address,
                    asset_balance.version,
                    total,
                    new_locked,
                )
                .await?;

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
        // Pad the prefix-stripped req_id to 64 characters (256 bits) and decode it to bytes, then sort by that.
        // 'i' is for case-insensitive matching.
        .order_by_asc(Expr::cust(
            r#"decode(lpad(regexp_replace(req_id, '^0x', '', 'i'), 64, '0'), 'hex')"#,
        ))
        .all(ctx.db.as_ref())
        .await?;
    Ok(rows)
}

pub async fn get_last_guarantee_for_tab(
    ctx: &PersistCtx,
    tab_id: U256,
) -> Result<Option<guarantee::Model>, PersistDbError> {
    let tab_id = u256_to_string(tab_id);
    info!("Fetching last guarantee for tab {}", tab_id);
    let row = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(tab_id))
        // Pad the prefix-stripped req_id to 64 characters (256 bits) and decode it to bytes, then sort by that.
        // 'i' is for case-insensitive matching.
        .order_by_desc(Expr::cust(
            r#"decode(lpad(regexp_replace(req_id, '^0x', '', 'i'), 64, '0'), 'hex')"#,
        ))
        .one(ctx.db.as_ref())
        .await?;
    Ok(row)
}
