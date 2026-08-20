use crate::error::PersistDbError;
use crate::persist::canonical::Canonical;
use crate::persist::rows::StoreCycleGuaranteeInput;
use crate::persist::rows::{CycleGuarantee, decode_all};
use alloy::primitives::Address;
use alloy::primitives::U256;
use chrono::{NaiveDateTime, Utc};
use entities::guarantee;
use entities::sea_orm_active_enums::GuaranteeSettlementStatus;
use metrics_4mica::measure;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    Set,
};

use super::balances::{get_user_balance_on, update_user_balance_and_version_on};
use super::common::is_unique_violation;
use super::withdrawals::get_pending_withdrawal_on;
use crate::metrics::misc::record_db_time;

/// Locks payer collateral for a cycle-native guarantee without mutating tab totals.
#[measure(record_db_time)]
pub async fn lock_user_balance_for_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    user_address: Address,
    asset_address: Address,
    amount: U256,
) -> Result<(), PersistDbError> {
    let asset_balance = get_user_balance_on(conn, user_address, asset_address).await?;
    let total = asset_balance.total;
    let locked = asset_balance.locked;

    let pending_amount = match get_pending_withdrawal_on(conn, user_address, asset_address).await? {
        Some(withdrawal) => U256::from_canonical(&withdrawal.requested_amount)?,
        None => U256::ZERO,
    };

    let free = total.saturating_sub(locked).saturating_sub(pending_amount);
    if free < amount {
        return Err(PersistDbError::InsufficientCollateral);
    }

    let new_locked = locked
        .checked_add(amount)
        .ok_or_else(|| PersistDbError::InvariantViolation("locked overflow".into()))?;

    update_user_balance_and_version_on(
        conn,
        user_address,
        asset_address,
        asset_balance.version,
        total,
        new_locked,
    )
    .await?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn store_cycle_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    data: StoreCycleGuaranteeInput,
) -> Result<(), PersistDbError> {
    let now = Utc::now().naive_utc();

    let active_model = guarantee::ActiveModel {
        guarantee_id: Set(data.guarantee_id.clone()),
        cycle_id: Set(data.cycle_id),
        req_id: Set(data.req_id.canonical()),
        version: Set(i32::try_from(data.version).map_err(|_| {
            PersistDbError::InvariantViolation(format!(
                "guarantee version {} does not fit in i32",
                data.version
            ))
        })?),
        from_address: Set(data.from.canonical()),
        to_address: Set(data.to.canonical()),
        asset_address: Set(data.asset.canonical()),
        value: Set(data.value.canonical()),
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
        .await
        .map_err(|err| {
            if is_unique_violation(&err) {
                PersistDbError::DuplicateGuarantee {
                    req_id: data.req_id.value(),
                }
            } else {
                PersistDbError::DatabaseFailure(err)
            }
        })?;

    Ok(())
}

#[measure(record_db_time)]
pub async fn get_guarantee_by_id_on<C: ConnectionTrait>(
    conn: &C,
    guarantee_id: &str,
) -> Result<Option<CycleGuarantee>, PersistDbError> {
    let row = guarantee::Entity::find()
        .filter(guarantee::Column::GuaranteeId.eq(guarantee_id))
        .one(conn)
        .await?;
    row.map(CycleGuarantee::try_from).transpose()
}

/// Which guarantees a transition applies to: one by id, or a cycle's, optionally narrowed to a
/// payer. Always constrained by `from`, so it cannot widen into every guarantee.
#[derive(Debug, Clone, Copy)]
pub struct GuaranteeSelector<'a> {
    scope: Scope<'a>,
    from: &'a [GuaranteeSettlementStatus],
}

#[derive(Debug, Clone, Copy)]
enum Scope<'a> {
    Id(&'a str),
    Cycle {
        cycle_id: &'a str,
        payer: Option<Address>,
    },
}

impl<'a> GuaranteeSelector<'a> {
    pub fn id(guarantee_id: &'a str, from: &'a [GuaranteeSettlementStatus]) -> Self {
        Self {
            scope: Scope::Id(guarantee_id),
            from,
        }
    }

    pub fn cycle(
        cycle_id: &'a str,
        payer: Option<Address>,
        from: &'a [GuaranteeSettlementStatus],
    ) -> Self {
        Self {
            scope: Scope::Cycle { cycle_id, payer },
            from,
        }
    }

    fn condition(&self) -> Condition {
        let mut condition = Condition::all()
            .add(guarantee::Column::SettlementStatus.is_in(self.from.iter().cloned()));
        match self.scope {
            Scope::Id(guarantee_id) => {
                condition = condition.add(guarantee::Column::GuaranteeId.eq(guarantee_id));
            }
            Scope::Cycle { cycle_id, payer } => {
                condition = condition.add(guarantee::Column::CycleId.eq(cycle_id));
                if let Some(payer) = payer {
                    condition = condition.add(guarantee::Column::FromAddress.eq(payer.canonical()));
                }
            }
        }
        condition
    }
}

/// Stamp the column that records when `target` was reached.
fn stamp_reached_at(
    update: &mut guarantee::ActiveModel,
    target: &GuaranteeSettlementStatus,
    now: NaiveDateTime,
) {
    use GuaranteeSettlementStatus::*;
    match target {
        FinalizedPayable => update.finalized_at = Set(Some(now)),
        Netted => update.netted_at = Set(Some(now)),
        Settled | DefaultRemunerated => update.settled_at = Set(Some(now)),
        Issued | PendingValidation | Disputed | Cancelled => {}
    }
}

#[measure(record_db_time)]
pub async fn list_guarantees_on<C: ConnectionTrait>(
    conn: &C,
    selector: GuaranteeSelector<'_>,
) -> Result<Vec<CycleGuarantee>, PersistDbError> {
    let rows = guarantee::Entity::find()
        .filter(selector.condition())
        .all(conn)
        .await?;
    decode_all(rows)
}

/// Move everything `selector` matches to `target`, returning how many rows moved.
#[measure(record_db_time)]
pub async fn transition_guarantees_on<C: ConnectionTrait>(
    conn: &C,
    selector: GuaranteeSelector<'_>,
    target: GuaranteeSettlementStatus,
    now: NaiveDateTime,
) -> Result<u64, PersistDbError> {
    let mut update = guarantee::ActiveModel {
        settlement_status: Set(target.clone()),
        updated_at: Set(now),
        ..Default::default()
    };
    stamp_reached_at(&mut update, &target, now);

    let result = guarantee::Entity::update_many()
        .filter(selector.condition())
        .set(update)
        .exec(conn)
        .await?;
    Ok(result.rows_affected)
}

#[measure(record_db_time)]
pub async fn release_locked_collateral_for_guarantee_on<C: ConnectionTrait>(
    conn: &C,
    guarantee: &CycleGuarantee,
) -> Result<(), PersistDbError> {
    let amount = guarantee.value;
    if amount == U256::ZERO {
        return Ok(());
    }

    let asset_balance = get_user_balance_on(conn, guarantee.payer, guarantee.asset).await?;
    let total = asset_balance.total;
    let locked = asset_balance.locked;
    if amount > locked {
        return Err(PersistDbError::InvariantViolation(format!(
            "guarantee {} release amount exceeds locked collateral",
            guarantee.guarantee_id
        )));
    }

    update_user_balance_and_version_on(
        conn,
        guarantee.payer,
        guarantee.asset,
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
) -> Result<Vec<CycleGuarantee>, PersistDbError> {
    let rows = guarantee::Entity::find()
        .filter(guarantee::Column::CycleId.eq(cycle_id))
        .filter(guarantee::Column::SettlementStatus.eq(GuaranteeSettlementStatus::FinalizedPayable))
        .order_by_asc(guarantee::Column::FromAddress)
        .order_by_asc(guarantee::Column::ToAddress)
        .order_by_asc(guarantee::Column::AssetAddress)
        .order_by_asc(guarantee::Column::ReqId)
        .all(conn)
        .await?;
    decode_all(rows)
}

/// Count the `FinalizedPayable` guarantees in a cycle. Used to detect cycles
/// with no payable exposure, which are short-circuited instead of being netted
/// and committed on-chain.
#[measure(record_db_time)]
pub async fn count_finalized_payable_guarantees_for_cycle_on<C: ConnectionTrait>(
    conn: &C,
    cycle_id: &str,
) -> Result<u64, PersistDbError> {
    let count = guarantee::Entity::find()
        .filter(guarantee::Column::CycleId.eq(cycle_id))
        .filter(guarantee::Column::SettlementStatus.eq(GuaranteeSettlementStatus::FinalizedPayable))
        .count(conn)
        .await?;
    Ok(count)
}
