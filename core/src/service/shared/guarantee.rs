//! Guarantee settlement-status transitions.

use alloy::primitives::Address;
use chrono::{NaiveDateTime, Utc};
use entities::sea_orm_active_enums::GuaranteeSettlementStatus;
use sea_orm::ConnectionTrait;

use crate::error::{ServiceError, ServiceResult};
use crate::persist::repo::{self, GuaranteeSelector};
use crate::persist::rows::CycleGuarantee;

/// Where a guarantee sits before anything has resolved it.
const UNRESOLVED: &[GuaranteeSettlementStatus] = &[
    GuaranteeSettlementStatus::Issued,
    GuaranteeSettlementStatus::PendingValidation,
];
const FINALIZED_PAYABLE: &[GuaranteeSettlementStatus] =
    &[GuaranteeSettlementStatus::FinalizedPayable];
const NETTED: &[GuaranteeSettlementStatus] = &[GuaranteeSettlementStatus::Netted];

/// A status a single guarantee can be moved to.
///
/// Excludes `Issued` and `PendingValidation`: those are written at issuance and are starting
/// points, not destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionTarget {
    FinalizedPayable,
    Netted,
    Settled,
    DefaultRemunerated,
    Disputed,
    Cancelled,
}

/// A status a whole cycle can be swept to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepTarget {
    Netted,
    Settled,
    DefaultRemunerated,
}

impl SweepTarget {
    fn target(self) -> TransitionTarget {
        match self {
            Self::Netted => TransitionTarget::Netted,
            Self::Settled => TransitionTarget::Settled,
            Self::DefaultRemunerated => TransitionTarget::DefaultRemunerated,
        }
    }

    /// The one status this sweep moves guarantees out of.
    fn from(self) -> GuaranteeSettlementStatus {
        match self {
            Self::Netted => GuaranteeSettlementStatus::FinalizedPayable,
            Self::Settled | Self::DefaultRemunerated => GuaranteeSettlementStatus::Netted,
        }
    }
}

impl TransitionTarget {
    /// The statuses this target may be reached from — the guarantee lifecycle, in one place.
    fn allowed_from(self) -> &'static [GuaranteeSettlementStatus] {
        match self {
            Self::FinalizedPayable | Self::Disputed | Self::Cancelled => UNRESOLVED,
            Self::Netted => FINALIZED_PAYABLE,
            Self::Settled | Self::DefaultRemunerated => NETTED,
        }
    }

    /// Whether reaching this target frees the collateral the guarantee locked.
    fn frees_collateral(self) -> bool {
        match self {
            Self::Disputed | Self::Cancelled | Self::Settled | Self::DefaultRemunerated => true,
            Self::FinalizedPayable | Self::Netted => false,
        }
    }

    fn status(self) -> GuaranteeSettlementStatus {
        match self {
            Self::FinalizedPayable => GuaranteeSettlementStatus::FinalizedPayable,
            Self::Netted => GuaranteeSettlementStatus::Netted,
            Self::Settled => GuaranteeSettlementStatus::Settled,
            Self::DefaultRemunerated => GuaranteeSettlementStatus::DefaultRemunerated,
            Self::Disputed => GuaranteeSettlementStatus::Disputed,
            Self::Cancelled => GuaranteeSettlementStatus::Cancelled,
        }
    }
}

async fn release<C: ConnectionTrait>(
    conn: &C,
    target: TransitionTarget,
    guarantees: &[CycleGuarantee],
) -> ServiceResult<()> {
    if !target.frees_collateral() {
        return Ok(());
    }
    for guarantee in guarantees {
        repo::release_locked_collateral_for_guarantee_on(conn, guarantee).await?;
    }
    Ok(())
}

/// A guarantee status change. Pick what to move, then where to.
///
/// ```ignore
/// GuaranteeTransition::guarantee(id).to(TransitionTarget::Disputed).run(txn).await?;
/// GuaranteeTransition::in_cycle(id).to(SweepTarget::Settled).at(now).by_payer(p).run(txn).await?;
/// ```
pub struct GuaranteeTransition;

impl GuaranteeTransition {
    /// One guarantee, by id.
    pub fn guarantee(guarantee_id: &str) -> SingleScope<'_> {
        SingleScope { guarantee_id }
    }

    /// Every guarantee in a cycle at the sweep's source status.
    pub fn in_cycle(cycle_id: &str) -> CycleScope<'_> {
        CycleScope { cycle_id }
    }
}

pub struct SingleScope<'a> {
    guarantee_id: &'a str,
}

impl<'a> SingleScope<'a> {
    pub fn to(self, target: TransitionTarget) -> SingleTransition<'a> {
        SingleTransition {
            guarantee_id: self.guarantee_id,
            target,
            now: Utc::now().naive_utc(),
        }
    }
}

pub struct CycleScope<'a> {
    cycle_id: &'a str,
}

impl<'a> CycleScope<'a> {
    pub fn to(self, sweep: SweepTarget) -> BulkTransition<'a> {
        BulkTransition {
            cycle_id: self.cycle_id,
            sweep,
            payer: None,
            now: Utc::now().naive_utc(),
        }
    }
}

pub struct SingleTransition<'a> {
    guarantee_id: &'a str,
    target: TransitionTarget,
    now: NaiveDateTime,
}

impl SingleTransition<'_> {
    /// Stamp the transition with `now` instead of the current time.
    pub fn at(mut self, now: NaiveDateTime) -> Self {
        self.now = now;
        self
    }

    /// `false` if the guarantee was already at the target. Errors if it does not exist, or is in a
    /// status the target cannot be reached from.
    pub async fn run<C: ConnectionTrait>(self, conn: &C) -> ServiceResult<bool> {
        let Self {
            guarantee_id,
            target,
            now,
        } = self;

        let guarantee = repo::get_guarantee_by_id_on(conn, guarantee_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Guarantee {guarantee_id}")))?;

        if guarantee.settlement_status == target.status() {
            return Ok(false);
        }
        if !target.allowed_from().contains(&guarantee.settlement_status) {
            return Err(ServiceError::InvalidParams(format!(
                "guarantee {guarantee_id} is {:?}, cannot transition to {target:?}",
                guarantee.settlement_status
            )));
        }

        let changed = repo::transition_guarantees_on(
            conn,
            GuaranteeSelector::id(guarantee_id, target.allowed_from()),
            target.status(),
            now,
        )
        .await?
            == 1;
        if changed {
            release(conn, target, std::slice::from_ref(&guarantee)).await?;
        }
        Ok(changed)
    }
}

pub struct BulkTransition<'a> {
    cycle_id: &'a str,
    sweep: SweepTarget,
    payer: Option<Address>,
    now: NaiveDateTime,
}

impl BulkTransition<'_> {
    /// Stamp the transition with `now` instead of the current time.
    pub fn at(mut self, now: NaiveDateTime) -> Self {
        self.now = now;
        self
    }

    /// Narrow to the guarantees this payer owes.
    pub fn by_payer(mut self, payer: Address) -> Self {
        self.payer = Some(payer);
        self
    }

    /// How many guarantees moved.
    pub async fn run<C: ConnectionTrait>(self, conn: &C) -> ServiceResult<u64> {
        let Self {
            cycle_id,
            sweep,
            payer,
            now,
        } = self;
        let target = sweep.target();
        let from = [sweep.from()];
        let selector = GuaranteeSelector::cycle(cycle_id, payer, &from);

        let guarantees = if target.frees_collateral() {
            repo::list_guarantees_on(conn, selector).await?
        } else {
            Vec::new()
        };
        let changed = repo::transition_guarantees_on(conn, selector, target.status(), now).await?;
        if changed > 0 {
            release(conn, target, &guarantees).await?;
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_is_reachable_and_only_from_earlier_states() {
        for target in [
            TransitionTarget::FinalizedPayable,
            TransitionTarget::Netted,
            TransitionTarget::Settled,
            TransitionTarget::DefaultRemunerated,
            TransitionTarget::Disputed,
            TransitionTarget::Cancelled,
        ] {
            let from = target.allowed_from();
            assert!(!from.is_empty(), "{target:?} has no way in");
            assert!(
                !from.contains(&target.status()),
                "{target:?} lists itself as a predecessor"
            );
        }
    }

    #[test]
    fn a_sweep_moves_guarantees_along_a_legal_edge() {
        // `SweepTarget::from` names the source directly, so it must agree with the lifecycle.
        for sweep in [
            SweepTarget::Netted,
            SweepTarget::Settled,
            SweepTarget::DefaultRemunerated,
        ] {
            let allowed = sweep.target().allowed_from();
            assert!(
                allowed.contains(&sweep.from()),
                "{sweep:?} sweeps from {:?}, which is not one of {allowed:?}",
                sweep.from()
            );
        }
    }

    #[test]
    fn collateral_is_freed_exactly_at_the_terminal_statuses() {
        assert!(TransitionTarget::Settled.frees_collateral());
        assert!(TransitionTarget::DefaultRemunerated.frees_collateral());
        assert!(TransitionTarget::Disputed.frees_collateral());
        assert!(TransitionTarget::Cancelled.frees_collateral());
        // Both still owe the payee, so the payer stays locked.
        assert!(!TransitionTarget::FinalizedPayable.frees_collateral());
        assert!(!TransitionTarget::Netted.frees_collateral());
    }
}
