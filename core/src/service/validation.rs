//! V2 validation lifecycle driver
//!
//! A validation-gated (V2) guarantee is stored `PendingValidation` at issuance. This module is
//! the missing driver that moves it out of that state by observing the on-chain ERC-8004
//! validation result named in the guarantee's policy:
//!
//! - resolved and accepted     -> `finalize_guarantee_payable` (nets and settles normally)
//! - resolved and rejected     -> `dispute_guarantee`          (releases the payer's collateral)
//! - unresolved past timeout    -> `cancel_guarantee`           (releases the payer's collateral)
//! - unresolved within timeout  -> left `PendingValidation`     (re-checked next sweep)
//!
//! The resolved-branch acceptance predicate mirrors `ValidationRegistryGuaranteeDecoder`
//! (`response >= min_validation_score`, validator match, agent match, tag match) so the
//! off-chain decision agrees with the on-chain verifier. Without this driver a V2 guarantee is
//!
//! A resolved-and-accepted validation is only honored while its settlement cycle can still be
//! netted (`Open`/`Frozen`). If the cycle already resolved before the validation landed — e.g.
//! the driver was down across the cycle's resolution, or the validation timeout was configured
//! longer than the cycle's resolution window — finalizing would move the guarantee into a dead
//! cycle that never settles, stranding the payer's collateral (the same L01/L02 failure, one hop
//! downstream). In that case the driver cancels and releases instead of finalizing.

use chrono::Utc;
use entities::guarantee;
use entities::sea_orm_active_enums::SettlementCycleStatus;
use log::{info, warn};
use rpc::{
    PaymentGuaranteeRequest, PaymentGuaranteeRequestEssentials, PaymentGuaranteeValidationPolicyV2,
};

use crate::ethereum::ValidationStatus;
use crate::persist::repo;
use crate::scheduler::{Task, async_trait};
use crate::service::CoreService;

/// What the driver should do with a single `PendingValidation` guarantee this sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationAction {
    /// Validation resolved and satisfies the policy: make the guarantee payable.
    Finalize,
    /// Validation resolved but violates the policy: dispute and release the payer's collateral.
    Dispute(&'static str),
    /// Validation cannot be honored (never resolved within the timeout, or resolved-and-accepted
    /// but its cycle already resolved): cancel and release the payer's collateral.
    Cancel(&'static str),
    /// Validation is still pending within the timeout window: re-check next sweep.
    Wait,
}

/// A `PendingValidation` guarantee can only be finalized into a cycle whose participant set is not
/// yet fixed — i.e. one still `Open` (will freeze and net later) or `Frozen` (about to net). Once
/// a cycle reaches `NettingComputed` or any later/terminal state, a late finalize would never be
/// included in a settlement and would strand the payer's collateral, so the driver cancels
/// instead.
fn cycle_still_nettable(status: &SettlementCycleStatus) -> bool {
    matches!(
        status,
        SettlementCycleStatus::Open | SettlementCycleStatus::Frozen
    )
}

/// Decide the lifecycle action for one guarantee. Pure and deterministic so it can be unit
/// tested exhaustively without a chain.
///
/// `status` is `None` when the registry read failed or returned nothing — treated identically
/// to an unresolved validation (wait, then cancel on timeout). The resolved branch mirrors the
/// acceptance checks in `ValidationRegistryGuaranteeDecoder`.
fn decide_validation_action(
    policy: &PaymentGuaranteeValidationPolicyV2,
    status: Option<&ValidationStatus>,
    issued_at_unix: u64,
    now_unix: u64,
    timeout_secs: u64,
) -> ValidationAction {
    match status {
        Some(s) if s.is_resolved() => {
            if s.response < policy.min_validation_score {
                ValidationAction::Dispute("validation score below minimum")
            } else if s.validator_address != policy.validator_address {
                ValidationAction::Dispute("validator address mismatch")
            } else if s.agent_id != policy.validator_agent_id {
                ValidationAction::Dispute("validator agent id mismatch")
            } else if !policy.required_validation_tag.is_empty()
                && s.tag != policy.required_validation_tag
            {
                ValidationAction::Dispute("validation tag mismatch")
            } else {
                ValidationAction::Finalize
            }
        }
        // Unresolved or unreadable: wait until the timeout, then cancel so the payer's collateral
        // is never stranded on a validation that resolves late or never.
        _ => {
            if now_unix.saturating_sub(issued_at_unix) >= timeout_secs {
                ValidationAction::Cancel("validation did not resolve before timeout")
            } else {
                ValidationAction::Wait
            }
        }
    }
}

/// Tally of one validation sweep, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ValidationSweepSummary {
    pub finalized: usize,
    pub disputed: usize,
    pub cancelled: usize,
    pub waiting: usize,
    pub errored: usize,
}

/// Clamp a Unix timestamp to a non-negative `u64` (timestamps before the epoch collapse to 0).
fn unix_secs(ts: i64) -> u64 {
    ts.max(0) as u64
}

impl CoreService {
    /// One pass of the V2 validation lifecycle driver: resolve every `PendingValidation`
    /// guarantee against its on-chain validation result and transition it accordingly. A
    /// per-guarantee failure is logged and skipped so one bad guarantee cannot stall the sweep.
    /// No-op unless `ENABLE_V2_VALIDATION_LIFECYCLE` is set.
    pub async fn drive_pending_validations(&self) -> anyhow::Result<ValidationSweepSummary> {
        if !self.inner.enable_v2_validation_lifecycle {
            return Ok(ValidationSweepSummary::default());
        }

        let timeout_secs = self.inner.config.guarantee.validation_timeout_secs;
        let now_unix = unix_secs(Utc::now().timestamp());
        let pending =
            repo::list_pending_validation_guarantees_on(self.inner.persist_ctx.db.as_ref()).await?;

        let mut summary = ValidationSweepSummary::default();
        for guarantee in pending {
            match self
                .drive_one_pending_validation(&guarantee, now_unix, timeout_secs)
                .await
            {
                Ok(ValidationAction::Finalize) => summary.finalized += 1,
                Ok(ValidationAction::Dispute(_)) => summary.disputed += 1,
                Ok(ValidationAction::Cancel(_)) => summary.cancelled += 1,
                Ok(ValidationAction::Wait) => summary.waiting += 1,
                Err(err) => {
                    summary.errored += 1;
                    warn!(
                        "validation lifecycle: guarantee {} skipped this sweep: {err:#}",
                        guarantee.guarantee_id
                    );
                }
            }
        }
        Ok(summary)
    }

    /// Resolve and transition a single `PendingValidation` guarantee. Returns the action taken so
    /// the caller can tally it.
    async fn drive_one_pending_validation(
        &self,
        guarantee: &guarantee::Model,
        now_unix: u64,
        timeout_secs: u64,
    ) -> anyhow::Result<ValidationAction> {
        let request_json = guarantee.request.as_deref().ok_or_else(|| {
            anyhow::anyhow!("guarantee {} has no stored request", guarantee.guarantee_id)
        })?;
        let request: PaymentGuaranteeRequest = serde_json::from_str(request_json)?;
        let policy = request
            .claims
            .validation_policy()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "PendingValidation guarantee {} carries no validation policy",
                    guarantee.guarantee_id
                )
            })?
            .clone();

        // A registry read failure (transport, revert, or a no-code registry) is treated like an
        // unresolved validation: wait, and cancel once the timeout elapses.
        let status = match self
            .inner
            .contract_api
            .get_validation_status(
                policy.validation_registry_address,
                policy.validation_request_hash,
            )
            .await
        {
            Ok(status) => Some(status),
            Err(err) => {
                warn!(
                    "validation lifecycle: status read failed for guarantee {}: {err}",
                    guarantee.guarantee_id
                );
                None
            }
        };

        let issued_at_unix = unix_secs(guarantee.created_at.and_utc().timestamp());
        let action = decide_validation_action(
            &policy,
            status.as_ref(),
            issued_at_unix,
            now_unix,
            timeout_secs,
        );

        // A resolved-and-accepted validation can only be finalized while its cycle is still
        // nettable. If the cycle already resolved, finalizing would strand the payer's collateral
        // in a dead cycle, so downgrade to a cancel that releases it instead.
        let action = match action {
            ValidationAction::Finalize
                if !self
                    .guarantee_cycle_still_nettable(&guarantee.cycle_id)
                    .await? =>
            {
                ValidationAction::Cancel(
                    "settlement cycle already resolved before validation landed",
                )
            }
            other => other,
        };

        match action {
            ValidationAction::Finalize => {
                self.finalize_guarantee_payable(&guarantee.guarantee_id)
                    .await?;
                info!(
                    "validation lifecycle: finalized guarantee {}",
                    guarantee.guarantee_id
                );
            }
            ValidationAction::Dispute(reason) => {
                self.dispute_guarantee(&guarantee.guarantee_id).await?;
                info!(
                    "validation lifecycle: disputed guarantee {} ({reason})",
                    guarantee.guarantee_id
                );
            }
            ValidationAction::Cancel(reason) => {
                self.cancel_guarantee(&guarantee.guarantee_id).await?;
                info!(
                    "validation lifecycle: cancelled guarantee {} ({reason})",
                    guarantee.guarantee_id
                );
            }
            ValidationAction::Wait => {}
        }
        Ok(action)
    }

    /// True if the guarantee's settlement cycle can still include it in a netting round. A missing
    /// cycle (deleted, or an orphaned reference) is treated as not nettable so the guarantee is
    /// cancelled and its collateral released rather than left stranded.
    async fn guarantee_cycle_still_nettable(&self, cycle_id: &str) -> anyhow::Result<bool> {
        let cycle = repo::get_cycle_by_id_on(self.inner.persist_ctx.db.as_ref(), cycle_id).await?;
        Ok(cycle
            .map(|c| cycle_still_nettable(&c.status))
            .unwrap_or(false))
    }
}

/// Scheduled task that periodically runs the V2 validation lifecycle sweep.
pub struct ValidationLifecycleTask(CoreService);

impl ValidationLifecycleTask {
    pub fn new(service: CoreService) -> Self {
        Self(service)
    }
}

#[async_trait]
impl Task for ValidationLifecycleTask {
    fn cron_pattern(&self) -> String {
        self.0.inner.config.guarantee.validation_poll_cron.clone()
    }

    async fn run(&self) -> anyhow::Result<()> {
        let summary = self.0.drive_pending_validations().await?;
        if summary != ValidationSweepSummary::default() {
            info!(
                "validation lifecycle sweep: finalized={}, disputed={}, cancelled={}, waiting={}, errored={}",
                summary.finalized,
                summary.disputed,
                summary.cancelled,
                summary.waiting,
                summary.errored
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256, U256};

    fn policy() -> PaymentGuaranteeValidationPolicyV2 {
        PaymentGuaranteeValidationPolicyV2 {
            validation_registry_address: Address::repeat_byte(0x33),
            validation_request_hash: B256::repeat_byte(0x44),
            validation_chain_id: 84532,
            validator_address: Address::repeat_byte(0x55),
            validator_agent_id: U256::from(7u64),
            min_validation_score: 80,
            validation_subject_hash: B256::repeat_byte(0x66),
            job_hash: B256::repeat_byte(0x77),
            required_validation_tag: "hard-finality".to_string(),
        }
    }

    /// A resolved status that satisfies `policy()` exactly.
    fn passing_status() -> ValidationStatus {
        ValidationStatus {
            validator_address: Address::repeat_byte(0x55),
            agent_id: U256::from(7u64),
            response: 80,
            tag: "hard-finality".to_string(),
            last_update: U256::from(1_700_000_000u64),
        }
    }

    fn decide(
        status: Option<&ValidationStatus>,
        issued: u64,
        now: u64,
        timeout: u64,
    ) -> ValidationAction {
        decide_validation_action(&policy(), status, issued, now, timeout)
    }

    #[test]
    fn resolved_and_satisfying_policy_finalizes() {
        assert_eq!(
            decide(Some(&passing_status()), 0, 100, 3600),
            ValidationAction::Finalize
        );
    }

    #[test]
    fn score_below_minimum_disputes() {
        let mut s = passing_status();
        s.response = 79;
        assert!(matches!(
            decide(Some(&s), 0, 100, 3600),
            ValidationAction::Dispute(_)
        ));
    }

    #[test]
    fn validator_mismatch_disputes() {
        let mut s = passing_status();
        s.validator_address = Address::repeat_byte(0xAB);
        assert!(matches!(
            decide(Some(&s), 0, 100, 3600),
            ValidationAction::Dispute(_)
        ));
    }

    #[test]
    fn agent_mismatch_disputes() {
        let mut s = passing_status();
        s.agent_id = U256::from(9u64);
        assert!(matches!(
            decide(Some(&s), 0, 100, 3600),
            ValidationAction::Dispute(_)
        ));
    }

    #[test]
    fn tag_mismatch_disputes() {
        let mut s = passing_status();
        s.tag = "soft".to_string();
        assert!(matches!(
            decide(Some(&s), 0, 100, 3600),
            ValidationAction::Dispute(_)
        ));
    }

    #[test]
    fn empty_required_tag_skips_tag_check() {
        let mut p = policy();
        p.required_validation_tag = String::new();
        let mut s = passing_status();
        s.tag = "anything".to_string();
        assert_eq!(
            decide_validation_action(&p, Some(&s), 0, 100, 3600),
            ValidationAction::Finalize
        );
    }

    #[test]
    fn unresolved_within_timeout_waits() {
        // lastUpdate == 0 means still pending.
        let mut s = passing_status();
        s.last_update = U256::ZERO;
        assert_eq!(decide(Some(&s), 0, 100, 3600), ValidationAction::Wait);
    }

    #[test]
    fn unresolved_past_timeout_cancels() {
        let mut s = passing_status();
        s.last_update = U256::ZERO;
        assert!(matches!(
            decide(Some(&s), 0, 3600, 3600),
            ValidationAction::Cancel(_)
        ));
    }

    #[test]
    fn unreadable_status_waits_then_cancels_on_timeout() {
        assert_eq!(decide(None, 0, 100, 3600), ValidationAction::Wait);
        assert!(matches!(
            decide(None, 0, 3600, 3600),
            ValidationAction::Cancel(_)
        ));
    }

    #[test]
    fn only_open_and_frozen_cycles_are_nettable() {
        assert!(cycle_still_nettable(&SettlementCycleStatus::Open));
        assert!(cycle_still_nettable(&SettlementCycleStatus::Frozen));
        for resolved in [
            SettlementCycleStatus::NettingComputed,
            SettlementCycleStatus::ClearingCommitted,
            SettlementCycleStatus::PaymentWindowOpen,
            SettlementCycleStatus::Finalized,
            SettlementCycleStatus::Settling,
            SettlementCycleStatus::Cancelled,
            SettlementCycleStatus::Shortfall,
        ] {
            assert!(
                !cycle_still_nettable(&resolved),
                "{resolved:?} must not be nettable"
            );
        }
    }
}
