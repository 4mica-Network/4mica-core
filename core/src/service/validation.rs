//! Validation lifecycle driver.
//!
//! A validation-gated guarantee is stored `PendingValidation` at issuance. This driver moves it
//! out of that state by asking the guarantee's validator adapter for a verdict:
//!
//! - approved before the deadline  -> `finalize_guarantee_payable` (nets and settles normally)
//! - rejected                      -> `dispute_guarantee`          (releases the payer's collateral)
//! - still pending at the deadline -> `cancel_guarantee`           (releases the payer's collateral)
//! - still pending before it       -> left `PendingValidation`     (re-checked next sweep)
//!
//! Whether a validator's answer means approved or rejected is the adapter's decision, not this
//! module's.

use std::matches;

use chrono::{NaiveDateTime, Utc};
use entities::guarantee_validation;
use entities::sea_orm_active_enums::{GuaranteeValidationStatus, SettlementCycleStatus};
use log::{info, warn};
use rpc::ValidationRequirement;
use validators::{Verdict, VerdictStatus};

use crate::persist::repo;
use crate::scheduler::{Task, async_trait};
use crate::service::CoreService;

/// What the driver should do with a single `PendingValidation` guarantee this sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationAction {
    Finalize,
    Dispute(&'static str),
    Cancel(&'static str),
    Wait,
}

/// A guarantee can only be finalized into a cycle that has not yet netted. Finalizing into a
/// later state would leave it in a cycle that never settles, stranding the payer's collateral.
fn cycle_still_nettable(status: &SettlementCycleStatus) -> bool {
    matches!(
        status,
        SettlementCycleStatus::Open | SettlementCycleStatus::Frozen
    )
}

/// A subject mismatch means the adapter answered about a different guarantee, which is never a
/// reason to reject this one.
fn decide_validation_action(
    verdict: &Verdict,
    expected_subject: &str,
    deadline: NaiveDateTime,
    now: NaiveDateTime,
) -> ValidationAction {
    if verdict.subject.to_string() != expected_subject {
        return if now >= deadline {
            ValidationAction::Cancel("validator answered about a different subject")
        } else {
            ValidationAction::Wait
        };
    }

    match verdict.status {
        VerdictStatus::Approved if now < deadline => ValidationAction::Finalize,
        VerdictStatus::Approved => ValidationAction::Cancel("validation approved after deadline"),
        VerdictStatus::Rejected => ValidationAction::Dispute("validator rejected the guarantee"),
        VerdictStatus::Pending if now >= deadline => {
            ValidationAction::Cancel("validation did not resolve before deadline")
        }
        VerdictStatus::Pending => ValidationAction::Wait,
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

impl CoreService {
    /// One pass of the validation lifecycle: resolve every pending validation against its
    /// validator and transition the guarantee accordingly. A per-guarantee failure is logged and
    /// skipped so one bad validator cannot stall the sweep.
    pub async fn drive_pending_validations(&self) -> anyhow::Result<ValidationSweepSummary> {
        if self.inner.validators.is_empty() {
            return Ok(ValidationSweepSummary::default());
        }

        let now = Utc::now().naive_utc();
        let pending =
            repo::list_pending_guarantee_validations_on(self.inner.persist_ctx.db.as_ref()).await?;

        let mut summary = ValidationSweepSummary::default();
        for validation in pending {
            match self.drive_one_pending_validation(&validation, now).await {
                Ok(ValidationAction::Finalize) => summary.finalized += 1,
                Ok(ValidationAction::Dispute(_)) => summary.disputed += 1,
                Ok(ValidationAction::Cancel(_)) => summary.cancelled += 1,
                Ok(ValidationAction::Wait) => summary.waiting += 1,
                Err(err) => {
                    summary.errored += 1;
                    warn!(
                        "validation lifecycle: guarantee {} skipped this sweep: {err:#}",
                        validation.guarantee_id
                    );
                }
            }
        }
        Ok(summary)
    }

    async fn drive_one_pending_validation(
        &self,
        validation: &guarantee_validation::Model,
        now: NaiveDateTime,
    ) -> anyhow::Result<ValidationAction> {
        let adapter = self
            .inner
            .validators
            .get(&validation.validator)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "validator {} is no longer whitelisted; guarantee {} will expire at its deadline",
                    validation.validator,
                    validation.guarantee_id
                )
            })?;

        let requirement = ValidationRequirement {
            validator: validation.validator.clone(),
            subject: validation.subject.parse()?,
            deadline: Some(validation.deadline.and_utc().timestamp().max(0) as u64),
            params: validation.params.clone().into(),
        };

        let verdict = adapter.resolve(&requirement).await?;
        let action =
            decide_validation_action(&verdict, &validation.subject, validation.deadline, now);

        // A resolved-and-accepted validation can only be finalized while its cycle is still
        // nettable. If the cycle already resolved, finalizing would strand the payer's collateral
        // in a dead cycle, so downgrade to a cancel that releases it instead.
        let action = match action {
            ValidationAction::Finalize
                if !self
                    .guarantee_cycle_still_nettable(&validation.guarantee_id)
                    .await? =>
            {
                ValidationAction::Cancel(
                    "settlement cycle already resolved before validation landed",
                )
            }
            other => other,
        };

        let evidence = Some(verdict.evidence.to_vec());
        match action {
            ValidationAction::Finalize => {
                self.finalize_guarantee_payable(&validation.guarantee_id)
                    .await?;
                self.record_validation_decision(
                    &validation.guarantee_id,
                    GuaranteeValidationStatus::Approved,
                    evidence,
                )
                .await?;
                info!(
                    "validation lifecycle: finalized guarantee {}",
                    validation.guarantee_id
                );
            }
            ValidationAction::Dispute(reason) => {
                self.dispute_guarantee(&validation.guarantee_id).await?;
                self.record_validation_decision(
                    &validation.guarantee_id,
                    GuaranteeValidationStatus::Rejected,
                    evidence,
                )
                .await?;
                info!(
                    "validation lifecycle: disputed guarantee {} ({reason})",
                    validation.guarantee_id
                );
            }
            ValidationAction::Cancel(reason) => {
                self.cancel_guarantee(&validation.guarantee_id).await?;
                self.record_validation_decision(
                    &validation.guarantee_id,
                    GuaranteeValidationStatus::Expired,
                    evidence,
                )
                .await?;
                info!(
                    "validation lifecycle: cancelled guarantee {} ({reason})",
                    validation.guarantee_id
                );
            }
            ValidationAction::Wait => {
                repo::record_guarantee_validation_poll_on(
                    self.inner.persist_ctx.db.as_ref(),
                    &validation.guarantee_id,
                    evidence,
                )
                .await?;
            }
        }
        Ok(action)
    }

    async fn record_validation_decision(
        &self,
        guarantee_id: &str,
        status: GuaranteeValidationStatus,
        evidence: Option<Vec<u8>>,
    ) -> anyhow::Result<()> {
        repo::decide_guarantee_validation_on(
            self.inner.persist_ctx.db.as_ref(),
            guarantee_id,
            status,
            evidence,
        )
        .await?;
        Ok(())
    }

    /// True if the guarantee's settlement cycle can still include it in a netting round. A missing
    /// guarantee or cycle is treated as not nettable so the guarantee is cancelled and its
    /// collateral released rather than left stranded.
    async fn guarantee_cycle_still_nettable(&self, guarantee_id: &str) -> anyhow::Result<bool> {
        let Some(guarantee) =
            repo::get_guarantee_by_id_on(self.inner.persist_ctx.db.as_ref(), guarantee_id).await?
        else {
            return Ok(false);
        };
        let cycle =
            repo::get_cycle_by_id_on(self.inner.persist_ctx.db.as_ref(), &guarantee.cycle_id)
                .await?;
        Ok(cycle
            .map(|c| cycle_still_nettable(&c.status))
            .unwrap_or(false))
    }
}

/// Scheduled task that periodically runs the validation lifecycle sweep.
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
    use alloy::primitives::B256;
    use chrono::DateTime;

    fn naive(unix: i64) -> NaiveDateTime {
        DateTime::from_timestamp(unix, 0)
            .expect("valid timestamp")
            .naive_utc()
    }

    fn verdict(status: VerdictStatus, subject: B256) -> Verdict {
        Verdict {
            status,
            subject,
            evidence: Default::default(),
            observed_at: 1_700_000_000,
        }
    }

    fn subject() -> B256 {
        B256::repeat_byte(0x11)
    }

    #[test]
    fn approved_before_deadline_finalizes() {
        let action = decide_validation_action(
            &verdict(VerdictStatus::Approved, subject()),
            &subject().to_string(),
            naive(1_000),
            naive(500),
        );
        assert_eq!(action, ValidationAction::Finalize);
    }

    #[test]
    fn approved_after_deadline_cancels() {
        let action = decide_validation_action(
            &verdict(VerdictStatus::Approved, subject()),
            &subject().to_string(),
            naive(1_000),
            naive(1_500),
        );
        assert!(matches!(action, ValidationAction::Cancel(_)));
    }

    #[test]
    fn rejected_disputes_regardless_of_deadline() {
        for now in [500, 1_500] {
            let action = decide_validation_action(
                &verdict(VerdictStatus::Rejected, subject()),
                &subject().to_string(),
                naive(1_000),
                naive(now),
            );
            assert!(matches!(action, ValidationAction::Dispute(_)));
        }
    }

    #[test]
    fn pending_waits_then_cancels_at_the_deadline() {
        let before = decide_validation_action(
            &verdict(VerdictStatus::Pending, subject()),
            &subject().to_string(),
            naive(1_000),
            naive(999),
        );
        assert_eq!(before, ValidationAction::Wait);

        let after = decide_validation_action(
            &verdict(VerdictStatus::Pending, subject()),
            &subject().to_string(),
            naive(1_000),
            naive(1_000),
        );
        assert!(matches!(after, ValidationAction::Cancel(_)));
    }

    #[test]
    fn subject_mismatch_never_disputes() {
        let action = decide_validation_action(
            &verdict(VerdictStatus::Rejected, B256::repeat_byte(0xAB)),
            &subject().to_string(),
            naive(1_000),
            naive(500),
        );
        assert_eq!(action, ValidationAction::Wait);
    }
}
