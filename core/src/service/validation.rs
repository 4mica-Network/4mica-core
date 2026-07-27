//! Validation lifecycle driver.
//!
//! A validation-gated guarantee is stored `PendingValidation` at issuance. This driver moves it
//! out of that state by asking the guarantee's validator adapter for a verdict:
//!
//! - approved before the deadline  -> `finalize_guarantee_payable_on` (nets and settles normally)
//! - rejected                      -> `dispute_guarantee_on`          (releases the payer's collateral)
//! - still pending at the deadline -> `cancel_guarantee_on`           (releases the payer's collateral)
//! - still pending before it       -> left `PendingValidation`        (re-checked next sweep)
//! - validator de-whitelisted      -> `finalize_guarantee_payable_on` (nothing gates it any more)
//!
//! Whether a validator's answer means approved or rejected is the adapter's decision, not this
//! module's. The transition and the validation record are written in a single transaction.

use std::matches;

use chrono::{NaiveDateTime, Utc};
use entities::guarantee_validation;
use entities::sea_orm_active_enums::{GuaranteeValidationStatus, SettlementCycleStatus};
use log::{info, warn};
use rpc::ValidationRequirement;
use sea_orm::{ConnectionTrait, TransactionTrait};
use validators::{Verdict, VerdictStatus};

use crate::error::ServiceError;
use crate::persist::repo;
use crate::scheduler::{Task, async_trait};
use crate::service::CoreService;

/// What the driver should do with a single `PendingValidation` guarantee this sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationAction {
    Finalize,
    Dispute(&'static str),
    Cancel(&'static str),
    Skip,
    Wait,
}

impl ValidationAction {
    fn from_verdict(
        verdict: &Verdict,
        expected_subject: &str,
        deadline: NaiveDateTime,
        now: NaiveDateTime,
    ) -> Self {
        // An answer about a different subject says nothing about this guarantee, so it can never
        // dispute it — it stays unresolved and expires at its deadline like any other.
        if verdict.subject.to_string() != expected_subject {
            return if now >= deadline {
                Self::Cancel("validator answered about a different subject")
            } else {
                Self::Wait
            };
        }

        match verdict.status {
            VerdictStatus::Approved if now < deadline => Self::Finalize,
            VerdictStatus::Approved => Self::Cancel("validation approved after deadline"),
            VerdictStatus::Rejected => Self::Dispute("validator rejected the guarantee"),
            VerdictStatus::Pending if now >= deadline => {
                Self::Cancel("validation did not resolve before deadline")
            }
            VerdictStatus::Pending => Self::Wait,
        }
    }
}

/// A guarantee can only be finalized into a cycle that has not yet netted. Finalizing into a
/// later state would leave it in a cycle that never settles, stranding the payer's collateral.
fn cycle_still_nettable(status: &SettlementCycleStatus) -> bool {
    matches!(
        status,
        SettlementCycleStatus::Open | SettlementCycleStatus::Frozen
    )
}

/// Tally of one validation sweep, for logging and tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ValidationSweepSummary {
    pub finalized: usize,
    pub disputed: usize,
    pub cancelled: usize,
    pub skipped: usize,
    pub waiting: usize,
    pub errored: usize,
}

impl CoreService {
    /// One pass of the validation lifecycle: resolve every pending validation against its
    /// validator and transition the guarantee accordingly. A per-guarantee failure is logged and
    /// skipped so one bad validator cannot stall the sweep.
    pub async fn drive_pending_validations(&self) -> anyhow::Result<ValidationSweepSummary> {
        let now = Utc::now().naive_utc();
        let pending =
            repo::list_pending_guarantee_validations_on(self.inner.persist_ctx.db.as_ref()).await?;

        let mut summary = ValidationSweepSummary::default();
        for validation in pending {
            match self.drive_one_pending_validation(&validation, now).await {
                Ok(ValidationAction::Finalize) => summary.finalized += 1,
                Ok(ValidationAction::Dispute(_)) => summary.disputed += 1,
                Ok(ValidationAction::Cancel(_)) => summary.cancelled += 1,
                Ok(ValidationAction::Skip) => summary.skipped += 1,
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
        let (action, verdict) = self.run_adapter_and_decide_action(validation, now).await?;
        let evidence = verdict.map(|v| v.evidence.to_vec());
        let guarantee_id = validation.guarantee_id.clone();

        self.inner
            .persist_ctx
            .db
            .transaction::<_, (), ServiceError>(|txn| {
                let service = self.clone();
                let guarantee_id = guarantee_id.clone();
                let evidence = evidence.clone();
                Box::pin(async move {
                    let decision = match action {
                        ValidationAction::Finalize => {
                            service
                                .finalize_guarantee_payable_on(txn, &guarantee_id)
                                .await?;
                            GuaranteeValidationStatus::Approved
                        }
                        ValidationAction::Dispute(_) => {
                            service.dispute_guarantee_on(txn, &guarantee_id).await?;
                            GuaranteeValidationStatus::Rejected
                        }
                        ValidationAction::Cancel(_) => {
                            service.cancel_guarantee_on(txn, &guarantee_id).await?;
                            GuaranteeValidationStatus::Expired
                        }
                        ValidationAction::Skip => {
                            // No validator gates it any more, so make it payable for its cycle.
                            service
                                .finalize_guarantee_payable_on(txn, &guarantee_id)
                                .await?;
                            GuaranteeValidationStatus::Skipped
                        }
                        ValidationAction::Wait => {
                            repo::record_guarantee_validation_poll_on(txn, &guarantee_id, evidence)
                                .await?;
                            return Ok(());
                        }
                    };
                    repo::decide_guarantee_validation_on(txn, &guarantee_id, decision, evidence)
                        .await?;

                    Ok(())
                })
            })
            .await
            .map_err(|e| match e {
                sea_orm::TransactionError::Transaction(inner) => anyhow::Error::from(inner),
                sea_orm::TransactionError::Connection(err) => anyhow::Error::from(err),
            })?;

        match action {
            ValidationAction::Finalize => info!(
                "validation lifecycle: finalized guarantee {}",
                validation.guarantee_id
            ),
            ValidationAction::Dispute(reason) => info!(
                "validation lifecycle: disputed guarantee {} ({reason})",
                validation.guarantee_id
            ),
            ValidationAction::Cancel(reason) => info!(
                "validation lifecycle: cancelled guarantee {} ({reason})",
                validation.guarantee_id
            ),
            ValidationAction::Skip => info!(
                "validation lifecycle: skipped guarantee {}",
                validation.guarantee_id
            ),
            ValidationAction::Wait => {}
        }
        Ok(action)
    }

    async fn run_adapter_and_decide_action(
        &self,
        validation: &guarantee_validation::Model,
        now: NaiveDateTime,
    ) -> anyhow::Result<(ValidationAction, Option<Verdict>)> {
        let Some(adapter) = self.inner.validators.get(&validation.validator) else {
            warn!(
                "validator {} is no longer whitelisted; skipping validation for guarantee {}",
                validation.validator, validation.guarantee_id
            );
            return Ok((ValidationAction::Skip, None));
        };

        let requirement = ValidationRequirement {
            validator: validation.validator.clone(),
            subject: validation.subject.parse()?,
            deadline: Some(validation.deadline.and_utc().timestamp().max(0) as u64),
            params: validation.params.clone().into(),
        };
        let verdict = adapter.resolve(&requirement).await?;
        let action =
            ValidationAction::from_verdict(&verdict, &validation.subject, validation.deadline, now);

        // Finalizing into a cycle that already resolved would strand the payer's collateral there,
        // so a cancel that releases it is the only thing left to do.
        let action = match action {
            ValidationAction::Finalize
                if !guarantee_cycle_still_nettable(
                    self.persist_ctx().db.as_ref(),
                    &validation.guarantee_id,
                )
                .await? =>
            {
                ValidationAction::Cancel(
                    "settlement cycle already resolved before validation landed",
                )
            }
            other => other,
        };

        Ok((action, Some(verdict)))
    }
}

/// True if the guarantee's settlement cycle can still include it in a netting round. A missing
/// guarantee or cycle is treated as not nettable so the guarantee is cancelled and its collateral
/// released rather than left stranded.
async fn guarantee_cycle_still_nettable<C: ConnectionTrait>(
    conn: &C,
    guarantee_id: &str,
) -> Result<bool, ServiceError> {
    let Some(guarantee) = repo::get_guarantee_by_id_on(conn, guarantee_id).await? else {
        return Ok(false);
    };
    let cycle = repo::get_cycle_by_id_on(conn, &guarantee.cycle_id).await?;
    Ok(cycle
        .map(|c| cycle_still_nettable(&c.status))
        .unwrap_or(false))
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
                "validation lifecycle sweep: finalized={}, disputed={}, cancelled={}, skipped={}, waiting={}, errored={}",
                summary.finalized,
                summary.disputed,
                summary.cancelled,
                summary.skipped,
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

    fn action_at(status: VerdictStatus, now: i64) -> ValidationAction {
        ValidationAction::from_verdict(
            &verdict(status, subject()),
            &subject().to_string(),
            naive(1_000),
            naive(now),
        )
    }

    #[test]
    fn approved_before_deadline_finalizes() {
        assert_eq!(
            action_at(VerdictStatus::Approved, 500),
            ValidationAction::Finalize
        );
    }

    #[test]
    fn approved_after_deadline_cancels() {
        assert!(matches!(
            action_at(VerdictStatus::Approved, 1_500),
            ValidationAction::Cancel(_)
        ));
    }

    #[test]
    fn rejected_disputes_regardless_of_deadline() {
        for now in [500, 1_500] {
            assert!(matches!(
                action_at(VerdictStatus::Rejected, now),
                ValidationAction::Dispute(_)
            ));
        }
    }

    #[test]
    fn pending_waits_then_cancels_at_the_deadline() {
        assert_eq!(
            action_at(VerdictStatus::Pending, 999),
            ValidationAction::Wait
        );
        assert!(matches!(
            action_at(VerdictStatus::Pending, 1_000),
            ValidationAction::Cancel(_)
        ));
    }

    #[test]
    fn subject_mismatch_never_disputes() {
        let action = ValidationAction::from_verdict(
            &verdict(VerdictStatus::Rejected, B256::repeat_byte(0xAB)),
            &subject().to_string(),
            naive(1_000),
            naive(500),
        );
        assert_eq!(action, ValidationAction::Wait);
    }

    #[test]
    fn only_pre_netting_cycles_are_nettable() {
        assert!(cycle_still_nettable(&SettlementCycleStatus::Open));
        assert!(cycle_still_nettable(&SettlementCycleStatus::Frozen));

        for status in [
            SettlementCycleStatus::NettingComputed,
            SettlementCycleStatus::ClearingCommitted,
            SettlementCycleStatus::PaymentWindowOpen,
            SettlementCycleStatus::Finalized,
            SettlementCycleStatus::Settling,
            SettlementCycleStatus::Cancelled,
            SettlementCycleStatus::Shortfall,
        ] {
            assert!(!cycle_still_nettable(&status), "{status:?} is not nettable");
        }
    }
}
