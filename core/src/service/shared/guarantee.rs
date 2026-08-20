//! Guarantee settlement-status transitions.
//!
//! Every method takes the connection so callers can compose them into a larger transaction.

use chrono::Utc;
use entities::sea_orm_active_enums::GuaranteeSettlementStatus;
use sea_orm::ConnectionTrait;

use crate::error::{ServiceError, ServiceResult};
use crate::persist::repo;

/// The statuses a guarantee may still leave; anything further along is terminal.
const OPEN_STATUSES: &[GuaranteeSettlementStatus] = &[
    GuaranteeSettlementStatus::Issued,
    GuaranteeSettlementStatus::PendingValidation,
];

/// Guarantee settlement-status transitions. Stateless: every method writes through the
/// connection it is handed, so callers can compose them into their own transaction.
#[derive(Default)]
pub struct GuaranteeOps;

impl GuaranteeOps {
    pub fn new() -> Self {
        Self
    }

    pub async fn finalize_payable_on<C: ConnectionTrait>(
        &self,
        conn: &C,
        guarantee_id: &str,
    ) -> ServiceResult<bool> {
        self.transition_on(
            conn,
            guarantee_id,
            GuaranteeSettlementStatus::FinalizedPayable,
            false,
        )
        .await
    }

    pub async fn dispute_on<C: ConnectionTrait>(
        &self,
        conn: &C,
        guarantee_id: &str,
    ) -> ServiceResult<bool> {
        self.transition_on(
            conn,
            guarantee_id,
            GuaranteeSettlementStatus::Disputed,
            true,
        )
        .await
    }

    pub async fn cancel_on<C: ConnectionTrait>(
        &self,
        conn: &C,
        guarantee_id: &str,
    ) -> ServiceResult<bool> {
        self.transition_on(
            conn,
            guarantee_id,
            GuaranteeSettlementStatus::Cancelled,
            true,
        )
        .await
    }

    async fn transition_on<C: ConnectionTrait>(
        &self,
        conn: &C,
        guarantee_id: &str,
        target: GuaranteeSettlementStatus,
        release_locked_collateral: bool,
    ) -> ServiceResult<bool> {
        let allowed_from = OPEN_STATUSES;
        let guarantee = repo::get_guarantee_by_id_on(conn, guarantee_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Guarantee {guarantee_id}")))?;

        if guarantee.settlement_status == target {
            return Ok(false);
        }
        if !allowed_from.contains(&guarantee.settlement_status) {
            return Err(ServiceError::InvalidParams(format!(
                "guarantee {guarantee_id} is {:?}, cannot transition to {:?}",
                guarantee.settlement_status, target
            )));
        }

        let changed = repo::transition_guarantee_settlement_status_on(
            conn,
            guarantee_id,
            allowed_from,
            target,
            Utc::now().naive_utc(),
        )
        .await?;
        if changed && release_locked_collateral {
            repo::release_locked_collateral_for_guarantee_on(conn, &guarantee).await?;
        }
        Ok(changed)
    }
}
