use chrono::Utc;
use entities::sea_orm_active_enums::SettlementCycleStatus;
use log::info;

use crate::{
    error::{ServiceError, ServiceResult},
    persist::repo,
    service::CoreService,
};

impl CoreService {
    pub async fn commit_cycle_to_chain(&self, cycle_id: &str) -> ServiceResult<()> {
        let cycle = repo::get_cycle_by_id(&self.inner.persist_ctx, cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;
        if cycle.status != SettlementCycleStatus::NettingComputed {
            return Err(ServiceError::InvalidParams(format!(
                "settlement cycle {cycle_id} is {:?}, expected {:?}",
                cycle.status,
                SettlementCycleStatus::NettingComputed
            )));
        }

        let _batch =
            repo::get_clearing_batch_by_cycle_on(self.inner.persist_ctx.db.as_ref(), cycle_id)
                .await?
                .ok_or_else(|| {
                    ServiceError::InvalidParams(format!(
                        "settlement cycle {cycle_id} has no clearing batch"
                    ))
                })?;

        // Phase 1 bridge: the ClearingHouse transaction sender is added in the cutover phase.
        let changed = repo::mark_cycle_payment_window_open_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            None,
            Utc::now().naive_utc(),
        )
        .await?;
        if changed {
            info!("marked settlement cycle {} payment window open", cycle_id);
        }
        Ok(())
    }

    pub async fn process_paid_debtor(
        &self,
        cycle_id: &str,
        debtor: &str,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        info!(
            "payment event bridge received: cycle={}, debtor={}, tx={}",
            cycle_id, debtor, tx_hash
        );
        Ok(())
    }

    pub async fn process_credit_claim(
        &self,
        cycle_id: &str,
        creditor: &str,
        tx_hash: &str,
    ) -> ServiceResult<()> {
        info!(
            "claim event bridge received: cycle={}, creditor={}, tx={}",
            cycle_id, creditor, tx_hash
        );
        Ok(())
    }

    pub async fn process_defaulted_debtor(
        &self,
        cycle_id: &str,
        debtor: &str,
    ) -> ServiceResult<()> {
        let changed = repo::mark_cycle_defaulted_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            Utc::now().naive_utc(),
        )
        .await?;
        if changed {
            info!(
                "default event bridge received: cycle={}, debtor={}",
                cycle_id, debtor
            );
        }
        Ok(())
    }

    pub async fn finalize_cycle(&self, cycle_id: &str) -> ServiceResult<()> {
        let changed = repo::mark_cycle_finalized_on(
            self.inner.persist_ctx.db.as_ref(),
            cycle_id,
            Utc::now().naive_utc(),
        )
        .await?;
        if changed {
            info!("finalized settlement cycle {}", cycle_id);
        }
        Ok(())
    }
}
