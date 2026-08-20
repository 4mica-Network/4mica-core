//! Scheduled entrypoints. Each task owns the ordering of one sweep and dispatches into the
//! domain services; it holds no domain logic of its own.

use std::sync::Arc;

use log::{info, warn};
use metrics_4mica::measure;

use crate::metrics::misc::record_task_time;
use crate::scheduler::{Task, async_trait};
use crate::service::ctx::Ctx;
use crate::service::domain::clearing::ClearingService;
use crate::service::domain::netting::NettingService;
use crate::service::domain::validation::{ValidationService, ValidationSweepSummary};

pub struct SettlementCycleTask {
    ctx: Arc<Ctx>,
    netting: Arc<NettingService>,
    clearing: Arc<ClearingService>,
}

impl SettlementCycleTask {
    pub fn new(
        ctx: Arc<Ctx>,
        netting: Arc<NettingService>,
        clearing: Arc<ClearingService>,
    ) -> Self {
        Self {
            ctx,
            netting,
            clearing,
        }
    }
}

#[async_trait]
impl Task for SettlementCycleTask {
    fn cron_pattern(&self) -> String {
        self.ctx.config.ethereum_config.cron_job_settings.clone()
    }

    #[measure(record_task_time, name = "settlement_cycles")]
    async fn run(&self) -> anyhow::Result<()> {
        match self.clearing.freeze_elapsed_cycles().await {
            Ok(frozen) if !frozen.is_empty() => {
                info!("froze {} elapsed settlement cycle(s)", frozen.len())
            }
            Ok(_) => {}
            Err(err) => warn!("failed to freeze elapsed settlement cycles: {err:?}"),
        }
        match self.netting.compute_due_cycle_netting().await {
            Ok(netted) if !netted.is_empty() => {
                info!("computed netting for {} settlement cycle(s)", netted.len())
            }
            Ok(_) => {}
            Err(err) => warn!("failed to compute due cycle netting: {err:?}"),
        }
        match self.clearing.commit_due_clearing_batches().await {
            Ok(committed) if !committed.is_empty() => {
                info!("committed {} clearing batch(es)", committed.len())
            }
            Ok(_) => {}
            Err(err) => warn!("failed to commit due clearing batches: {err:?}"),
        }
        match self.clearing.settle_due_cycles().await {
            Ok(settled) if !settled.is_empty() => {
                info!(
                    "opened settlement for {} cycle(s) at finality",
                    settled.len()
                )
            }
            Ok(_) => {}
            Err(err) => warn!("failed to settle due cycles: {err:?}"),
        }
        match self.clearing.retry_shortfall_cycles().await {
            Ok(retried) if !retried.is_empty() => {
                info!("re-drove {} shortfall settlement cycle(s)", retried.len())
            }
            Ok(_) => {}
            Err(err) => warn!("failed to retry shortfall cycles: {err:?}"),
        }
        match self.clearing.finalize_due_cycles().await {
            Ok(finalized) if !finalized.is_empty() => {
                info!("finalized {} settlement cycle(s)", finalized.len())
            }
            Ok(_) => {}
            Err(err) => warn!("failed to finalize due cycles: {err:?}"),
        }
        match self.clearing.ensure_active_cycles().await {
            Ok(opened) if !opened.is_empty() => {
                info!("ensured {} active settlement cycle(s)", opened.len())
            }
            Ok(_) => {}
            Err(err) => warn!("failed to ensure active settlement cycles: {err:?}"),
        }

        if let Err(err) = self.clearing.record_hanging_cycles_gauge().await {
            warn!("failed to record hanging settlement cycle gauge: {err:?}");
        }

        Ok(())
    }
}

/// Scheduled task that periodically runs the validation lifecycle sweep.
pub struct ValidationLifecycleTask {
    ctx: Arc<Ctx>,
    validation: Arc<ValidationService>,
}

impl ValidationLifecycleTask {
    pub fn new(ctx: Arc<Ctx>, validation: Arc<ValidationService>) -> Self {
        Self { ctx, validation }
    }
}

#[async_trait]
impl Task for ValidationLifecycleTask {
    fn cron_pattern(&self) -> String {
        self.ctx.config.guarantee.validation_poll_cron.clone()
    }

    async fn run(&self) -> anyhow::Result<()> {
        let summary = self.validation.drive_pending_validations().await?;
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
