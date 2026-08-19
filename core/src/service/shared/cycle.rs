//! Settlement-cycle row lifecycle: opening, freezing, and status checks.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::anyhow;
use chrono::{DateTime, Duration, TimeZone, Utc};
use entities::sea_orm_active_enums::SettlementCycleStatus;
use entities::settlement_cycle;
use log::info;

use crate::config::{DEFAULT_ASSET_ADDRESS, SettlementCycleConfig};
use crate::error::{ServiceError, ServiceResult};
use crate::persist::repo;
use crate::service::ctx::Ctx;

pub struct CycleOps {
    ctx: Arc<Ctx>,
}

impl CycleOps {
    pub fn new(ctx: Arc<Ctx>) -> Self {
        Self { ctx }
    }

    pub async fn get_or_create_active_cycle(
        &self,
        asset_address: &str,
        now: DateTime<Utc>,
    ) -> ServiceResult<settlement_cycle::Model> {
        if let Some(existing) =
            repo::get_open_cycle_by_asset(&self.ctx.persist, asset_address).await?
        {
            if existing.period_end > now.naive_utc() {
                return Ok(existing);
            }

            self.freeze_cycle(&existing.id).await?;
        }

        let window = SettlementCycleWindow::for_instant(&self.ctx.config.settlement_cycle, now)?;
        let cycle_id = cycle_id_for(asset_address, window.period_start);
        let input = repo::CreateSettlementCycleInput {
            id: cycle_id.clone(),
            asset_address: asset_address.to_string(),
            period_start: window.period_start.naive_utc(),
            period_end: window.period_end.naive_utc(),
            resolution_cutoff: window.resolution_cutoff.naive_utc(),
            clearing_commit_deadline: window.clearing_commit_deadline.naive_utc(),
            payment_submission_deadline: window.payment_submission_deadline.naive_utc(),
            payment_finality_deadline: window.payment_finality_deadline.naive_utc(),
        };

        match repo::create_settlement_cycle_on(self.ctx.db(), input).await {
            Ok(created) => Ok(created),
            Err(repo_err) => {
                if let Some(existing) = repo::get_cycle_by_id_on(self.ctx.db(), &cycle_id).await? {
                    Ok(existing)
                } else {
                    Err(repo_err.into())
                }
            }
        }
    }

    pub async fn freeze_cycle(&self, cycle_id: &str) -> ServiceResult<()> {
        let now = Utc::now().naive_utc();
        let changed = repo::freeze_cycle_on(self.ctx.db(), cycle_id, now).await?;
        if changed {
            info!("froze settlement cycle {}", cycle_id);
        }
        Ok(())
    }

    /// Load a cycle and assert it is in `status`, so callers can't act on a cycle that has moved on.
    pub async fn require_cycle_status(
        &self,
        cycle_id: &str,
        status: SettlementCycleStatus,
    ) -> ServiceResult<settlement_cycle::Model> {
        let cycle = repo::get_cycle_by_id(&self.ctx.persist, cycle_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Settlement cycle {cycle_id}")))?;
        if cycle.status != status {
            return Err(ServiceError::InvalidParams(format!(
                "settlement cycle {cycle_id} is {:?}, expected {:?}",
                cycle.status, status
            )));
        }
        Ok(cycle)
    }

    /// Every asset that needs an open cycle: the native asset plus whatever the contract supports.
    pub async fn supported_settlement_assets(&self) -> ServiceResult<Vec<String>> {
        let mut assets = BTreeSet::new();
        assets.insert(DEFAULT_ASSET_ADDRESS.to_string());
        for token in self
            .ctx
            .chain
            .get_supported_tokens()
            .await
            .map_err(|e| ServiceError::Other(anyhow!(e)))?
        {
            assets.insert(token.address);
        }
        Ok(assets.into_iter().collect())
    }
}

#[derive(Debug, Clone, Copy)]
struct SettlementCycleWindow {
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    resolution_cutoff: DateTime<Utc>,
    clearing_commit_deadline: DateTime<Utc>,
    payment_submission_deadline: DateTime<Utc>,
    payment_finality_deadline: DateTime<Utc>,
}

impl SettlementCycleWindow {
    fn for_instant(config: &SettlementCycleConfig, now: DateTime<Utc>) -> anyhow::Result<Self> {
        let cycle_secs = i64::try_from(config.cycle_secs)?;
        let resolution_cutoff_secs = i64::try_from(config.resolution_cutoff_secs)?;
        let clearing_commit_delay_secs = i64::try_from(config.clearing_commit_delay_secs)?;
        let payment_submission_window_secs = i64::try_from(config.payment_submission_window_secs)?;
        let payment_finality_window_secs = i64::try_from(config.payment_finality_window_secs)?;

        let now_ts = now.timestamp();
        let period_start_ts = now_ts - now_ts.rem_euclid(cycle_secs);
        let period_start = Utc
            .timestamp_opt(period_start_ts, 0)
            .single()
            .ok_or_else(|| anyhow!("invalid cycle period start timestamp"))?;
        let period_end = period_start + Duration::seconds(cycle_secs);
        let resolution_cutoff = period_end + Duration::seconds(resolution_cutoff_secs);
        let clearing_commit_deadline =
            resolution_cutoff + Duration::seconds(clearing_commit_delay_secs);
        let payment_submission_deadline =
            clearing_commit_deadline + Duration::seconds(payment_submission_window_secs);
        let payment_finality_deadline =
            clearing_commit_deadline + Duration::seconds(payment_finality_window_secs);

        Ok(Self {
            period_start,
            period_end,
            resolution_cutoff,
            clearing_commit_deadline,
            payment_submission_deadline,
            payment_finality_deadline,
        })
    }
}

fn cycle_id_for(asset_address: &str, period_start: DateTime<Utc>) -> String {
    format!(
        "{}:{}",
        asset_address.to_ascii_lowercase(),
        period_start.timestamp()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SettlementCycleConfig;

    #[test]
    fn cycle_window_aligns_to_configured_boundary() {
        let cfg = SettlementCycleConfig {
            cycle_secs: 86_400,
            resolution_cutoff_secs: 21_600,
            clearing_commit_delay_secs: 900,
            payment_submission_window_secs: 7_200,
            payment_finality_window_secs: 14_400,
            seizure_margin_secs: 21_600,
            default_batch_size: 50,
            shortfall_grace_secs: 21_600,
            settlement_retry_delay_secs: 1_800,
            hanging_retry_windows: 3,
        };
        let now = Utc.with_ymd_and_hms(2026, 4, 27, 14, 37, 11).unwrap();

        let window = SettlementCycleWindow::for_instant(&cfg, now).expect("window");

        assert_eq!(
            window.period_start,
            Utc.with_ymd_and_hms(2026, 4, 27, 0, 0, 0).unwrap()
        );
        assert_eq!(
            window.period_end,
            Utc.with_ymd_and_hms(2026, 4, 28, 0, 0, 0).unwrap()
        );
        assert_eq!(
            window.resolution_cutoff,
            Utc.with_ymd_and_hms(2026, 4, 28, 6, 0, 0).unwrap()
        );
        assert_eq!(
            window.clearing_commit_deadline,
            Utc.with_ymd_and_hms(2026, 4, 28, 6, 15, 0).unwrap()
        );
        assert_eq!(
            window.payment_submission_deadline,
            Utc.with_ymd_and_hms(2026, 4, 28, 8, 15, 0).unwrap()
        );
        assert_eq!(
            window.payment_finality_deadline,
            Utc.with_ymd_and_hms(2026, 4, 28, 10, 15, 0).unwrap()
        );
    }

    #[test]
    fn cycle_id_is_deterministic_and_lowercased() {
        let start = Utc.with_ymd_and_hms(2026, 4, 27, 0, 0, 0).unwrap();
        assert_eq!(cycle_id_for("0xABCD", start), "0xabcd:1777248000");
    }
}
