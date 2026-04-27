use crate::config::{DEFAULT_ASSET_ADDRESS, SettlementCycleConfig};
use crate::metrics::misc::record_task_time;
use crate::persist::repo;
use crate::scheduler::Task;
use crate::service::CoreService;
use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone, Utc};
use entities::settlement_cycle;
use log::info;
use metrics_4mica::measure;
use std::collections::BTreeSet;

impl CoreService {
    pub async fn get_or_create_active_cycle(
        &self,
        asset_address: &str,
        now: DateTime<Utc>,
    ) -> crate::error::ServiceResult<settlement_cycle::Model> {
        if let Some(existing) =
            repo::get_open_cycle_by_asset(&self.inner.persist_ctx, asset_address).await?
        {
            if existing.period_end > now.naive_utc() {
                return Ok(existing);
            }

            self.freeze_cycle(&existing.id).await?;
        }

        let window = SettlementCycleWindow::for_instant(&self.inner.config.settlement_cycle, now)?;
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

        match repo::create_settlement_cycle_on(self.inner.persist_ctx.db.as_ref(), input).await {
            Ok(created) => Ok(created),
            Err(repo_err) => {
                if let Some(existing) =
                    repo::get_cycle_by_id_on(self.inner.persist_ctx.db.as_ref(), &cycle_id).await?
                {
                    Ok(existing)
                } else {
                    Err(repo_err.into())
                }
            }
        }
    }

    pub async fn freeze_cycle(&self, cycle_id: &str) -> crate::error::ServiceResult<()> {
        let now = Utc::now().naive_utc();
        let changed =
            repo::freeze_cycle_on(self.inner.persist_ctx.db.as_ref(), cycle_id, now).await?;
        if changed {
            info!("froze settlement cycle {}", cycle_id);
        }
        Ok(())
    }

    pub async fn ensure_active_cycles(&self) -> crate::error::ServiceResult<Vec<String>> {
        let now = Utc::now();
        let assets = self.supported_settlement_assets().await?;
        let mut cycle_ids = Vec::with_capacity(assets.len());
        for asset in assets {
            let cycle = self.get_or_create_active_cycle(&asset, now).await?;
            cycle_ids.push(cycle.id);
        }
        Ok(cycle_ids)
    }

    pub async fn freeze_elapsed_cycles(&self) -> crate::error::ServiceResult<Vec<String>> {
        let now = Utc::now().naive_utc();
        let due = repo::list_open_cycles_ending_before_on(self.inner.persist_ctx.db.as_ref(), now)
            .await?;
        let mut frozen = Vec::new();
        for cycle in due {
            let cycle_id = cycle.id.clone();
            self.freeze_cycle(&cycle_id).await?;
            frozen.push(cycle_id);
        }
        Ok(frozen)
    }

    async fn supported_settlement_assets(&self) -> crate::error::ServiceResult<Vec<String>> {
        let mut assets = BTreeSet::new();
        assets.insert(DEFAULT_ASSET_ADDRESS.to_string());
        for token in self
            .inner
            .contract_api
            .get_supported_tokens()
            .await
            .map_err(|e| crate::error::ServiceError::Other(anyhow!(e)))?
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

pub struct SettlementCycleTask(CoreService);

impl SettlementCycleTask {
    pub fn new(service: CoreService) -> Self {
        Self(service)
    }

    fn scheduler_cron_pattern(&self) -> String {
        self.0
            .inner
            .config
            .ethereum_config
            .cron_job_settings
            .clone()
    }
}

#[async_trait]
impl Task for SettlementCycleTask {
    fn cron_pattern(&self) -> String {
        self.scheduler_cron_pattern()
    }

    #[measure(record_task_time, name = "settlement_cycles")]
    async fn run(&self) -> anyhow::Result<()> {
        let frozen = self.0.freeze_elapsed_cycles().await?;
        let opened = self.0.ensure_active_cycles().await?;

        if !opened.is_empty() {
            info!("ensured {} active settlement cycle(s)", opened.len());
        }
        if !frozen.is_empty() {
            info!("froze {} elapsed settlement cycle(s)", frozen.len());
        }

        Ok(())
    }
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
