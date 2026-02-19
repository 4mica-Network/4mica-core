use async_trait::async_trait;
use metrics_4mica::{Metric, http::HttpRequestDurationMetric, measure};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

use crate::{metrics::record::record_task_time, scheduler::Task};

pub mod health;
pub mod metrics;
pub mod record;

pub use health::HealthCheckTask;

pub fn setup_metrics_recorder() -> anyhow::Result<PrometheusHandle> {
    const EXPONENTIAL_SECONDS: &[f64] = &[
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    let recorder_handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full(HttpRequestDurationMetric::name().to_string()),
            EXPONENTIAL_SECONDS,
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to set buckets for metric {}: {}",
                HttpRequestDurationMetric::name(),
                e
            )
        })?
        .add_global_label("app", "core")
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("Failed to install metrics recorder: {}", e))?;

    Ok(recorder_handle)
}

pub struct MetricsUpkeepTask {
    recorder_handle: PrometheusHandle,
    cron_pattern: String,
}

impl MetricsUpkeepTask {
    pub fn new(recorder_handle: PrometheusHandle, cron_pattern: String) -> Self {
        Self {
            recorder_handle,
            cron_pattern,
        }
    }
}

#[async_trait]
impl Task for MetricsUpkeepTask {
    fn cron_pattern(&self) -> String {
        self.cron_pattern.clone()
    }

    #[measure(record_task_time, name = "metrics_upkeep")]
    async fn run(&self) -> anyhow::Result<()> {
        self.recorder_handle.run_upkeep();
        Ok(())
    }
}
