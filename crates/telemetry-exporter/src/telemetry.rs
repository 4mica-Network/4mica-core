use std::time::Duration;

use anyhow::Context;
use env_logger::Env;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

pub fn init_logger(level: log::Level) {
    env_logger::Builder::from_env(Env::default().default_filter_or(level.as_str())).init();
}

pub fn install_metrics_recorder() -> anyhow::Result<PrometheusHandle> {
    PrometheusBuilder::new()
        .add_global_label("app", "telemetry-exporter")
        .install_recorder()
        .context("Failed to install metrics recorder")
}

pub fn emit_startup_metrics() {
    metrics::gauge!("metrics_exporter_up").set(1.0);
    metrics::counter!("metrics_exporter_start_total").increment(1);
    metrics::counter!("core_business_query_failures_total").absolute(0);
}

pub fn set_snapshot_age_seconds(age_seconds: f64) {
    metrics::gauge!("core_business_snapshot_age_seconds").set(age_seconds);
}

pub fn record_query_duration(duration: Duration) {
    metrics::histogram!("core_business_query_duration_seconds").record(duration.as_secs_f64());
}

pub fn increment_query_failures() {
    metrics::counter!("core_business_query_failures_total").increment(1);
}
