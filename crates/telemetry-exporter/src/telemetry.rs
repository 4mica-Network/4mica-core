use std::time::Duration;
use std::{sync::OnceLock, vec::Vec};

use anyhow::{Context, bail};
use env_logger::Env;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

#[derive(Debug, Clone)]
struct MetricNames {
    users_total: String,
    active_users_1h: String,
    active_users_24h: String,
    active_users_7d: String,
    snapshot_age_seconds: String,
    query_duration_seconds: String,
    query_failures_total: String,
}

impl MetricNames {
    fn from_chain_id(chain_id: &str) -> anyhow::Result<Self> {
        let namespace = sanitize_metric_namespace(chain_id)?;
        Ok(Self {
            users_total: format!("{namespace}_users_total"),
            active_users_1h: format!("{namespace}_active_users_1h"),
            active_users_24h: format!("{namespace}_active_users_24h"),
            active_users_7d: format!("{namespace}_active_users_7d"),
            snapshot_age_seconds: format!("{namespace}_snapshot_age_seconds"),
            query_duration_seconds: format!("{namespace}_query_duration_seconds"),
            query_failures_total: format!("{namespace}_query_failures_total"),
        })
    }
}

static METRIC_NAMES: OnceLock<MetricNames> = OnceLock::new();

pub fn init_logger(level: log::Level) {
    env_logger::Builder::from_env(Env::default().default_filter_or(level.as_str())).init();
}

pub fn install_metrics_recorder() -> anyhow::Result<PrometheusHandle> {
    PrometheusBuilder::new()
        .add_global_label("app", "telemetry-exporter")
        .install_recorder()
        .context("Failed to install metrics recorder")
}

pub fn init_metric_namespace(chain_id: &str) -> anyhow::Result<()> {
    let names = MetricNames::from_chain_id(chain_id)?;
    if let Some(existing) = METRIC_NAMES.get() {
        if existing.users_total == names.users_total {
            return Ok(());
        }
        bail!(
            "metric namespace already initialized as {}, got {}",
            existing.users_total,
            names.users_total
        );
    }

    METRIC_NAMES
        .set(names)
        .map_err(|_| anyhow::anyhow!("failed to initialize metric namespace"))?;
    Ok(())
}

pub fn emit_startup_metrics() {
    metrics::gauge!("metrics_exporter_up").set(1.0);
    metrics::counter!("metrics_exporter_start_total").increment(1);
    let names = metric_names();
    metrics::counter!(names.query_failures_total.as_str()).absolute(0);
    metrics::gauge!(names.users_total.as_str()).set(0.0);
    metrics::gauge!(names.active_users_1h.as_str()).set(0.0);
    metrics::gauge!(names.active_users_24h.as_str()).set(0.0);
    metrics::gauge!(names.active_users_7d.as_str()).set(0.0);
}

pub fn set_snapshot_age_seconds(age_seconds: f64) {
    metrics::gauge!(metric_names().snapshot_age_seconds.as_str()).set(age_seconds);
}

pub fn record_query_duration(duration: Duration) {
    metrics::histogram!(metric_names().query_duration_seconds.as_str())
        .record(duration.as_secs_f64());
}

pub fn increment_query_failures() {
    metrics::counter!(metric_names().query_failures_total.as_str()).increment(1);
}

pub fn set_users_total(users_total: u64) {
    metrics::gauge!(metric_names().users_total.as_str()).set(users_total as f64);
}

pub fn set_active_users_1h(active_users_1h: u64) {
    metrics::gauge!(metric_names().active_users_1h.as_str()).set(active_users_1h as f64);
}

pub fn set_active_users_24h(active_users_24h: u64) {
    metrics::gauge!(metric_names().active_users_24h.as_str()).set(active_users_24h as f64);
}

pub fn set_active_users_7d(active_users_7d: u64) {
    metrics::gauge!(metric_names().active_users_7d.as_str()).set(active_users_7d as f64);
}

fn metric_names() -> &'static MetricNames {
    METRIC_NAMES
        .get()
        .expect("metric namespace not initialized; call init_metric_namespace first")
}

fn sanitize_metric_namespace(chain_id: &str) -> anyhow::Result<String> {
    let chain_id = chain_id.trim();
    if chain_id.is_empty() {
        bail!("chain id cannot be empty");
    }

    let mut chars: Vec<char> = chain_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    while chars.first() == Some(&'_') {
        chars.remove(0);
    }
    while chars.last() == Some(&'_') {
        chars.pop();
    }
    let mut compacted = String::with_capacity(chars.len());
    let mut prev_underscore = false;
    for ch in chars {
        if ch == '_' {
            if !prev_underscore {
                compacted.push(ch);
            }
            prev_underscore = true;
        } else {
            compacted.push(ch);
            prev_underscore = false;
        }
    }

    if compacted.is_empty() {
        bail!("chain id does not produce a valid metric namespace");
    }
    if compacted
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit())
    {
        compacted = format!("chain_{compacted}");
    }
    Ok(compacted)
}

#[cfg(test)]
mod tests {
    use super::sanitize_metric_namespace;

    #[test]
    fn sanitizes_numeric_chain_id_with_prefix() {
        let value = sanitize_metric_namespace("11155111").expect("chain id should sanitize");
        assert_eq!(value, "chain_11155111");
    }

    #[test]
    fn sanitizes_mixed_chain_id() {
        let value = sanitize_metric_namespace("Sepolia-Testnet").expect("chain id should sanitize");
        assert_eq!(value, "sepolia_testnet");
    }

    #[test]
    fn rejects_empty_chain_id() {
        let err = sanitize_metric_namespace("   ").unwrap_err();
        assert!(err.to_string().contains("cannot be empty"));
    }
}
