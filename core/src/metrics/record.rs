use std::time::Duration;

use metrics_4mica::MetricAccess;

use crate::{
    metrics::metrics::{
        DbQueryDurationMetric, DbQueryTotalMetric, EthereumEventDurationMetric,
        EthereumEventTotalMetric, FnExecLabels, HealthLabels, HealthStatusMetric,
        TaskExecutionDurationMetric, TaskExecutionTotalMetric,
    },
    service::health::CheckStatus,
};

pub fn record_db_time(fn_name: &'static str, duration: Duration) {
    let labels = FnExecLabels {
        name: fn_name.to_string(),
    };
    DbQueryTotalMetric::get(&labels).increment(1);
    DbQueryDurationMetric::get(&labels).record(duration.as_secs_f64());
}

pub fn record_event_handler_time(fn_name: &'static str, duration: Duration) {
    let labels = FnExecLabels {
        name: fn_name.to_string(),
    };
    EthereumEventTotalMetric::get(&labels).increment(1);
    EthereumEventDurationMetric::get(&labels).record(duration.as_secs_f64());
}

pub fn record_task_time(fn_name: &'static str, duration: Duration) {
    let labels = FnExecLabels {
        name: fn_name.to_string(),
    };
    TaskExecutionTotalMetric::get(&labels).increment(1);
    TaskExecutionDurationMetric::get(&labels).record(duration.as_secs_f64());
}

pub fn record_health_status(scope: &str, status: CheckStatus) {
    let labels = HealthLabels {
        scope: scope.to_string(),
    };
    HealthStatusMetric::get(&labels).set(match status {
        CheckStatus::Ok => 1.0,
        CheckStatus::Fail => 0.0,
    });
}
