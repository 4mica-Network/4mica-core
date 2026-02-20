use std::time::Duration;

use metrics_4mica::{Metric, MetricAccess, MetricLabels};

#[derive(Debug, Clone, MetricLabels)]
pub struct FnExecLabels {
    pub name: String,
}

#[derive(Clone, Metric)]
#[histogram(labels = FnExecLabels, name = "db_query_duration_seconds")]
pub struct DbQueryDurationMetric;

#[derive(Clone, Metric)]
#[counter(labels = FnExecLabels, name = "db_query_total")]
pub struct DbQueryTotalMetric;

#[derive(Clone, Metric)]
#[histogram(labels = FnExecLabels, name = "ethereum_event_duration_seconds")]
pub struct EthereumEventDurationMetric;

#[derive(Clone, Metric)]
#[counter(labels = FnExecLabels, name = "ethereum_event_total")]
pub struct EthereumEventTotalMetric;

#[derive(Clone, Metric)]
#[histogram(labels = FnExecLabels, name = "task_execution_duration_seconds")]
pub struct TaskExecutionDurationMetric;

#[derive(Clone, Metric)]
#[counter(labels = FnExecLabels, name = "task_execution_total")]
pub struct TaskExecutionTotalMetric;

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
