use metrics_4mica::{Metric, MetricLabels};

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

#[derive(Debug, Clone, MetricLabels)]
pub struct HealthLabels {
    pub scope: String,
}

#[derive(Clone, Metric)]
#[gauge(labels = HealthLabels, name = "health_status")]
pub struct HealthStatusMetric;
