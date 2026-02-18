use crate::{Metric, MetricLabels};

#[derive(Debug, Clone, MetricLabels)]
pub struct HttpLabels {
    pub method: String,
    pub path: String,
    pub status: u16,
}

#[derive(Metric)]
#[counter(labels = HttpLabels, name = "http_requests_total")]
pub struct HttpRequestsTotalMetric;

#[derive(Metric)]
#[histogram(labels = HttpLabels, name = "http_requests_duration_millis")]
pub struct HttpRequestsDurationMetric;
