use metrics_4mica::{Metric, MetricAccess, MetricLabels};
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug, Clone)]
pub enum PaymentTxStatus {
    Pending,
    Confirmed,
    Recorded,
    Finalized,
    Reverted,
}

impl Display for PaymentTxStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            PaymentTxStatus::Pending => f.write_str("pending"),
            PaymentTxStatus::Confirmed => f.write_str("confirmed"),
            PaymentTxStatus::Recorded => f.write_str("recorded"),
            PaymentTxStatus::Finalized => f.write_str("finalized"),
            PaymentTxStatus::Reverted => f.write_str("reverted"),
        }
    }
}

#[derive(Debug, Clone, MetricLabels)]
pub struct PaymentTxStatusLabels {
    pub status: PaymentTxStatus,
    pub asset: String,
}

#[derive(Clone, Metric)]
#[counter(labels = PaymentTxStatusLabels, name = "payment_tx_status_change_total")]
pub struct PaymentTxStatusChangeMetric;

#[derive(Clone, Metric)]
#[histogram(labels = PaymentTxStatusLabels, name = "payment_tx_status_change_duration_seconds")]
pub struct PaymentTxStatusChangeDurationMetric;

#[derive(Debug, Clone)]
pub enum EventTxStatus {
    Pending,
    Confirmed,
    Reverted,
}

impl Display for EventTxStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            EventTxStatus::Pending => f.write_str("pending"),
            EventTxStatus::Confirmed => f.write_str("confirmed"),
            EventTxStatus::Reverted => f.write_str("reverted"),
        }
    }
}

#[derive(Debug, Clone, MetricLabels)]
pub struct EventTxStatusLabels {
    pub status: EventTxStatus,
    pub signature: String,
}

#[derive(Clone, Metric)]
#[counter(labels = EventTxStatusLabels, name = "event_tx_status_change_total")]
pub struct EventTxStatusChangeMetric;

#[derive(Clone, Metric)]
#[histogram(labels = EventTxStatusLabels, name = "event_tx_status_change_duration_seconds")]
pub struct EventTxStatusChangeDurationMetric;

#[derive(Clone, Metric)]
#[gauge(labels = (), name = "blockchain_safe_head")]
pub struct BlockchainSafeHeadMetric;

pub fn record_event_status_change(status: EventTxStatus, signature: &str, duration_secs: f64) {
    let labels = EventTxStatusLabels {
        status,
        signature: signature.to_string(),
    };
    EventTxStatusChangeMetric::get(&labels).increment(1);
    EventTxStatusChangeDurationMetric::get(&labels).record(duration_secs);
}

pub fn record_payment_status_change(status: PaymentTxStatus, asset: &str, duration_secs: f64) {
    let labels = PaymentTxStatusLabels {
        status,
        asset: asset.to_string(),
    };
    PaymentTxStatusChangeMetric::get(&labels).increment(1);
    PaymentTxStatusChangeDurationMetric::get(&labels).record(duration_secs);
}

pub fn record_blockchain_safe_head(block_number: u64) {
    BlockchainSafeHeadMetric::get(&()).set(block_number as f64);
}
