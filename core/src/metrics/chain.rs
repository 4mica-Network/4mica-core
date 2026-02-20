use metrics_4mica::{Metric, MetricAccess, MetricLabels};

#[derive(Debug, Clone)]
pub enum PaymentTxStatus {
    Pending,
    Confirmed,
    Recorded,
    Finalized,
    Reverted,
}

impl ToString for PaymentTxStatus {
    fn to_string(&self) -> String {
        match self {
            PaymentTxStatus::Pending => "pending".to_string(),
            PaymentTxStatus::Confirmed => "confirmed".to_string(),
            PaymentTxStatus::Recorded => "recorded".to_string(),
            PaymentTxStatus::Finalized => "finalized".to_string(),
            PaymentTxStatus::Reverted => "reverted".to_string(),
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

impl ToString for EventTxStatus {
    fn to_string(&self) -> String {
        match self {
            EventTxStatus::Pending => "pending".to_string(),
            EventTxStatus::Confirmed => "confirmed".to_string(),
            EventTxStatus::Reverted => "reverted".to_string(),
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
