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
#[counter(labels = PaymentTxStatusLabels, name = "processed_payment_tx_total")]
pub struct ProcessedPaymentTxTotalMetric;

#[derive(Clone, Metric)]
#[histogram(labels = PaymentTxStatusLabels, name = "processed_payment_tx_duration_seconds")]
pub struct ProcessedPaymentTxDurationMetric;

#[derive(Clone, Metric)]
#[gauge(labels = (), name = "scanned_payment_tx_block")]
pub struct ScannedPaymentTxBlockMetric;

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
#[counter(labels = EventTxStatusLabels, name = "processed_event_tx_total")]
pub struct ProcessedEventTxTotalMetric;

#[derive(Clone, Metric)]
#[histogram(labels = EventTxStatusLabels, name = "processed_event_tx_duration_seconds")]
pub struct ProcessedEventTxDurationMetric;

#[derive(Clone, Metric)]
#[gauge(labels = (), name = "scanned_event_tx_block")]
pub struct ScannedEventTxBlockMetric;

#[derive(Clone, Metric)]
#[gauge(labels = (), name = "blockchain_safe_head")]
pub struct BlockchainSafeHeadMetric;

#[derive(Debug, Clone, MetricLabels)]
pub struct HangingCycleLabels {
    pub status: String,
}

#[derive(Clone, Metric)]
#[gauge(labels = HangingCycleLabels, name = "hanging_unconfirmed_settlement_cycles")]
pub struct HangingUnconfirmedCyclesMetric;

/// Whether a failed contract call reverted on-chain (with decodable revert data)
/// or failed for a transport/RPC reason.
#[derive(Debug, Clone)]
pub enum ContractErrorKind {
    Revert,
    Transport,
}

impl Display for ContractErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ContractErrorKind::Revert => f.write_str("revert"),
            ContractErrorKind::Transport => f.write_str("transport"),
        }
    }
}

#[derive(Debug, Clone, MetricLabels)]
pub struct ContractCallErrorLabels {
    /// The proxy method that failed, e.g. `"commitCycle"`.
    pub method: String,
    pub kind: ContractErrorKind,
    /// For reverts: the error signature (or selector hex). For transport
    /// failures: a fixed `"transport"` bucket to keep cardinality bounded.
    pub error: String,
}

#[derive(Clone, Metric)]
#[counter(labels = ContractCallErrorLabels, name = "contract_call_error_total")]
pub struct ContractCallErrorTotalMetric;

pub fn record_contract_call_error(method: &str, kind: ContractErrorKind, error: &str) {
    let labels = ContractCallErrorLabels {
        method: method.to_string(),
        kind,
        error: error.to_string(),
    };
    ContractCallErrorTotalMetric::get(&labels).increment(1);
}

pub fn record_processed_event_tx(status: EventTxStatus, signature: &str, duration_secs: f64) {
    let labels = EventTxStatusLabels {
        status,
        signature: signature.to_string(),
    };
    ProcessedEventTxTotalMetric::get(&labels).increment(1);
    ProcessedEventTxDurationMetric::get(&labels).record(duration_secs);
}

pub fn record_processed_payment_tx(status: PaymentTxStatus, asset: &str, duration_secs: f64) {
    let labels = PaymentTxStatusLabels {
        status,
        asset: asset.to_string(),
    };
    ProcessedPaymentTxTotalMetric::get(&labels).increment(1);
    ProcessedPaymentTxDurationMetric::get(&labels).record(duration_secs);
}

pub fn record_blockchain_safe_head(block_number: u64) {
    BlockchainSafeHeadMetric::get(&()).set(block_number as f64);
}

pub fn record_scanned_payment_tx_block(block_number: u64) {
    ScannedPaymentTxBlockMetric::get(&()).set(block_number as f64);
}

pub fn record_scanned_event_tx_block(block_number: u64) {
    ScannedEventTxBlockMetric::get(&()).set(block_number as f64);
}

pub fn record_hanging_unconfirmed_cycles(status: &str, count: u64) {
    let labels = HangingCycleLabels {
        status: status.to_string(),
    };
    HangingUnconfirmedCyclesMetric::get(&labels).set(count as f64);
}

#[derive(Debug, Clone, MetricLabels)]
pub struct DeadLetteredEventLabels {
    pub signature: String,
}

#[derive(Clone, Metric)]
#[counter(labels = DeadLetteredEventLabels, name = "dead_lettered_event_total")]
pub struct DeadLetteredEventTotalMetric;
pub fn record_dead_lettered_event(signature: &str) {
    let labels = DeadLetteredEventLabels {
        signature: signature.to_string(),
    };
    DeadLetteredEventTotalMetric::get(&labels).increment(1);
}

#[derive(Debug, Clone, MetricLabels)]
pub struct UndercollateralizedSyncLabels {
    pub asset: String,
}

/// A chain reconciliation found on-chain backing below already-locked collateral (INV-3 would be
/// violated) and pinned `total` to `locked` instead. This should be unreachable under a correct
/// deployment (a sufficient withdrawal grace period keeps collateral seizable before it can exit);
/// a non-zero count signals a broken solvency invariant (e.g. grace period too short, M02/M07) and
/// warrants investigation.
#[derive(Clone, Metric)]
#[counter(labels = UndercollateralizedSyncLabels, name = "undercollateralized_sync_total")]
pub struct UndercollateralizedSyncTotalMetric;
pub fn record_undercollateralized_sync(asset: &str) {
    let labels = UndercollateralizedSyncLabels {
        asset: asset.to_string(),
    };
    UndercollateralizedSyncTotalMetric::get(&labels).increment(1);
}

#[derive(Debug, Clone, MetricLabels)]
pub struct WithdrawalExceedsFreeLabels {
    pub asset: String,
}
#[derive(Clone, Metric)]
#[counter(labels = WithdrawalExceedsFreeLabels, name = "withdrawal_exceeds_free_total")]
pub struct WithdrawalExceedsFreeTotalMetric;
pub fn record_withdrawal_exceeds_free(asset: &str) {
    let labels = WithdrawalExceedsFreeLabels {
        asset: asset.to_string(),
    };
    WithdrawalExceedsFreeTotalMetric::get(&labels).increment(1);
}
