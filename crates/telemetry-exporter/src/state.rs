use std::time::Instant;

use metrics_exporter_prometheus::PrometheusHandle;

use crate::snapshot::{SnapshotEnvelope, SnapshotStore};

#[derive(Debug, Clone, Copy)]
pub struct Readiness {
    pub is_ready: bool,
    pub snapshot_age_seconds: Option<u64>,
}

#[derive(Clone)]
pub struct AppState {
    pub metrics: PrometheusHandle,
    pub started_at: Instant,
    pub snapshots: SnapshotStore,
    pub stale_after_sec: u64,
}

impl AppState {
    pub fn new(metrics: PrometheusHandle, stale_after_sec: u64) -> Self {
        Self {
            metrics,
            started_at: Instant::now(),
            snapshots: SnapshotStore::new(),
            stale_after_sec,
        }
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub async fn readiness(&self) -> Readiness {
        let latest = self.snapshots.latest().await;
        let snapshot_age_seconds = snapshot_age_seconds(latest.as_ref());
        Readiness {
            is_ready: is_snapshot_fresh(snapshot_age_seconds, self.stale_after_sec),
            snapshot_age_seconds,
        }
    }
}

fn snapshot_age_seconds(latest: Option<&SnapshotEnvelope>) -> Option<u64> {
    latest.map(|envelope| {
        // Touch snapshot fields so clippy treats the model as used before scheduler wiring.
        let _total_users = envelope.snapshot.users_total;
        let _active_users = envelope
            .snapshot
            .active_users_1h
            .saturating_add(envelope.snapshot.active_users_24h)
            .saturating_add(envelope.snapshot.active_users_7d);
        let _query_duration_ms = envelope.meta.query_duration_ms;
        envelope.meta.captured_at.elapsed().as_secs()
    })
}

fn is_snapshot_fresh(snapshot_age_seconds: Option<u64>, stale_after_sec: u64) -> bool {
    snapshot_age_seconds
        .map(|age| age <= stale_after_sec)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{is_snapshot_fresh, snapshot_age_seconds};
    use crate::snapshot::{Snapshot, SnapshotEnvelope, SnapshotMeta};
    use std::time::{Duration, Instant};

    #[test]
    fn missing_snapshot_is_not_fresh() {
        assert!(!is_snapshot_fresh(None, 180));
    }

    #[test]
    fn stale_snapshot_is_not_fresh() {
        assert!(!is_snapshot_fresh(Some(181), 180));
    }

    #[test]
    fn fresh_snapshot_is_fresh() {
        assert!(is_snapshot_fresh(Some(180), 180));
        assert!(is_snapshot_fresh(Some(10), 180));
    }

    #[test]
    fn computes_snapshot_age_from_instant() {
        let five_secs_ago = Instant::now()
            .checked_sub(Duration::from_secs(5))
            .expect("valid instant math");
        let envelope = SnapshotEnvelope {
            snapshot: Snapshot::default(),
            meta: SnapshotMeta {
                captured_at: five_secs_ago,
                query_duration_ms: 1,
            },
        };
        let age = snapshot_age_seconds(Some(&envelope)).expect("age should exist");
        assert!(age >= 5);
    }
}
