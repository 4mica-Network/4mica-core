use std::time::Instant;

use metrics_exporter_prometheus::PrometheusHandle;

use crate::snapshot::SnapshotStore;

#[derive(Clone)]
pub struct AppState {
    pub metrics: PrometheusHandle,
    pub started_at: Instant,
    #[allow(dead_code)]
    pub snapshots: SnapshotStore,
}

impl AppState {
    pub fn new(metrics: PrometheusHandle) -> Self {
        Self {
            metrics,
            started_at: Instant::now(),
            snapshots: SnapshotStore::new(),
        }
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}
