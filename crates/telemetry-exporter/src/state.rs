use std::time::Instant;

use metrics_exporter_prometheus::PrometheusHandle;

#[derive(Clone)]
pub struct AppState {
    pub metrics: PrometheusHandle,
    pub started_at: Instant,
}

impl AppState {
    pub fn new(metrics: PrometheusHandle) -> Self {
        Self {
            metrics,
            started_at: Instant::now(),
        }
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}
