use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Serialize)]
pub struct ReadinessResponse {
    pub status: &'static str,
    pub uptime_seconds: u64,
    pub snapshot_age_seconds: Option<u64>,
}

pub async fn get_metrics(State(state): State<AppState>) -> String {
    state.metrics.render()
}

pub async fn get_health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

pub async fn get_ready(State(state): State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    let readiness = state.readiness().await;
    let status = if readiness.is_ready { "ready" } else { "stale" };
    let status_code = if readiness.is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status_code,
        Json(ReadinessResponse {
            status,
            uptime_seconds: state.uptime_seconds(),
            snapshot_age_seconds: readiness.snapshot_age_seconds,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::get_ready;
    use crate::snapshot::{Snapshot, SnapshotMeta, SnapshotStore};
    use crate::state::AppState;
    use axum::{Json, extract::State, http::StatusCode};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use std::time::Instant;

    fn test_state(stale_after_sec: u64) -> AppState {
        let recorder = PrometheusBuilder::new().build_recorder();
        AppState {
            metrics: recorder.handle(),
            started_at: Instant::now(),
            snapshots: SnapshotStore::new(),
            stale_after_sec,
        }
    }

    #[tokio::test]
    async fn readyz_is_service_unavailable_when_snapshot_is_missing() {
        let state = test_state(180);
        let (status, Json(body)) = get_ready(State(state)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.status, "stale");
        assert!(body.snapshot_age_seconds.is_none());
    }

    #[tokio::test]
    async fn readyz_is_ok_when_snapshot_is_fresh() {
        let state = test_state(180);
        state
            .snapshots
            .update(
                Snapshot::default(),
                SnapshotMeta {
                    captured_at: Instant::now(),
                    query_duration_ms: 1,
                },
            )
            .await;

        let (status, Json(body)) = get_ready(State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "ready");
        assert!(body.snapshot_age_seconds.is_some());
    }
}
