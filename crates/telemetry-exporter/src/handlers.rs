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
}

pub async fn get_metrics(State(state): State<AppState>) -> String {
    state.metrics.render()
}

pub async fn get_health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

pub async fn get_ready(State(state): State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    (
        StatusCode::OK,
        Json(ReadinessResponse {
            status: "ready",
            uptime_seconds: state.uptime_seconds(),
        }),
    )
}
