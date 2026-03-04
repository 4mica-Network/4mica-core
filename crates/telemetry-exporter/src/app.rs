use axum::{Router, routing::get};

use crate::handlers::{get_health, get_metrics, get_ready};
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(get_metrics))
        .route("/healthz", get(get_health))
        .route("/readyz", get(get_ready))
        .with_state(state)
}
