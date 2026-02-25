mod config;

use std::time::Instant;

use anyhow::Context;
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use config::ExporterConfig;
use env_logger::Env;
use log::info;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::Serialize;
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    metrics: PrometheusHandle,
    started_at: Instant,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct ReadinessResponse {
    status: &'static str,
    uptime_seconds: u64,
}

fn load_config() -> anyhow::Result<ExporterConfig> {
    dotenv::dotenv()
        .map_err(|err| {
            eprintln!(".env file error: {err}");
            err
        })
        .ok();

    ExporterConfig::fetch()
}

fn setup_metrics_recorder() -> anyhow::Result<PrometheusHandle> {
    PrometheusBuilder::new()
        .add_global_label("app", "metrics-exporter")
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("Failed to install metrics recorder: {e}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = load_config()?;

    env_logger::Builder::from_env(Env::default().default_filter_or(cfg.log_level.as_str())).init();

    let metrics_handle = setup_metrics_recorder()?;
    metrics::gauge!("metrics_exporter_up").set(1.0);
    metrics::counter!("metrics_exporter_start_total").increment(1);

    let state = AppState {
        metrics: metrics_handle,
        started_at: Instant::now(),
    };

    let app = Router::new()
        .route("/metrics", get(get_metrics))
        .route("/healthz", get(get_health))
        .route("/readyz", get(get_ready))
        .with_state(state);

    let bind_addr = cfg.bind_addr();
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind {bind_addr}"))?;

    info!("metrics-exporter listening on {}", listener.local_addr()?);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server exited unexpectedly")?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn get_metrics(State(state): State<AppState>) -> String {
    state.metrics.render()
}

async fn get_health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn get_ready(State(state): State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    let uptime_seconds = state.started_at.elapsed().as_secs();
    (
        StatusCode::OK,
        Json(ReadinessResponse {
            status: "ready",
            uptime_seconds,
        }),
    )
}
