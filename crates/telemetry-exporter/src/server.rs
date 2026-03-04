use anyhow::Context;
use axum::Router;
use log::{info, warn};
use tokio::net::TcpListener;

pub async fn serve(bind_addr: &str, app: Router) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("Failed to bind {bind_addr}"))?;

    info!("telemetry-exporter listening on {}", listener.local_addr()?);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server exited unexpectedly")
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate_signal =
            signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");

        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(err) = result {
                    warn!("failed waiting for Ctrl+C signal: {err}");
                }
            }
            _ = terminate_signal.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(err) = tokio::signal::ctrl_c().await {
            warn!("failed waiting for Ctrl+C signal: {err}");
        }
    }

    info!("shutdown signal received");
}
