mod app;
mod bootstrap;
mod config;
mod handlers;
mod scheduler;
mod server;
mod snapshot;
mod state;
mod telemetry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bootstrap::run().await
}
