use crate::app;
use crate::config::ExporterConfig;
use crate::db;
use crate::scheduler;
use crate::server;
use crate::state::AppState;
use crate::telemetry;
use log::info;

pub async fn run() -> anyhow::Result<()> {
    let cfg = load_config()?;
    telemetry::init_logger(cfg.log_level);
    info!(
        "telemetry exporter config: bind_addr={}, snapshot_interval_sec={}, query_timeout_ms={}, max_db_connections={}, stale_after_sec={}",
        cfg.bind_addr(),
        cfg.snapshot_interval_sec,
        cfg.query_timeout_ms,
        cfg.max_db_connections,
        cfg.stale_after_sec
    );

    let metrics = telemetry::install_metrics_recorder()?;
    telemetry::emit_startup_metrics();

    let readonly_db =
        db::connect_readonly_pool(&cfg.readonly_replica_dsn, cfg.max_db_connections).await?;
    info!(
        "connected readonly replica pool with max_db_connections={}",
        cfg.max_db_connections
    );

    let state = AppState::new(metrics, cfg.stale_after_sec);
    let _snapshot_scheduler = scheduler::spawn_snapshot_scheduler(
        state.snapshots.clone(),
        cfg.snapshot_interval_sec,
        readonly_db,
    );
    let app = app::router(state);

    let result = server::serve(&cfg.bind_addr(), app).await;
    metrics::gauge!("metrics_exporter_up").set(0.0);
    result
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
