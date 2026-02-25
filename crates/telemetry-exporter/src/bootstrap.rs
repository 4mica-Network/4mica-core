use crate::app;
use crate::config::ExporterConfig;
use crate::server;
use crate::state::AppState;
use crate::telemetry;

pub async fn run() -> anyhow::Result<()> {
    let cfg = load_config()?;
    telemetry::init_logger(cfg.log_level);

    let metrics = telemetry::install_metrics_recorder()?;
    telemetry::emit_startup_metrics();

    let state = AppState::new(metrics);
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
