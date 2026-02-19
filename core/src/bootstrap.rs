use std::sync::Arc;

use core_service::{
    config::{AppConfig, ServerConfig},
    ethereum::EthereumEventScanner,
    http,
    metrics::{HealthCheckTask, MetricsUpkeepTask, setup_metrics_recorder},
    scheduler::TaskScheduler,
    service::{
        CoreService,
        payment::{ConfirmPaymentsTask, FinalizePaymentsTask, ScanPaymentsTask},
    },
};
use env_logger::Env;
use log::info;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

fn load_config() -> anyhow::Result<AppConfig> {
    dotenv::dotenv()
        .map_err(|err| {
            eprintln!(".env file error: {err}");
            err
        })
        .ok();

    AppConfig::fetch()
}

pub async fn bootstrap() -> anyhow::Result<()> {
    let app_config = load_config()?;

    let ServerConfig {
        host,
        port,
        log_level,
    } = app_config.server_config.clone();

    env_logger::Builder::from_env(Env::default().default_filter_or(log_level.as_str())).init();

    let cors_layer = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any);

    let service = CoreService::new(app_config.clone()).await?;

    let ethereum_scanner = Arc::new(EthereumEventScanner::new(
        app_config.ethereum_config.clone(),
        service.persist_ctx().clone(),
        service.read_provider().clone(),
        Arc::new(service.clone()),
    ));

    let metrics_recorder = setup_metrics_recorder()?;

    let mut scheduler = TaskScheduler::new().await?;

    scheduler.add_task(ethereum_scanner).await?;
    scheduler
        .add_task(Arc::new(ScanPaymentsTask::new(service.clone())))
        .await?;
    scheduler
        .add_task(Arc::new(ConfirmPaymentsTask::new(service.clone())))
        .await?;
    scheduler
        .add_task(Arc::new(FinalizePaymentsTask::new(service.clone())))
        .await?;
    scheduler
        .add_task(Arc::new(MetricsUpkeepTask::new(
            metrics_recorder.clone(),
            app_config.monitoring.metrics_upkeep_cron.clone(),
        )))
        .await?;
    scheduler
        .add_task(Arc::new(HealthCheckTask::new(
            service.clone(),
            app_config.monitoring.health_check_cron.clone(),
        )))
        .await?;

    scheduler.start().await?;

    let app = http::router(service, metrics_recorder).layer(cors_layer);

    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr).await?;
    let local_addr = listener.local_addr()?;
    info!("Running server on {}...", local_addr);

    axum::serve(listener, app).await?;
    Ok(())
}
