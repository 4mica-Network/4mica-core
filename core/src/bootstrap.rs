use core_service::{
    config::{AppConfig, ServerConfig},
    service::CoreService,
};
use env_logger::Env;
use jsonrpsee::server::Server;
use log::info;
use rpc::core::CoreApiServer;
use std::env;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};

fn load_config() -> AppConfig {
    dotenv::dotenv()
        .map_err(|err| {
            eprintln!(".env file error: {err}");
            err
        })
        .ok();

    AppConfig::fetch()
}

pub async fn bootstrap() -> anyhow::Result<()> {
    let app_config = load_config();

    let ServerConfig {
        host,
        port,
        log_level,
    } = &app_config.server_config;

    env_logger::Builder::from_env(Env::default().default_filter_or(log_level.as_str())).init();

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any);
    let middleware = ServiceBuilder::new().layer(cors);

    let server = Server::builder()
        .set_http_middleware(middleware)
        .build(format!("{host}:{port}"))
        .await?;

    let service = CoreService::new(app_config).await?;

    info!("Running server on {}...", server.local_addr()?);
    let handle = server.start(service.into_rpc());
    handle.stopped().await;

    Ok(())
}
