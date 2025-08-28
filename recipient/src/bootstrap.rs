use jsonrpsee::server::Server;
use log::info;
use recipient::{
    config::{AppConfig, ServerConfig},
    service::RecipientService,
};
use rpc::recipient::RecipientApiServer;
use std::env;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};

fn load_config() -> AppConfig {
    dotenv::dotenv()
        .map_err(|err| {
            eprintln!(".env file error: {}", err);
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

    unsafe { env::set_var("RUST_LOG", log_level.as_str()); }
    env_logger::init();

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any);
    let middleware = ServiceBuilder::new().layer(cors);

    let service = RecipientService::new(&app_config).await?;

    let server = Server::builder()
        .set_http_middleware(middleware)
        .build(format!("{}:{}", host, port))
        .await?;

    info!("Running server on {}...", server.local_addr()?);
    let handle = server.start(service.into_rpc());
    handle.stopped().await;

    Ok(())
}
