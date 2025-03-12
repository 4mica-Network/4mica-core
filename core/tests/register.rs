use core_service::config::AppConfig;
use rpc::core::CoreApiClient;
use rpc::proxy::RpcProxy;
use test_log::test;
use uuid::Uuid;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv()
        .map_err(|err| {
            eprintln!(".env file error: {}", err);
            err
        })
        .ok();

    Ok(AppConfig::fetch())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn register_user() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };

    let user_addr = Uuid::new_v4().to_string();

    let core_client = RpcProxy::new(&core_addr).await?;
    core_client.register_user(user_addr.clone()).await?;

    use core_service::persist::{prisma, PersistCtx};

    let persist_ctx = PersistCtx::new().await?;

    let user = persist_ctx
        .client
        .user()
        .find_unique(prisma::user::address::equals(user_addr.clone()))
        .exec()
        .await?
        .expect("User not registered!");

    assert_eq!(user.deposit, 0f64);

    // Registering the user again should do nothing.
    core_client.register_user(user_addr.clone()).await?;

    let user = persist_ctx
        .client
        .user()
        .find_unique(prisma::user::address::equals(user_addr.clone()))
        .exec()
        .await?
        .expect("User not registered!");

    assert_eq!(user.version, 1);
    assert_eq!(user.deposit, 0f64);

    Ok(())
}
