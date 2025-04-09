use core_service::config::AppConfig;
use core_service::persist::{prisma, PersistCtx};
use crypto::bls::BLSCert;
use log::info;
use rpc::common::PaymentGuaranteeClaims;
use rpc::core::CoreApiClient;
use rpc::proxy::RpcProxy;
use test_log::test;
use tokio::task::JoinHandle;
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
async fn issue_payment_cert_normal() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };
    info!("Core address: {}", core_addr);
    let user_addr = Uuid::new_v4().to_string();
    let recipient_addr = Uuid::new_v4().to_string();
    let deposit_amount = 1f64;

    let core_client = RpcProxy::new(&core_addr).await?;
    core_client.register_user(user_addr.clone()).await?;

    let persist_ctx = PersistCtx::new().await?;

    // Add user deposit manually...
    persist_ctx
        .client
        .user()
        .update(
            prisma::user::address::equals(user_addr.clone()),
            vec![prisma::user::deposit::set(deposit_amount)],
        )
        .exec()
        .await?;

    let tx_id = Uuid::new_v4().to_string();
    let cert = core_client
        .issue_payment_cert(
            user_addr.clone(),
            recipient_addr.clone(),
            tx_id.clone(),
            deposit_amount / 2f64,
        )
        .await?;

    info!("Cert Issued: {:?}", cert);

    let public_params = core_client.get_public_params().await?;
    let verified = cert.verify(&public_params.public_key)?;

    assert!(verified);

    let claims: PaymentGuaranteeClaims = cert.claims_bytes()?.try_into()?;
    assert_eq!(claims.user_addr, user_addr);

    info!("Cert is valid!");

    let user = persist_ctx
        .client
        .user()
        .find_unique(prisma::user::address::equals(user_addr.clone()))
        .with(prisma::user::transactions::fetch(vec![
            prisma::user_transaction::finalized::equals(false),
        ]))
        .exec()
        .await?
        .expect("User not registered!");

    let transactions = user.transactions.unwrap();
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].tx_id, tx_id);
    assert_eq!(transactions[0].amount, deposit_amount / 2f64);

    info!("Transaction is correct!");

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn issue_payment_cert_insufficient_deposit() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };

    let user_addr = Uuid::new_v4().to_string();
    let recipient_addr = Uuid::new_v4().to_string();
    let core_client = RpcProxy::new(&core_addr).await?;
    core_client.register_user(user_addr.clone()).await?;

    let persist_ctx = PersistCtx::new().await?;

    // Add user deposit manually...
    persist_ctx
        .client
        .user()
        .update(
            prisma::user::address::equals(user_addr.clone()),
            vec![prisma::user::deposit::set(1f64)],
        )
        .exec()
        .await?;

    let tx_id = Uuid::new_v4().to_string();
    core_client
        .issue_payment_cert(user_addr.clone(), recipient_addr.clone(), tx_id, 0.7f64)
        .await?;

    let tx_id = Uuid::new_v4().to_string();
    let cert_result = core_client
        .issue_payment_cert(user_addr.clone(), recipient_addr.clone(), tx_id, 0.7f64)
        .await
        .map_err(|err| {
            info!("Issue payment cert error: {}", err);
        });

    assert!(cert_result.is_err());

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn issue_payment_cert_multiple_certs() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };

    let user_addr = Uuid::new_v4().to_string();
    let recipient_addr = Uuid::new_v4().to_string();
    let core_client = RpcProxy::new(&core_addr).await?;
    core_client.register_user(user_addr.clone()).await?;

    let persist_ctx = PersistCtx::new().await?;

    // Add user deposit manually...
    persist_ctx
        .client
        .user()
        .update(
            prisma::user::address::equals(user_addr.clone()),
            vec![prisma::user::deposit::set(1f64)],
        )
        .exec()
        .await?;

    let tx_id = Uuid::new_v4().to_string();
    core_client
        .issue_payment_cert(
            user_addr.clone(),
            recipient_addr.clone(),
            tx_id.clone(),
            0.7f64,
        )
        .await?;

    core_client
        .issue_payment_cert(user_addr.clone(), recipient_addr.clone(), tx_id, 0.7f64)
        .await?;

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn issue_payment_cert_racing_transactions() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };

    let user_addr = Uuid::new_v4().to_string();
    let recipient_addr = Uuid::new_v4().to_string();
    let deposit_amount = 1f64;

    let core_client = RpcProxy::new(&core_addr).await?;
    core_client.register_user(user_addr.clone()).await?;

    let persist_ctx = PersistCtx::new().await?;

    // Add user deposit manually...
    persist_ctx
        .client
        .user()
        .update(
            prisma::user::address::equals(user_addr.clone()),
            vec![prisma::user::deposit::set(deposit_amount)],
        )
        .exec()
        .await?;

    let user_addr_clone = user_addr.clone();
    let recipient_addr_clone = recipient_addr.clone();
    let core_client_clone = core_client.clone();
    let tx1_handle: JoinHandle<anyhow::Result<BLSCert>> = tokio::spawn(async move {
        let tx_id = Uuid::new_v4().to_string();
        let cert = core_client_clone
            .issue_payment_cert(user_addr_clone, recipient_addr_clone, tx_id, 0.7f64)
            .await?;

        Ok(cert)
    });

    let user_addr_clone = user_addr.clone();
    let recipient_addr_clone = recipient_addr.clone();
    let core_client_clone = core_client.clone();
    let tx2_handle: JoinHandle<anyhow::Result<BLSCert>> = tokio::spawn(async move {
        let tx_id = Uuid::new_v4().to_string();
        let cert = core_client_clone
            .issue_payment_cert(user_addr_clone, recipient_addr_clone, tx_id, 0.7f64)
            .await?;

        Ok(cert)
    });

    let result1 = tx1_handle.await?.map_err(|err| {
        info!("Issue payment cert error: {}", err);
        err
    });
    let result2 = tx2_handle.await?.map_err(|err| {
        info!("Issue payment cert error: {}", err);
        err
    });

    assert!(result1.is_ok() || result2.is_ok());
    assert!(result1.is_err() || result2.is_err());

    let user = persist_ctx
        .client
        .user()
        .find_unique(prisma::user::address::equals(user_addr.clone()))
        .with(prisma::user::transactions::fetch(vec![]))
        .exec()
        .await?
        .expect("User not registered!");

    assert_eq!(user.version, 2);

    let transactions = user.transactions.unwrap();
    assert_eq!(transactions.len(), 1);
    assert!(transactions[0].amount - 0.7f64 < 0.01f64);

    info!("Transaction is correct!");

    Ok(())
}
