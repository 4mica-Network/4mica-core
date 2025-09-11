use core_service::config::AppConfig;
use core_service::persist::PersistCtx;
use crypto::bls::BLSCert;
use log::info;
use rpc::common::PaymentGuaranteeClaims;
use rpc::core::CoreApiClient;
use rpc::proxy::RpcProxy;
use test_log::test;
use tokio::task::JoinHandle;
// --- SeaORM bits ---
use entities::user_transaction;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

// NOTE: don't import `test` to avoid ambiguity with built-in #[test]
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

    let user_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));
    let recipient_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));

    let core_client = RpcProxy::new(&core_addr).await?;

    // add initial collateral
    let deposit_amount = 1f64;
    core_client
        .deposit(user_addr.clone(), deposit_amount)
        .await?;

    let tx_id = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
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

    // Check unfinalized tx exists and matches
    let persist_ctx = PersistCtx::new().await?;
    let transactions = user_transaction::Entity::find()
        .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
        .filter(user_transaction::Column::Finalized.eq(false))
        .all(&*persist_ctx.db)
        .await?;
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].tx_id, tx_id);
    assert_eq!(transactions[0].amount, deposit_amount / 2f64);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn issue_payment_cert_insufficient_deposit() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };

    let core_client = RpcProxy::new(&core_addr).await?;
    let user_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));
    let recipient_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));

    // give the user 1.0 collateral
    core_client.deposit(user_addr.clone(), 1.0).await?;

    // First cert 0.7 succeeds
    let tx_id1 = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
    core_client
        .issue_payment_cert(user_addr.clone(), recipient_addr.clone(), tx_id1, 0.7f64)
        .await?;

    // Second cert 0.7 should fail
    let tx_id2 = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
    let cert_result = core_client
        .issue_payment_cert(user_addr.clone(), recipient_addr.clone(), tx_id2, 0.7f64)
        .await;

    assert!(cert_result.is_err());
    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn issue_payment_cert_multiple_certs_same_tx_id_is_idempotent() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };

    let user_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));
    let recipient_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));
    let core_client = RpcProxy::new(&core_addr).await?;

    // user has 1.0 collateral
    core_client.deposit(user_addr.clone(), 1.0).await?;

    let tx_id = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
    core_client
        .issue_payment_cert(
            user_addr.clone(),
            recipient_addr.clone(),
            tx_id.clone(),
            0.7f64,
        )
        .await?;

    // second call with same tx_id should be idempotent
    core_client
        .issue_payment_cert(
            user_addr.clone(),
            recipient_addr.clone(),
            tx_id.clone(),
            0.7f64,
        )
        .await?;

    // Ensure only one record exists for this tx_id
    let ctx = PersistCtx::new().await?;
    let txs = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(tx_id))
        .all(&*ctx.db)
        .await?;
    assert_eq!(txs.len(), 1);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn issue_payment_cert_racing_transactions() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };

    let user_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));
    let recipient_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));
    let deposit_amount = 1f64;

    let core_client = RpcProxy::new(&core_addr).await?;

    core_client
        .deposit(user_addr.clone(), deposit_amount)
        .await?;

    // Launch two concurrent cert requests of 0.7 each; only one should succeed
    let user_addr_clone = user_addr.clone();
    let recipient_addr_clone = recipient_addr.clone();
    let core_client_clone = core_client.clone();
    let tx1_handle: JoinHandle<anyhow::Result<BLSCert>> = tokio::spawn(async move {
        let tx_id = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
        core_client_clone
            .issue_payment_cert(user_addr_clone, recipient_addr_clone, tx_id, 0.7f64)
            .await
            .map_err(anyhow::Error::from)
    });

    let user_addr_clone = user_addr.clone();
    let recipient_addr_clone = recipient_addr.clone();
    let core_client_clone = core_client.clone();
    let tx2_handle: JoinHandle<anyhow::Result<BLSCert>> = tokio::spawn(async move {
        let tx_id = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
        core_client_clone
            .issue_payment_cert(user_addr_clone, recipient_addr_clone, tx_id, 0.7f64)
            .await
            .map_err(anyhow::Error::from)
    });

    let result1 = tx1_handle.await?;
    let result2 = tx2_handle.await?;

    assert!(result1.is_ok() || result2.is_ok(), "expected one success");
    assert!(result1.is_err() || result2.is_err(), "expected one failure");

    let ctx = PersistCtx::new().await?;
    let txs = user_transaction::Entity::find()
        .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
        .all(&*ctx.db)
        .await?;
    assert_eq!(txs.len(), 1);
    assert!((txs[0].amount - 0.7f64).abs() < 0.01f64);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn issue_payment_cert_exactly_consumes_all_available() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };
    let core_client = RpcProxy::new(&core_addr).await?;

    let user_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));
    let recipient_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));

    core_client.deposit(user_addr.clone(), 1.0).await?;

    // Two certs 0.4 and 0.6 should both succeed
    let tx1 = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
    core_client
        .issue_payment_cert(user_addr.clone(), recipient_addr.clone(), tx1, 0.4)
        .await?;

    let tx2 = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
    core_client
        .issue_payment_cert(user_addr.clone(), recipient_addr.clone(), tx2, 0.6)
        .await?;

    // Third should fail
    let tx3 = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
    let res = core_client
        .issue_payment_cert(user_addr.clone(), recipient_addr.clone(), tx3, 0.01)
        .await;
    assert!(res.is_err());

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn get_transactions_by_hash_returns_expected() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };
    let core_client = RpcProxy::new(&core_addr).await?;

    let user_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));
    let recipient_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));

    core_client.deposit(user_addr.clone(), 5.0).await?;

    let tx1 = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
    let tx2 = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
    core_client
        .issue_payment_cert(user_addr.clone(), recipient_addr.clone(), tx1.clone(), 1.0)
        .await?;
    core_client
        .issue_payment_cert(user_addr.clone(), recipient_addr.clone(), tx2.clone(), 2.5)
        .await?;

    let list = core_client
        .get_transactions_by_hash(vec![tx1.clone(), tx2.clone()])
        .await?;
    assert_eq!(list.len(), 2);
    let mut hashes: Vec<_> = list.into_iter().map(|t| t.tx_hash).collect();
    hashes.sort();
    let mut expected = vec![tx1, tx2];
    expected.sort();
    assert_eq!(hashes, expected);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn verify_transaction_idempotent() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };
    let core_client = RpcProxy::new(&core_addr).await?;

    let user_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));
    let recipient_addr = format!("0x{}", hex::encode(rand::random::<[u8; 20]>()));

    core_client.deposit(user_addr.clone(), 2.0).await?;

    let tx = format!("0x{}", hex::encode(rand::random::<[u8; 32]>()));
    core_client
        .issue_payment_cert(user_addr.clone(), recipient_addr.clone(), tx.clone(), 1.0)
        .await?;

    let r1 = core_client.verify_transaction(tx.clone()).await?;
    assert!(matches!(
        r1,
        rpc::common::TransactionVerificationResult::Verified
    ));

    let r2 = core_client.verify_transaction(tx.clone()).await?;
    assert!(matches!(
        r2,
        rpc::common::TransactionVerificationResult::AlreadyVerified
    ));

    Ok(())
}
