use chrono::Utc;
use core_service::config::AppConfig;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::{guarantee, user, user_transaction};
use rpc::common::TransactionVerificationResult;
use rpc::core::CoreApiClient;
use rpc::proxy::RpcProxy;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
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

//
// ────────────────────── RPC Smoke Test ──────────────────────
//
#[ignore]
#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn add_collateral_via_rpc() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };

    let user_addr = Uuid::new_v4().to_string();
    let core_client = RpcProxy::new(&core_addr)
        .await
        .map_err(anyhow::Error::from)?;

    // Add collateral over RPC
    core_client
        .add_collateral(user_addr.clone(), 5.0)
        .await
        .map_err(anyhow::Error::from)?;

    // SeaORM ctx
    let persist_ctx = PersistCtx::new().await?;
    let user_row = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*persist_ctx.db)
        .await?
        .expect("User not created by add_collateral!");

    assert_eq!(user_row.collateral, 5.0);

    Ok(())
}

//
// ────────────────────── Direct Repo Tests ──────────────────────
//

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn add_collateral_creates_and_increments_user() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    // First call should create the user
    repo::add_collateral(&ctx, user_addr.clone(), 5.0).await?;
    let u1 = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
        .expect("user missing after add_collateral");
    assert_eq!(u1.collateral, 5.0);

    // Second call increments collateral
    repo::add_collateral(&ctx, user_addr.clone(), 3.0).await?;
    let u2 = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
        .expect("user missing after add_collateral second time");
    assert_eq!(u2.collateral, 8.0);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn submit_payment_tx_user_not_registered() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();

    let err = repo::submit_payment_transaction(
        &ctx,
        user_addr,
        recipient,
        Uuid::new_v4().to_string(),
        1.0,
        "dummy-cert".to_string(),
    )
    .await
    .expect_err("expected UserNotRegistered");

    matches!(err, repo::SubmitPaymentTxnError::UserNotRegistered)
        .then_some(())
        .ok_or_else(|| anyhow::anyhow!("wrong error variant"))?;
    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn submit_payment_tx_not_enough_deposit() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();

    repo::add_collateral(&ctx, user_addr.clone(), 2.0).await?;

    let err = repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient,
        Uuid::new_v4().to_string(),
        3.0,
        "dummy-cert".to_string(),
    )
    .await
    .expect_err("expected NotEnoughDeposit");

    matches!(err, repo::SubmitPaymentTxnError::NotEnoughDeposit)
        .then_some(())
        .ok_or_else(|| anyhow::anyhow!("wrong error variant"))?;
    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn submit_verify_confirm_fail_flow() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();

    repo::add_collateral(&ctx, user_addr.clone(), 10.0).await?;

    // Submit tx A = 3.0
    let tx_a = Uuid::new_v4().to_string();
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient.clone(),
        tx_a.clone(),
        3.0,
        "cert-a".to_string(),
    )
    .await?;

    // Submit tx B = 4.0
    let tx_b = Uuid::new_v4().to_string();
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient.clone(),
        tx_b.clone(),
        4.0,
        "cert-b".to_string(),
    )
    .await?;

    // Both exist and are unverified/unfinalized
    let txs = user_transaction::Entity::find()
        .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
        .all(&*ctx.db)
        .await?;
    assert_eq!(txs.len(), 2);
    assert!(txs.iter().all(|t| !t.finalized && !t.verified));

    // Verify A
    let result = repo::verify_transaction(&ctx, tx_a.clone()).await?;
    assert!(matches!(result, TransactionVerificationResult::Verified));

    // Verify again -> AlreadyVerified
    let result2 = repo::verify_transaction(&ctx, tx_a.clone()).await?;
    assert!(matches!(
        result2,
        TransactionVerificationResult::AlreadyVerified
    ));

    // Confirm B
    repo::confirm_transaction(&ctx, tx_b.clone()).await?;
    let tx_b_row = user_transaction::Entity::find_by_id(tx_b.clone())
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert!(tx_b_row.finalized);

    // Fail A
    repo::fail_transaction(&ctx, user_addr.clone(), tx_a.clone()).await?;
    let failed_a = user_transaction::Entity::find_by_id(tx_a.clone())
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert!(failed_a.finalized && failed_a.failed);

    // Collateral should drop by 3.0
    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert!((u.collateral - 7.0).abs() < f64::EPSILON);

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn multiple_submissions_exactly_use_all_collateral() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();

    repo::add_collateral(&ctx, user_addr.clone(), 5.0).await?;

    let tx1 = Uuid::new_v4().to_string();
    let tx2 = Uuid::new_v4().to_string();

    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient.clone(),
        tx1.clone(),
        2.0,
        "c1".to_string(),
    )
    .await?;
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient.clone(),
        tx2.clone(),
        3.0,
        "c2".to_string(),
    )
    .await?;

    // Submitting another small tx should fail
    let err = repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient,
        Uuid::new_v4().to_string(),
        0.01,
        "c3".to_string(),
    )
    .await
    .expect_err("expected NotEnoughDeposit");

    matches!(err, repo::SubmitPaymentTxnError::NotEnoughDeposit)
        .then_some(())
        .ok_or_else(|| anyhow::anyhow!("wrong error variant"))?;
    Ok(())
}

#[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
async fn store_and_get_certificate_and_check_guarantee() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let tab_id = Uuid::new_v4().to_string();
    let req_id = 1;
    let now = Utc::now().naive_utc();
    // Insert a dummy user first
    let user_addr = Uuid::new_v4().to_string();
    let user_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set(0.0),
        locked_collateral: Set(0.0),
        revenue: Set(0.0),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(user_am)
        .exec(&*ctx.db)
        .await?;

    // Insert a Tab row with user_address
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(user_addr.clone()), // ✅ required
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(&*ctx.db)
        .await?;
    // Now store the certificate
    repo::store_certificate(
        &ctx,
        tab_id.clone(),
        req_id,
        "from".to_string(),
        "to".to_string(),
        42.0,
        chrono::Utc::now().naive_utc(),
        "bls-cert".to_string(),
    )
    .await?;

    // via repo API
    let cert = repo::get_certificate(&ctx, tab_id.clone(), req_id)
        .await?
        .expect("certificate missing");
    assert_eq!(cert.cert, Some("bls-cert".to_string()));
    assert_eq!(cert.value, 42.0);

    // directly via guarantee::Entity
    let g = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(tab_id.clone()))
        .filter(guarantee::Column::ReqId.eq(req_id))
        .one(&*ctx.db)
        .await?
        .expect("guarantee missing");
    assert_eq!(g.from_address, "from");
    assert_eq!(g.to_address, "to");
    assert_eq!(g.value, 42.0);

    Ok(())
}
