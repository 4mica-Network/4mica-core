use core_service::config::AppConfig;
use rpc::core::CoreApiClient;
use rpc::proxy::RpcProxy;
use test_log::test;
use uuid::Uuid;

// --- SeaORM / persist imports (new) ---
use core_service::persist::PersistCtx;
use entities::{user, user_transaction};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

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
async fn register_user_via_rpc() -> anyhow::Result<()> {
    let config = init()?;
    let core_addr = {
        let core_service::config::ServerConfig { host, port, .. } = &config.server_config;
        format!("{}:{}", host, port)
    };

    let user_addr = Uuid::new_v4().to_string();

    let core_client = RpcProxy::new(&core_addr).await?;
    core_client.register_user(user_addr.clone()).await?;

    // SeaORM ctx
    let persist_ctx = PersistCtx::new().await?;

    // Load user via SeaORM
    let user_row = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*persist_ctx.db)
        .await?
        .expect("User not registered!");

    // In SeaORM impl, we initialize `version = 0`, `collateral = 0.0`
    assert_eq!(user_row.version, 0);
    assert_eq!(user_row.collateral, 0.0);

    // Registering the user again should be idempotent and not bump version
    core_client.register_user(user_addr.clone()).await?;

    let user_row2 = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*persist_ctx.db)
        .await?
        .expect("User disappeared after re-register!");

    assert_eq!(
        user_row2.version, 0,
        "Idempotent register should not bump version"
    );
    assert_eq!(user_row2.collateral, 0.0);

    Ok(())
}

// -----------------------------------------------------------------------------
// Additional repo-level tests (no RPC dependency)
// -----------------------------------------------------------------------------
mod repo_tests {
    use super::*;
    use core_service::persist::repo;

    /// Register or update a user with a starting deposit (collateral).
    #[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
    async fn register_user_with_deposit_sets_collateral_and_bumps_version_on_update()
    -> anyhow::Result<()> {
        let _ = init()?;
        let ctx = PersistCtx::new().await?;
        let user_addr = Uuid::new_v4().to_string();

        // First time: insert with collateral = 5.5, version = 0
        repo::register_user_with_deposit(&ctx, user_addr.clone(), 5.5).await?;

        let u1 = user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(&*ctx.db)
            .await?
            .expect("user missing after register_user_with_deposit");
        assert_eq!(u1.collateral, 5.5);
        assert_eq!(u1.version, 0);

        // Second time same user: set collateral again, bump version by +1
        repo::register_user_with_deposit(&ctx, user_addr.clone(), 9.0).await?;

        let u2 = user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(&*ctx.db)
            .await?
            .expect("user missing after second register_user_with_deposit");
        assert_eq!(u2.collateral, 9.0);
        assert_eq!(u2.version, 1, "expected version to bump on update");

        Ok(())
    }

    /// Increment deposit (collateral) for an existing user.
    #[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
    async fn add_user_deposit_increments_collateral() -> anyhow::Result<()> {
        let _ = init()?;
        let ctx = PersistCtx::new().await?;
        let user_addr = Uuid::new_v4().to_string();

        repo::register_user_with_deposit(&ctx, user_addr.clone(), 2.0).await?;
        repo::add_user_deposit(&ctx, user_addr.clone(), 3.25).await?;

        let u = user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(&*ctx.db)
            .await?
            .expect("user missing after add_user_deposit");
        assert!((u.collateral - 5.25).abs() < f64::EPSILON);

        Ok(())
    }

    /// Submitting a payment transaction requires the user to exist.
    #[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
    async fn submit_payment_tx_user_not_registered() -> anyhow::Result<()> {
        let _ = init()?;
        let ctx = PersistCtx::new().await?;
        let user_addr = Uuid::new_v4().to_string();
        let recipient = Uuid::new_v4().to_string();
        let tx_id = Uuid::new_v4().to_string();

        let err = repo::submit_payment_transaction(
            &ctx,
            user_addr,
            recipient,
            tx_id,
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

    /// Not enough deposit available should fail.
    #[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
    async fn submit_payment_tx_not_enough_deposit() -> anyhow::Result<()> {
        let _ = init()?;
        let ctx = PersistCtx::new().await?;
        let user_addr = Uuid::new_v4().to_string();
        let recipient = Uuid::new_v4().to_string();

        // Put 2.0 into collateral
        repo::register_user_with_deposit(&ctx, user_addr.clone(), 2.0).await?;

        // Ask for 3.0, should fail
        let tx_id = Uuid::new_v4().to_string();
        let err = repo::submit_payment_transaction(
            &ctx,
            user_addr.clone(),
            recipient,
            tx_id,
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

    /// Happy path: submit, verify, confirm, and fail scenarios.
    #[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
    async fn submit_verify_and_fail_flow() -> anyhow::Result<()> {
        let _ = init()?;
        let ctx = PersistCtx::new().await?;
        let user_addr = Uuid::new_v4().to_string();
        let recipient = Uuid::new_v4().to_string();

        // Plenty of collateral
        repo::register_user_with_deposit(&ctx, user_addr.clone(), 10.0).await?;

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

        // Submit tx B = 4.0 (still ok)
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

        // Check both exist and are not finalized
        let txs = user_transaction::Entity::find()
            .filter(user_transaction::Column::UserAddress.eq(user_addr.clone()))
            .all(&*ctx.db)
            .await?;
        assert_eq!(txs.len(), 2);
        assert!(txs.iter().all(|t| !t.finalized && !t.verified));

        // Verify tx A
        let result = repo::verify_transaction(&ctx, tx_a.clone()).await?;
        assert!(matches!(
            result,
            rpc::common::TransactionVerificationResult::Verified
        ));

        // Verify tx A again -> AlreadyVerified
        let result2 = repo::verify_transaction(&ctx, tx_a.clone()).await?;
        assert!(matches!(
            result2,
            rpc::common::TransactionVerificationResult::AlreadyVerified
        ));

        // Confirm tx B (mark finalized)
        repo::confirm_transaction(&ctx, tx_b.clone()).await?;

        let tx_b_row = user_transaction::Entity::find_by_id(tx_b.clone())
            .one(&*ctx.db)
            .await?
            .expect("tx_b missing");
        assert!(tx_b_row.finalized);

        // Fail tx A (sets finalized+failed and decrements collateral by 3.0)
        repo::fail_transaction(&ctx, user_addr.clone(), tx_a.clone()).await?;

        let failed_a = user_transaction::Entity::find_by_id(tx_a.clone())
            .one(&*ctx.db)
            .await?
            .expect("tx_a missing");
        assert!(failed_a.finalized && failed_a.failed);

        // Collateral should have been decremented by 3.0
        let u = user::Entity::find()
            .filter(user::Column::Address.eq(user_addr.clone()))
            .one(&*ctx.db)
            .await?
            .expect("user missing");
        // Started at 10.0; no collateral debited for submission; only fail_transaction subtracts 3.0.
        assert!((u.collateral - 7.0).abs() < f64::EPSILON);

        Ok(())
    }

    /// Multiple submissions that sum to exactly collateral should be allowed.
    #[test(tokio::test(flavor = "multi_thread", worker_threads = 4))]
    async fn submit_multiple_that_exactly_use_all_collateral() -> anyhow::Result<()> {
        let _ = init()?;
        let ctx = PersistCtx::new().await?;
        let user_addr = Uuid::new_v4().to_string();
        let recipient = Uuid::new_v4().to_string();

        repo::register_user_with_deposit(&ctx, user_addr.clone(), 5.0).await?;

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

        // Submitting another 0.01 should fail (exceeds total collateral)
        let err = repo::submit_payment_transaction(
            &ctx,
            user_addr.clone(),
            recipient.clone(),
            Uuid::new_v4().to_string(),
            0.01,
            "c3".to_string(),
        )
        .await
        .expect_err("expected NotEnoughDeposit when exceeding collateral");

        matches!(err, repo::SubmitPaymentTxnError::NotEnoughDeposit)
            .then_some(())
            .ok_or_else(|| anyhow::anyhow!("wrong error variant"))?;

        Ok(())
    }
}
