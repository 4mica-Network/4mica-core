use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::error::PersistDbError;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::{user, user_transaction};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use test_log::test;
use uuid::Uuid;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

// Ensure a user row exists (idempotent)
async fn ensure_user(ctx: &PersistCtx, addr: &str) -> anyhow::Result<()> {
    let now = Utc::now().naive_utc();
    let am = entities::user::ActiveModel {
        address: Set(addr.to_string()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        collateral: Set("0".to_string()),
        locked_collateral: Set("0".to_string()),
        ..Default::default()
    };
    user::Entity::insert(am)
        .on_conflict(
            OnConflict::column(user::Column::Address)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(ctx.db.as_ref())
        .await?;
    Ok(())
}

#[test(tokio::test)]
async fn duplicate_transaction_id_is_noop() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();

    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient.clone(),
        tx_id.clone(),
        U256::from(2u64),
    )
    .await?;
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient,
        tx_id.clone(),
        U256::from(2u64),
    )
    .await?;

    let txs = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(tx_id))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(txs.len(), 1);
    Ok(())
}

#[test(tokio::test)]
async fn fail_transaction_twice_is_idempotent() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient,
        tx_id.clone(),
        U256::from(3u64),
    )
    .await?;

    repo::fail_transaction(&ctx, user_addr.clone(), tx_id.clone()).await?;
    repo::fail_transaction(&ctx, user_addr.clone(), tx_id.clone()).await?;

    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(7u64).to_string());
    Ok(())
}

#[test(tokio::test)]
async fn duplicate_tx_id_is_stable_and_idempotent() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(9u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    for _ in 0..3 {
        // same tx inserted multiple times must stay single-row
        let _ = repo::submit_payment_transaction(
            &ctx,
            user_addr.clone(),
            recipient.clone(),
            tx_id.clone(),
            U256::from(2u64),
        )
        .await;
    }

    let txs = user_transaction::Entity::find()
        .filter(user_transaction::Column::TxId.eq(tx_id))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(txs.len(), 1);
    Ok(())
}

/// NEW: failing a non-existent transaction should error with TransactionNotFound.
#[test(tokio::test)]
async fn fail_transaction_missing_tx_returns_err() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;

    let missing_tx_id = Uuid::new_v4().to_string();
    let res = repo::fail_transaction(&ctx, user_addr.clone(), missing_tx_id.clone()).await;

    match res {
        Err(PersistDbError::TransactionNotFound(id)) => assert_eq!(id, missing_tx_id),
        Err(e) => panic!("expected TransactionNotFound, got {e:?}"),
        Ok(_) => panic!("expected error when tx is missing"),
    }

    Ok(())
}

/// NEW: failing a transaction with the wrong user must error and cause no side effects.
#[test(tokio::test)]
async fn fail_transaction_wrong_user_returns_err_and_no_changes() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;

    let owner_addr = Uuid::new_v4().to_string();
    let other_addr = Uuid::new_v4().to_string();
    let recipient = Uuid::new_v4().to_string();

    ensure_user(&ctx, &owner_addr).await?;
    ensure_user(&ctx, &other_addr).await?;
    repo::deposit(&ctx, owner_addr.clone(), U256::from(10u64)).await?;
    repo::deposit(&ctx, other_addr.clone(), U256::from(10u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    repo::submit_payment_transaction(
        &ctx,
        owner_addr.clone(),
        recipient,
        tx_id.clone(),
        U256::from(3u64),
    )
    .await?;

    // Attempt to fail using the WRONG user address
    let res = repo::fail_transaction(&ctx, other_addr.clone(), tx_id.clone()).await;
    assert!(
        res.is_err(),
        "expected error when failing tx for the wrong user"
    );

    // Transaction should remain untouched
    let row = user_transaction::Entity::find_by_id(tx_id.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert!(!row.failed, "tx should not be marked failed");
    assert!(!row.finalized, "tx should not be finalized");

    // Collateral should be unchanged for both users
    let owner = user::Entity::find_by_id(owner_addr.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(owner.collateral, U256::from(10u64).to_string());

    let other = user::Entity::find_by_id(other_addr.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(other.collateral, U256::from(10u64).to_string());

    Ok(())
}
