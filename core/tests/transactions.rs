use alloy::primitives::U256;
use core_service::persist::repo;
use core_service::{config::DEFAULT_ASSET_ADDRESS, error::PersistDbError};
use entities::user_transaction;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use test_log::test;
use uuid::Uuid;

mod common;
use common::fixtures::{ensure_user, ensure_user_with_collateral, init_test_env, random_address};

use crate::common::fixtures::read_collateral;

#[test(tokio::test)]
async fn duplicate_transaction_id_is_noop() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    let recipient = random_address();

    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        tx_id.clone(),
        U256::from(2u64),
    )
    .await?;
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient,
        DEFAULT_ASSET_ADDRESS.to_string(),
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
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();
    let recipient = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient,
        DEFAULT_ASSET_ADDRESS.to_string(),
        tx_id.clone(),
        U256::from(3u64),
    )
    .await?;

    repo::fail_transaction(&ctx, user_addr.clone(), tx_id.clone()).await?;
    repo::fail_transaction(&ctx, user_addr.clone(), tx_id.clone()).await?;

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(7u64)
    );
    Ok(())
}

#[test(tokio::test)]
async fn duplicate_tx_id_is_stable_and_idempotent() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();
    let recipient = random_address();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(9u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    for _ in 0..3 {
        // same tx inserted multiple times must stay single-row
        let _ = repo::submit_payment_transaction(
            &ctx,
            user_addr.clone(),
            recipient.clone(),
            DEFAULT_ASSET_ADDRESS.to_string(),
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
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

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
    let (_cfg, ctx) = init_test_env().await?;

    let owner_addr = random_address();
    let other_addr = random_address();
    let recipient = random_address();

    ensure_user_with_collateral(&ctx, &owner_addr, U256::from(10u64)).await?;
    ensure_user_with_collateral(&ctx, &other_addr, U256::from(10u64)).await?;

    let tx_id = Uuid::new_v4().to_string();
    repo::submit_payment_transaction(
        &ctx,
        owner_addr.clone(),
        recipient,
        DEFAULT_ASSET_ADDRESS.to_string(),
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
    assert_eq!(
        read_collateral(&ctx, &owner_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(10u64)
    );

    assert_eq!(
        read_collateral(&ctx, &other_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(10u64)
    );

    Ok(())
}
