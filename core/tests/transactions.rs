use alloy::primitives::U256;
use core_service::config::AppConfig;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::{user, user_transaction};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use test_log::test;
use uuid::Uuid;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

#[test(tokio::test)]
async fn duplicate_transaction_id_is_noop() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();
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
        .all(&*ctx.db)
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
        .one(&*ctx.db)
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
        .all(&*ctx.db)
        .await?;
    assert_eq!(txs.len(), 1);
    Ok(())
}
