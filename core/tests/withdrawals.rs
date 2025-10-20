use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::DEFAULT_ASSET_ADDRESS;
use core_service::persist::repo;
use entities::sea_orm_active_enums::WithdrawalStatus;
use entities::withdrawal::{self, ActiveModel, Entity};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use test_log::test;
use uuid::Uuid;

mod common;
use common::fixtures::{ensure_user, ensure_user_with_collateral, init_test_env, random_address};

use crate::common::fixtures::read_collateral;

#[test(tokio::test)]
async fn withdrawal_more_than_collateral_fails() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    let res = repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        1,
        U256::from(10u64),
    )
    .await;

    assert!(res.is_err());

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(5u64)
    );

    Ok(())
}

#[test(tokio::test)]
async fn finalize_withdrawal_twice_second_call_errors() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        1,
        U256::from(5u64),
    )
    .await?;

    // First finalize succeeds
    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    // Second finalize should now ERROR (no pending withdrawal left)
    let res = repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(5u64)).await;
    assert!(res.is_err(), "second finalize must error");

    // State remains Executed
    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);

    Ok(())
}

#[test(tokio::test)]
async fn withdrawal_request_cancel_then_finalize_errors() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    // Create and verify it's Pending
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        12345,
        U256::from(2u64),
    )
    .await?;
    let w1 = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w1.status, WithdrawalStatus::Pending);

    // Cancel it
    repo::cancel_withdrawal(&ctx, user_addr.clone()).await?;
    let w2 = withdrawal::Entity::find_by_id(w1.id.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w2.status, WithdrawalStatus::Cancelled);

    // Finalize after cancel should now ERROR
    let res = repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(2u64)).await;
    assert!(res.is_err(), "finalize after cancel must error");

    // Status remains Cancelled and collateral unchanged (5)
    let w3 = withdrawal::Entity::find_by_id(w1.id.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w3.status, WithdrawalStatus::Cancelled);

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(5u64)
    );

    Ok(())
}

#[test(tokio::test)]
async fn finalize_withdrawal_reduces_collateral() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        123,
        U256::from(5u64),
    )
    .await?;
    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(3u64)).await?;

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(2u64)
    );
    Ok(())
}

#[test(tokio::test)]
async fn finalize_without_any_request_errors_and_preserves_collateral() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    // No request exists; finalize must ERROR now
    let res = repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(3u64)).await;
    assert!(
        res.is_err(),
        "finalize without a pending request must error"
    );

    // Collateral unchanged
    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(10u64)
    );
    Ok(())
}

#[test(tokio::test)]
async fn cancel_after_finalize_does_not_change_executed() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(6u64)).await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        111,
        U256::from(5u64),
    )
    .await?;
    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    // Calling cancel afterward should be a no-op on Executed withdrawals
    repo::cancel_withdrawal(&ctx, user_addr.clone()).await?;

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);
    Ok(())
}

#[test(tokio::test)]
async fn double_cancel_is_idempotent() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(8u64)).await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        222,
        U256::from(3u64),
    )
    .await?;

    repo::cancel_withdrawal(&ctx, user_addr.clone()).await?;
    repo::cancel_withdrawal(&ctx, user_addr.clone()).await?;

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Cancelled);
    Ok(())
}

#[test(tokio::test)]
async fn finalize_withdrawal_underflow_errors() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(3u64)).await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        333,
        U256::from(2u64),
    )
    .await?;

    let res = repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(5u64)).await;
    assert!(res.is_err());

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(3u64)
    );
    Ok(())
}

#[test(tokio::test)]
async fn finalize_withdrawal_records_executed_amount_and_updates_collateral() -> anyhow::Result<()>
{
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    // user starts with 10
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    // user requests 8
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        42,
        U256::from(8u64),
    )
    .await?;

    // but chain only executes 5
    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    // user collateral must now be 10 – 5 = 5
    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(5u64)
    );

    // withdrawal row must be Executed and executed_amount = 5, requested amount still 8
    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);
    assert_eq!(
        w.requested_amount,
        U256::from(8u64).to_string(),
        "requested amount unchanged"
    );
    assert_eq!(
        w.executed_amount,
        U256::from(5u64).to_string(),
        "executed amount persisted correctly"
    );

    Ok(())
}

#[test(tokio::test)]
async fn finalize_withdrawal_with_full_execution_still_sets_executed_amount() -> anyhow::Result<()>
{
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    // request 4, chain executes full 4
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        99,
        U256::from(4u64),
    )
    .await?;
    repo::finalize_withdrawal(&ctx, user_addr.clone(), U256::from(4u64)).await?;

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(6u64)
    );

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);
    assert_eq!(
        w.requested_amount,
        U256::from(4u64).to_string(),
        "requested amount unchanged"
    );
    assert_eq!(
        w.executed_amount,
        U256::from(4u64).to_string(),
        "executed amount persisted correctly"
    );

    Ok(())
}

#[test(tokio::test)]
async fn unique_pending_withdrawal_per_user_is_enforced() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();
    ensure_user(&ctx, &user_addr).await?;

    let now = Utc::now().naive_utc();

    // insert the first Pending withdrawal – should succeed
    let w1 = ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_address: Set(user_addr.clone()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        requested_amount: Set(U256::from(5u64).to_string()),
        executed_amount: Set("0".into()),
        request_ts: Set(Utc::now().naive_utc()),
        status: Set(WithdrawalStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
    };
    Entity::insert(w1).exec(ctx.db.as_ref()).await?;

    // insert a second Pending withdrawal for the same user – should violate the
    // partial unique index and return a database error.
    let w2 = ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_address: Set(user_addr.clone()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        requested_amount: Set(U256::from(5u64).to_string()),
        executed_amount: Set("0".into()),
        request_ts: Set(Utc::now().naive_utc()),
        status: Set(WithdrawalStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
    };

    let res = Entity::insert(w2).exec(ctx.db.as_ref()).await;
    assert!(
        res.is_err(),
        "Second pending withdrawal for same user should violate unique index"
    );
    Ok(())
}
