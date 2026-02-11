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
#[serial_test::serial]
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
#[serial_test::serial]
async fn duplicate_withdrawal_request_updates_existing_pending() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        1,
        U256::from(10u64),
    )
    .await?;

    let first_withdrawal = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .one(ctx.db.as_ref())
        .await?
        .expect("First withdrawal should exist");

    assert_eq!(
        first_withdrawal.requested_amount,
        U256::from(10u64).to_string()
    );

    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        2,
        U256::from(5u64),
    )
    .await?;

    let pending = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .all(ctx.db.as_ref())
        .await?;

    assert_eq!(pending.len(), 1, "only one pending withdrawal should exist");

    let updated_withdrawal = &pending[0];
    assert_eq!(
        updated_withdrawal.requested_amount,
        U256::from(5u64).to_string(),
        "requested amount should be updated to new value"
    );
    assert_eq!(
        updated_withdrawal.executed_amount, "0",
        "executed amount should be reset to 0"
    );
    assert_eq!(
        updated_withdrawal.id, first_withdrawal.id,
        "same withdrawal record should be updated, not a new one created"
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn request_withdrawal_after_cancelled_creates_new_pending() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        1,
        U256::from(10u64),
    )
    .await?;

    let first_id = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .one(ctx.db.as_ref())
        .await?
        .expect("First withdrawal should exist")
        .id;

    repo::cancel_withdrawal(&ctx, user_addr.clone(), DEFAULT_ASSET_ADDRESS.to_string()).await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        2,
        U256::from(5u64),
    )
    .await?;

    let withdrawals = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .all(ctx.db.as_ref())
        .await?;

    assert_eq!(withdrawals.len(), 2, "should have two withdrawal records");

    let cancelled = withdrawals
        .iter()
        .find(|w| w.status == WithdrawalStatus::Cancelled)
        .expect("should have cancelled withdrawal");
    assert_eq!(cancelled.id, first_id);
    assert_eq!(cancelled.requested_amount, U256::from(10u64).to_string());

    let pending = withdrawals
        .iter()
        .find(|w| w.status == WithdrawalStatus::Pending)
        .expect("should have new pending withdrawal");
    assert_ne!(pending.id, first_id, "should be a new withdrawal record");
    assert_eq!(pending.requested_amount, U256::from(5u64).to_string());

    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn request_withdrawal_after_executed_creates_new_pending() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();
    ensure_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        1,
        U256::from(8u64),
    )
    .await?;

    let first_id = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .one(ctx.db.as_ref())
        .await?
        .expect("First withdrawal should exist")
        .id;

    repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(8u64),
    )
    .await?;

    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        2,
        U256::from(5u64),
    )
    .await?;

    let withdrawals = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .all(ctx.db.as_ref())
        .await?;

    assert_eq!(withdrawals.len(), 2, "should have two withdrawal records");

    let executed = withdrawals
        .iter()
        .find(|w| w.status == WithdrawalStatus::Executed)
        .expect("should have executed withdrawal");
    assert_eq!(executed.id, first_id);
    assert_eq!(executed.requested_amount, U256::from(8u64).to_string());
    assert_eq!(executed.executed_amount, U256::from(8u64).to_string());

    let pending = withdrawals
        .iter()
        .find(|w| w.status == WithdrawalStatus::Pending)
        .expect("should have new pending withdrawal");
    assert_ne!(pending.id, first_id, "should be a new withdrawal record");
    assert_eq!(pending.requested_amount, U256::from(5u64).to_string());
    assert_eq!(pending.executed_amount, "0");

    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
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
    repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(5u64),
    )
    .await?;

    // Second finalize should now ERROR (no pending withdrawal left)
    let res = repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(5u64),
    )
    .await;
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
#[serial_test::serial]
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
    repo::cancel_withdrawal(&ctx, user_addr.clone(), DEFAULT_ASSET_ADDRESS.to_string()).await?;
    let w2 = withdrawal::Entity::find_by_id(w1.id.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w2.status, WithdrawalStatus::Cancelled);

    // Finalize after cancel should now ERROR
    let res = repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(2u64),
    )
    .await;
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
#[serial_test::serial]
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
    repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(3u64),
    )
    .await?;

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(2u64)
    );
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn finalize_without_any_request_errors_and_preserves_collateral() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;

    // No request exists; finalize must ERROR now
    let res = repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(3u64),
    )
    .await;
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
#[serial_test::serial]
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
    repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(5u64),
    )
    .await?;

    // Calling cancel afterward should be a no-op on Executed withdrawals
    repo::cancel_withdrawal(&ctx, user_addr.clone(), DEFAULT_ASSET_ADDRESS.to_string()).await?;

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
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

    repo::cancel_withdrawal(&ctx, user_addr.clone(), DEFAULT_ASSET_ADDRESS.to_string()).await?;
    repo::cancel_withdrawal(&ctx, user_addr.clone(), DEFAULT_ASSET_ADDRESS.to_string()).await?;

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Cancelled);
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn finalize_withdrawal_exceeding_requested_amount_takes_minimum() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user_with_collateral(&ctx, &user_addr, U256::from(10u64)).await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        333,
        U256::from(2u64),
    )
    .await?;

    repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(5u64),
    )
    .await?;

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(8u64),
        "Collateral should be reduced by minimum(executed, requested) = min(5, 2) = 2"
    );

    let w = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr))
        .filter(withdrawal::Column::AssetAddress.eq(DEFAULT_ASSET_ADDRESS))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(w.status, WithdrawalStatus::Executed);
    assert_eq!(
        w.executed_amount,
        U256::from(2u64).to_string(),
        "Executed amount should be min(5, 2) = 2"
    );
    assert_eq!(
        w.requested_amount,
        U256::from(2u64).to_string(),
        "Requested amount unchanged"
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
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
    repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(5u64),
    )
    .await?;

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
#[serial_test::serial]
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
    repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(4u64),
    )
    .await?;

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
#[serial_test::serial]
async fn multiple_pending_withdrawals_per_user_different_assets_allowed() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();
    ensure_user(&ctx, &user_addr).await?;

    let now = Utc::now().naive_utc();
    let asset1 = "0x0000000000000000000000000000000000000000".to_string();
    let asset2 = "0x0000000000000000000000000000000000000001".to_string();

    // Insert first pending withdrawal for asset1 – should succeed
    let w1 = ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_address: Set(user_addr.clone()),
        asset_address: Set(asset1.clone()),
        requested_amount: Set(U256::from(5u64).to_string()),
        executed_amount: Set("0".into()),
        request_ts: Set(Utc::now().naive_utc()),
        status: Set(WithdrawalStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
    };
    Entity::insert(w1).exec(ctx.db.as_ref()).await?;

    // Insert second pending withdrawal for asset2 – should also succeed
    let w2 = ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_address: Set(user_addr.clone()),
        asset_address: Set(asset2.clone()),
        requested_amount: Set(U256::from(3u64).to_string()),
        executed_amount: Set("0".into()),
        request_ts: Set(Utc::now().naive_utc()),
        status: Set(WithdrawalStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
    };
    let res = Entity::insert(w2).exec(ctx.db.as_ref()).await;
    assert!(
        res.is_ok(),
        "User should be allowed to have pending withdrawals for different assets"
    );

    // Verify both withdrawals exist
    let withdrawals = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::Status.eq(WithdrawalStatus::Pending))
        .all(ctx.db.as_ref())
        .await?;

    assert_eq!(
        withdrawals.len(),
        2,
        "Should have two pending withdrawals for different assets"
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn deposit_and_withdraw_multiple_assets_updates_collateral_correctly() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::WithdrawalStatus;

    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    // Define two different assets: ETH (default) and a stablecoin
    let eth_asset = DEFAULT_ASSET_ADDRESS.to_string();
    let stablecoin_asset = "0x0000000000000000000000000000000000000001".to_string();

    // Deposit ETH: 100 units
    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(
        &ctx,
        user_addr.clone(),
        eth_asset.clone(),
        U256::from(100u64),
    )
    .await?;

    // Deposit stablecoin: 200 units
    repo::deposit(
        &ctx,
        user_addr.clone(),
        stablecoin_asset.clone(),
        U256::from(200u64),
    )
    .await?;

    // Verify initial collateral
    assert_eq!(
        read_collateral(&ctx, &user_addr, &eth_asset).await?,
        U256::from(100u64),
        "Initial ETH collateral should be 100"
    );
    assert_eq!(
        read_collateral(&ctx, &user_addr, &stablecoin_asset).await?,
        U256::from(200u64),
        "Initial stablecoin collateral should be 200"
    );

    // Request withdrawal for ETH: 30 units
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        eth_asset.clone(),
        1,
        U256::from(30u64),
    )
    .await?;

    // Request withdrawal for stablecoin: 50 units
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        stablecoin_asset.clone(),
        2,
        U256::from(50u64),
    )
    .await?;

    // Verify both withdrawal requests exist and are pending
    let eth_withdrawal = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(eth_asset.clone()))
        .one(ctx.db.as_ref())
        .await?
        .expect("ETH withdrawal request should exist");
    assert_eq!(eth_withdrawal.status, WithdrawalStatus::Pending);
    assert_eq!(
        eth_withdrawal.requested_amount,
        U256::from(30u64).to_string()
    );

    let stablecoin_withdrawal = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(stablecoin_asset.clone()))
        .one(ctx.db.as_ref())
        .await?
        .expect("Stablecoin withdrawal request should exist");
    assert_eq!(stablecoin_withdrawal.status, WithdrawalStatus::Pending);
    assert_eq!(
        stablecoin_withdrawal.requested_amount,
        U256::from(50u64).to_string()
    );

    // Finalize ETH withdrawal: execute 25 units (less than requested 30)
    repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        eth_asset.clone(),
        U256::from(25u64),
    )
    .await?;

    // Finalize stablecoin withdrawal: execute full 50 units
    repo::finalize_withdrawal(
        &ctx,
        user_addr.clone(),
        stablecoin_asset.clone(),
        U256::from(50u64),
    )
    .await?;

    // Verify ETH collateral: 100 - 25 = 75
    assert_eq!(
        read_collateral(&ctx, &user_addr, &eth_asset).await?,
        U256::from(75u64),
        "ETH collateral should be reduced by executed amount (25)"
    );

    // Verify stablecoin collateral: 200 - 50 = 150
    assert_eq!(
        read_collateral(&ctx, &user_addr, &stablecoin_asset).await?,
        U256::from(150u64),
        "Stablecoin collateral should be reduced by executed amount (50)"
    );

    // Verify both withdrawals are marked as Executed
    let eth_withdrawal_final = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(eth_asset.clone()))
        .one(ctx.db.as_ref())
        .await?
        .expect("ETH withdrawal should exist");
    assert_eq!(eth_withdrawal_final.status, WithdrawalStatus::Executed);
    assert_eq!(
        eth_withdrawal_final.executed_amount,
        U256::from(25u64).to_string(),
        "ETH executed amount should be 25"
    );

    let stablecoin_withdrawal_final = withdrawal::Entity::find()
        .filter(withdrawal::Column::UserAddress.eq(user_addr.clone()))
        .filter(withdrawal::Column::AssetAddress.eq(stablecoin_asset.clone()))
        .one(ctx.db.as_ref())
        .await?
        .expect("Stablecoin withdrawal should exist");
    assert_eq!(
        stablecoin_withdrawal_final.status,
        WithdrawalStatus::Executed
    );
    assert_eq!(
        stablecoin_withdrawal_final.executed_amount,
        U256::from(50u64).to_string(),
        "Stablecoin executed amount should be 50"
    );

    Ok(())
}
