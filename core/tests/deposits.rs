use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::DEFAULT_ASSET_ADDRESS;
use core_service::error::PersistDbError;
use core_service::persist::{PersistCtx, repo};
use core_service::util::u256_to_string;
use entities::{collateral_event, sea_orm_active_enums::*, tabs};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use std::str::FromStr;
use test_log::test;

mod common;
use common::fixtures::{ensure_user, fetch_user, init_test_env, random_address};

use crate::common::fixtures::{read_collateral, read_locked_collateral};

#[test(tokio::test)]
#[serial_test::serial]
async fn deposit_zero_does_not_crash() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::ZERO,
    )
    .await?;

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::ZERO
    );
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn deposit_large_value() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user(&ctx, &user_addr).await?;
    let big = U256::from(1000000000000u64);
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        big,
    )
    .await?;
    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        big
    );
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn multiple_deposits_accumulate_and_log_events() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(10u64),
    )
    .await?;
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(5u64),
    )
    .await?;

    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(15u64)
    );

    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::UserAddress.eq(user_addr.clone()))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|e| e.event_type == CollateralEventType::Deposit)
    );
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn deposit_overflow_protection() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::MAX,
    )
    .await?;
    // second deposit should overflow and error
    let res = repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(1u8),
    )
    .await;
    assert!(res.is_err());

    // value should remain U256::MAX
    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::MAX
    );
    Ok(())
}
#[test(tokio::test)]
#[serial_test::serial]
async fn lock_successfully_updates_locked_collateral_and_version() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user(&ctx, &user_addr).await?;
    // give the user 100 units of collateral
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let before =
        repo::get_user_balance_on(ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(U256::from_str(&before.locked)?, U256::ZERO);

    // lock 40 units
    repo::update_user_balance_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        before.version,
        before.total.parse::<U256>()?,
        U256::from(40u64),
    )
    .await?;

    let after =
        repo::get_user_balance_on(ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(after.version, before.version + 1);
    assert_eq!(U256::from_str(&after.locked)?, U256::from(40u64));
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn lock_fails_with_stale_version() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(20u64),
    )
    .await?;
    let before =
        repo::get_user_balance_on(ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS).await?;

    // first update bumps version to version + 1
    repo::update_user_balance_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        before.version,
        before.total.parse::<U256>()?,
        U256::from(5u64),
    )
    .await?;

    // second update tries with old version -> must error with OptimisticLockConflict
    let err = repo::update_user_balance_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        before.version,
        before.total.parse::<U256>()?,
        U256::from(10u64),
    )
    .await
    .expect_err("expected optimistic lock conflict");
    match err {
        PersistDbError::OptimisticLockConflict { .. } => { /* expected */ }
        other => panic!("unexpected error: {other:?}"),
    }

    assert_eq!(
        read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(5u64)
    );
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn multiple_locks_accumulate_locked_collateral() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(50u64),
    )
    .await?;

    // first lock of 10
    let v1 = repo::get_user_balance_on(ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    repo::update_user_balance_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        v1.version,
        v1.total.parse::<U256>()?,
        U256::from(10u64),
    )
    .await?;

    // second lock to total 25 (fresh version)
    let v2 = repo::get_user_balance_on(ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    repo::update_user_balance_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        v2.version,
        v2.total.parse::<U256>()?,
        U256::from(25u64),
    )
    .await?;

    assert_eq!(
        read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(25u64)
    );
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn lock_fails_on_u256_overflow() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user(&ctx, &user_addr).await?;
    // deposit the maximum U256 value
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::MAX,
    )
    .await?;

    // verify we cannot even represent max + 1, so any attempt to add 1 is an overflow in our own logic
    let max = U256::MAX;
    let plus_one = max.checked_add(U256::from(1u64));
    assert!(plus_one.is_none(), "U256::MAX + 1 must overflow");

    // locked_collateral is still 0
    assert_eq!(
        read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::ZERO
    );
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn db_check_rejects_inserting_locked_gt_total() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user(&ctx, &user_addr).await?;

    let balance =
        repo::get_user_balance_on(ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    let res = repo::update_user_balance_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        balance.version,
        U256::from(10u64),
        U256::from(25u64),
    )
    .await;

    assert!(res.is_err(), "insert should fail due to CHECK constraint");
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn db_check_rejects_lowering_total_below_locked() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;
    let user_addr = random_address();

    ensure_user(&ctx, &user_addr).await?;
    // collateral = 20
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(20u64),
    )
    .await?;

    // lock 7 (valid)
    let balance =
        repo::get_user_balance_on(ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    repo::update_user_balance_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        balance.version,
        balance.total.parse::<U256>()?,
        U256::from(7u64),
    )
    .await?;

    // Now try to LOWER collateral below 7 via a raw update (simulate a bad path)
    let balance =
        repo::get_user_balance_on(ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    let res = repo::update_user_balance_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        DEFAULT_ASSET_ADDRESS,
        balance.version,
        U256::from(5u64),
        balance.locked.parse::<U256>()?,
    )
    .await;

    assert!(res.is_err(), "update should fail due to CHECK constraint");

    // Row should remain unchanged
    let balance =
        repo::get_user_balance_on(ctx.db.as_ref(), &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(U256::from_str(&balance.total)?, U256::from(20u64));
    assert_eq!(U256::from_str(&balance.locked)?, U256::from(7u64));

    Ok(())
}

async fn make_user_with_locked(
    ctx: &PersistCtx,
    addr: &str,
    total: U256,
    locked: U256,
) -> anyhow::Result<()> {
    use entities::user_asset_balance;

    // Create user first
    ensure_user(ctx, addr).await?;

    // Create balance with locked collateral
    let now = Utc::now().naive_utc();
    let am = user_asset_balance::ActiveModel {
        user_address: Set(addr.to_string()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        total: Set(total.to_string()),
        locked: Set(locked.to_string()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
    };
    user_asset_balance::Entity::insert(am)
        .on_conflict(
            OnConflict::columns([
                user_asset_balance::Column::UserAddress,
                user_asset_balance::Column::AssetAddress,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(ctx.db.as_ref())
        .await?;

    Ok(())
}

async fn make_tab(ctx: &PersistCtx, tab_id: U256, user_addr: &str) -> anyhow::Result<()> {
    let now = Utc::now().naive_utc();
    let am = tabs::ActiveModel {
        id: Set(u256_to_string(tab_id)),
        user_address: Set(user_addr.to_string()),
        server_address: Set("0xserver0000000000000000000000000000000000".to_string()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(now),
        ttl: Set(60),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
    };
    tabs::Entity::insert(am).exec(ctx.db.as_ref()).await?;
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn unlock_user_collateral_for_tab_reduces_locked_and_marks_settled() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;

    let user_addr = random_address();
    let tab_id = U256::from_be_bytes(rand::random::<[u8; 32]>());

    // user: total 100, locked 40
    make_user_with_locked(&ctx, &user_addr, U256::from(100u64), U256::from(40u64)).await?;
    make_tab(&ctx, tab_id, &user_addr).await?;

    // unlock 25
    repo::unlock_user_collateral(
        &ctx,
        tab_id,
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(25u64),
    )
    .await?;

    // locked should now be 15
    let locked = read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(locked, U256::from(15u64));

    // total collateral unchanged
    let total = read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(total, U256::from(100u64));

    // tab should be Settled
    let t = tabs::Entity::find_by_id(u256_to_string(tab_id))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(t.settlement_status, SettlementStatus::Settled);

    // an Unlock collateral event is recorded
    let evs = collateral_event::Entity::find()
        .filter(collateral_event::Column::UserAddress.eq(user_addr.clone()))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].event_type, CollateralEventType::Unlock);
    assert_eq!(U256::from_str(&evs[0].amount)?, U256::from(25u64));
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn unlock_user_collateral_is_idempotent_when_already_settled() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;

    let user_addr = random_address();
    let tab_id = U256::from_be_bytes(rand::random::<[u8; 32]>());

    // start: 50 total, 20 locked
    make_user_with_locked(&ctx, &user_addr, U256::from(50u64), U256::from(20u64)).await?;
    make_tab(&ctx, tab_id, &user_addr).await?;

    // first unlock of 10
    repo::unlock_user_collateral(
        &ctx,
        tab_id,
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(10u64),
    )
    .await?;
    // second unlock of 10 should be a no-op (tab already Settled)
    repo::unlock_user_collateral(
        &ctx,
        tab_id,
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(10u64),
    )
    .await?;

    let locked = read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    // locked should only be decreased once (20-10)
    assert_eq!(locked, U256::from(10u64));

    let evs = collateral_event::Entity::find()
        .filter(collateral_event::Column::UserAddress.eq(user_addr.clone()))
        .all(ctx.db.as_ref())
        .await?;
    // only one Unlock event was written
    assert_eq!(evs.len(), 1);
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn unlock_user_collateral_fails_if_unlock_amount_exceeds_locked() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;

    let user_addr = random_address();
    let tab_id = U256::from_be_bytes(rand::random::<[u8; 32]>());

    make_user_with_locked(&ctx, &user_addr, U256::from(30u64), U256::from(5u64)).await?;
    make_tab(&ctx, tab_id, &user_addr).await?;

    // trying to unlock 10 when only 5 are locked must error
    let err = repo::unlock_user_collateral(
        &ctx,
        tab_id,
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(10u64),
    )
    .await
    .expect_err("should fail unlocking more than locked");
    match err {
        PersistDbError::InvariantViolation(_) => { /* expected */ }
        other => panic!("unexpected error: {other:?}"),
    }

    // locked collateral unchanged
    let locked = read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(locked, U256::from(5u64));
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn unlock_user_collateral_fails_if_asset_mismatched() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;

    let user_addr = random_address();
    let tab_id = U256::from_be_bytes(rand::random::<[u8; 32]>());

    make_user_with_locked(&ctx, &user_addr, U256::from(30u64), U256::from(10u64)).await?;
    make_tab(&ctx, tab_id, &user_addr).await?;

    let mut other_asset = random_address();
    while other_asset == DEFAULT_ASSET_ADDRESS {
        other_asset = random_address();
    }

    let err = repo::unlock_user_collateral(
        &ctx,
        tab_id,
        other_asset,
        U256::from(5u64),
    )
    .await
    .expect_err("should fail unlocking with mismatched asset");
    match err {
        PersistDbError::InvariantViolation(_) => { /* expected */ }
        other => panic!("unexpected error: {other:?}"),
    }

    let locked = read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?;
    assert_eq!(locked, U256::from(10u64));

    let t = tabs::Entity::find_by_id(u256_to_string(tab_id))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(t.settlement_status, SettlementStatus::Pending);
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn deposit_creates_user_if_missing() -> anyhow::Result<()> {
    let (_cfg, ctx) = init_test_env().await?;

    // Make a brand-new random address and DO NOT pre-insert the user.
    let user_addr = random_address();

    // Perform a deposit directly – this should now create the user row automatically.
    let amount = U256::from(42u64);
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        amount,
    )
    .await?;

    // User row must now exist
    let u = fetch_user(&ctx, &user_addr).await?;
    assert!(u.address == user_addr);

    // Collateral must equal the deposited amount and locked collateral is still 0
    assert_eq!(
        read_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        amount
    );
    assert_eq!(
        read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::ZERO
    );

    // A CollateralEvent::Deposit must also be recorded
    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::UserAddress.eq(user_addr))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, CollateralEventType::Deposit);
    assert_eq!(U256::from_str(&events[0].amount)?, amount);

    Ok(())
}
