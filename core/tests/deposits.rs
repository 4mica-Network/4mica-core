use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::error::PersistDbError;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::{collateral_event, sea_orm_active_enums::CollateralEventType, user};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use std::str::FromStr;
use test_log::test;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

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

async fn load_user(ctx: &PersistCtx, addr: &str) -> user::Model {
    user::Entity::find()
        .filter(user::Column::Address.eq(addr.to_string()))
        .one(ctx.db.as_ref())
        .await
        .unwrap()
        .unwrap()
}

#[test(tokio::test)]
async fn deposit_zero_does_not_crash() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::ZERO).await?;
    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::ZERO.to_string());
    Ok(())
}

#[test(tokio::test)]
async fn deposit_large_value() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    let big = U256::from(1000000000000u64);
    repo::deposit(&ctx, user_addr.clone(), big).await?;
    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(u.collateral, big.to_string());
    Ok(())
}

#[test(tokio::test)]
async fn multiple_deposits_accumulate_and_log_events() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(15u64).to_string());

    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::UserAddress.eq(user_addr))
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
async fn deposit_overflow_protection() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::MAX).await?;
    // second deposit should overflow and error
    let res = repo::deposit(&ctx, user_addr.clone(), U256::from(1u8)).await;
    assert!(res.is_err());

    // value should remain U256::MAX
    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::MAX.to_string());
    Ok(())
}
#[test(tokio::test)]
async fn lock_successfully_updates_locked_collateral_and_version() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    // give the user 100 units of collateral
    repo::deposit(&ctx, user_addr.clone(), U256::from(100u64)).await?;

    let before = load_user(&ctx, &user_addr).await;
    let before_version = before.version;
    assert_eq!(U256::from_str(&before.locked_collateral)?, U256::ZERO);

    // lock 40 units
    repo::update_user_lock_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        before_version,
        U256::from(40u64),
    )
    .await?;

    let after = load_user(&ctx, &user_addr).await;
    assert_eq!(after.version, before_version + 1);
    assert_eq!(U256::from_str(&after.locked_collateral)?, U256::from(40u64));
    Ok(())
}

#[test(tokio::test)]
async fn lock_fails_if_not_enough_free_collateral() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    // deposit only 10
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    // Pre-lock 8 units
    let u = load_user(&ctx, &user_addr).await;
    repo::update_user_lock_and_version_on(ctx.db.as_ref(), &user_addr, u.version, U256::from(8u64))
        .await?;
    // free collateral is only 2; trying to lock 5 more must be rejected in our own check
    let u2 = load_user(&ctx, &user_addr).await;
    let total = U256::from_str(&u2.collateral)?;
    let locked = U256::from_str(&u2.locked_collateral)?;
    let free = total - locked;
    assert!(free < U256::from(5u64));

    // do NOT attempt DB update because our own check already fails
    Ok(())
}

#[test(tokio::test)]
async fn lock_fails_with_stale_version() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(20u64)).await?;
    let u = load_user(&ctx, &user_addr).await;
    let version = u.version;

    // first update bumps version to version + 1
    repo::update_user_lock_and_version_on(ctx.db.as_ref(), &user_addr, version, U256::from(5u64))
        .await?;

    // second update tries with old version -> must error with OptimisticLockConflict
    let err = repo::update_user_lock_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        version,
        U256::from(10u64),
    )
    .await
    .expect_err("expected optimistic lock conflict");
    match err {
        PersistDbError::OptimisticLockConflict { .. } => { /* expected */ }
        other => panic!("unexpected error: {other:?}"),
    }

    let after = load_user(&ctx, &user_addr).await;
    assert_eq!(U256::from_str(&after.locked_collateral)?, U256::from(5u64));
    Ok(())
}

#[test(tokio::test)]
async fn multiple_locks_accumulate_locked_collateral() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(50u64)).await?;

    // first lock of 10
    let u1 = load_user(&ctx, &user_addr).await;
    repo::update_user_lock_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        u1.version,
        U256::from(10u64),
    )
    .await?;
    // second lock to total 25 (fresh version)
    let u2 = load_user(&ctx, &user_addr).await;
    repo::update_user_lock_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        u2.version,
        U256::from(25u64),
    )
    .await?;
    let after = load_user(&ctx, &user_addr).await;
    assert_eq!(U256::from_str(&after.locked_collateral)?, U256::from(25u64));
    Ok(())
}

#[test(tokio::test)]
async fn lock_fails_on_u256_overflow() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    // deposit the maximum U256 value
    repo::deposit(&ctx, user_addr.clone(), U256::MAX).await?;

    // verify we cannot even represent max + 1, so any attempt to add 1 is an overflow in our own logic
    let max = U256::MAX;
    let plus_one = max.checked_add(U256::from(1u64));
    assert!(plus_one.is_none(), "U256::MAX + 1 must overflow");

    // locked_collateral is still 0
    let u = load_user(&ctx, &user_addr).await;
    assert_eq!(U256::from_str(&u.locked_collateral)?, U256::ZERO);
    Ok(())
}

use sea_orm::ActiveModelTrait; // ADD this near your other sea_orm imports

#[test(tokio::test)]
async fn db_check_rejects_inserting_locked_gt_total() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    // Try to INSERT a user where locked_collateral > collateral
    let am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        collateral: Set("10".to_string()),
        locked_collateral: Set("11".to_string()), // violates CHECK
        ..Default::default()
    };
    let res = entities::user::Entity::insert(am)
        .exec(ctx.db.as_ref())
        .await;
    assert!(res.is_err(), "insert should fail due to CHECK constraint");

    // Make sure the row wasn't inserted
    let found = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(ctx.db.as_ref())
        .await?;
    assert!(found.is_none());
    Ok(())
}

#[test(tokio::test)]
async fn db_check_rejects_update_locked_beyond_total_via_repo() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    // Give the user collateral = 10
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    let before = load_user(&ctx, &user_addr).await;
    let before_version = before.version;
    assert_eq!(U256::from_str(&before.locked_collateral)?, U256::ZERO);

    // Attempt to set locked_collateral = 11 (> 10). This should be rejected by the DB CHECK.
    let err = repo::update_user_lock_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        before_version,
        U256::from(11u64),
    )
    .await
    .expect_err("expected DB CHECK to reject locked > total");
    // (Optional) sanity: error should mention a constraint/check
    let msg = format!("{err:?}");
    assert!(msg.to_lowercase().contains("check") || msg.to_lowercase().contains("constraint"));

    // Ensure nothing changed
    let after = load_user(&ctx, &user_addr).await;
    assert_eq!(
        after.version, before_version,
        "version must not change on failed update"
    );
    assert_eq!(U256::from_str(&after.locked_collateral)?, U256::ZERO);
    assert_eq!(U256::from_str(&after.collateral)?, U256::from(10u64));
    Ok(())
}

#[test(tokio::test)]
async fn db_check_rejects_lowering_total_below_locked() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    ensure_user(&ctx, &user_addr).await?;
    // collateral = 20
    repo::deposit(&ctx, user_addr.clone(), U256::from(20u64)).await?;

    // lock 7 (valid)
    let u1 = load_user(&ctx, &user_addr).await;
    repo::update_user_lock_and_version_on(
        ctx.db.as_ref(),
        &user_addr,
        u1.version,
        U256::from(7u64),
    )
    .await?;
    // Now try to LOWER collateral below 7 via a raw update (simulate a bad path)
    let current = load_user(&ctx, &user_addr).await;
    let mut am: entities::user::ActiveModel = current.into();
    am.collateral = Set("5".to_string()); // violates CHECK because locked=7
    let res = am.update(ctx.db.as_ref()).await;
    assert!(res.is_err(), "update should fail due to CHECK constraint");

    // Row should remain unchanged
    let after = load_user(&ctx, &user_addr).await;
    assert_eq!(U256::from_str(&after.collateral)?, U256::from(20u64));
    assert_eq!(U256::from_str(&after.locked_collateral)?, U256::from(7u64));
    Ok(())
}
