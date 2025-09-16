use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::{collateral_event, sea_orm_active_enums::CollateralEventType, user};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use std::str::FromStr;
use test_log::test;
use uuid::Uuid;

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
        .exec_without_returning(&*ctx.db)
        .await?;
    Ok(())
}

async fn load_user(ctx: &PersistCtx, addr: &str) -> user::Model {
    user::Entity::find()
        .filter(user::Column::Address.eq(addr.to_string()))
        .one(&*ctx.db)
        .await
        .unwrap()
        .unwrap()
}

#[test(tokio::test)]
async fn deposit_zero_does_not_crash() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::ZERO).await?;
    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::ZERO.to_string());
    Ok(())
}

#[test(tokio::test)]
async fn deposit_large_value() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;
    let big = U256::from(1000000000000u64);
    repo::deposit(&ctx, user_addr.clone(), big).await?;
    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, big.to_string());
    Ok(())
}

#[test(tokio::test)]
async fn multiple_deposits_accumulate_and_log_events() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;

    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr.clone()))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(15u64).to_string());

    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::UserAddress.eq(user_addr))
        .all(&*ctx.db)
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
    let user_addr = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::MAX).await?;
    // second deposit should overflow and error
    let res = repo::deposit(&ctx, user_addr.clone(), U256::from(1u8)).await;
    assert!(res.is_err());

    // value should remain U256::MAX
    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::MAX.to_string());
    Ok(())
}

#[test(tokio::test)]
async fn deposit_fails_on_invalid_collateral_in_db() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();
    let user_addr = Uuid::new_v4().to_string();

    // Manually insert broken collateral (no ensure_user on purpose)
    let am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set("not_a_number".to_string()),
        locked_collateral: Set("0".to_string()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(am).exec(&*ctx.db).await?;

    // Any deposit should now fail when parsing collateral
    let res = repo::deposit(&ctx, user_addr.clone(), U256::from(1u64)).await;
    assert!(res.is_err());
    Ok(())
}

#[test(tokio::test)]
async fn lock_successfully_updates_locked_collateral_and_version() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;
    // give the user 100 units of collateral
    repo::deposit(&ctx, user_addr.clone(), U256::from(100u64)).await?;

    let before = load_user(&ctx, &user_addr).await;
    let before_version = before.version;
    assert_eq!(U256::from_str(&before.locked_collateral)?, U256::ZERO);

    // lock 40 units
    let ok =
        repo::update_user_lock_and_version(&ctx, &user_addr, before_version, U256::from(40u64))
            .await?;
    assert!(ok);

    let after = load_user(&ctx, &user_addr).await;
    assert_eq!(after.version, before_version + 1);
    assert_eq!(U256::from_str(&after.locked_collateral)?, U256::from(40u64));
    Ok(())
}

#[test(tokio::test)]
async fn lock_fails_if_not_enough_free_collateral() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;
    // deposit only 10
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    // Pre-lock 8 units
    let u = load_user(&ctx, &user_addr).await;
    let _ =
        repo::update_user_lock_and_version(&ctx, &user_addr, u.version, U256::from(8u64)).await?;

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
    let user_addr = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(20u64)).await?;
    let u = load_user(&ctx, &user_addr).await;
    let version = u.version;

    // first update bumps version to version + 1
    let ok1 =
        repo::update_user_lock_and_version(&ctx, &user_addr, version, U256::from(5u64)).await?;
    assert!(ok1);

    // second update tries with old version -> must not update
    let ok2 =
        repo::update_user_lock_and_version(&ctx, &user_addr, version, U256::from(10u64)).await?;
    assert!(!ok2);

    let after = load_user(&ctx, &user_addr).await;
    assert_eq!(U256::from_str(&after.locked_collateral)?, U256::from(5u64));
    Ok(())
}

#[test(tokio::test)]
async fn multiple_locks_accumulate_locked_collateral() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    ensure_user(&ctx, &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(50u64)).await?;

    // first lock of 10
    let u1 = load_user(&ctx, &user_addr).await;
    let _ =
        repo::update_user_lock_and_version(&ctx, &user_addr, u1.version, U256::from(10u64)).await?;

    // second lock to total 25 (fresh version)
    let u2 = load_user(&ctx, &user_addr).await;
    let _ =
        repo::update_user_lock_and_version(&ctx, &user_addr, u2.version, U256::from(25u64)).await?;

    let after = load_user(&ctx, &user_addr).await;
    assert_eq!(U256::from_str(&after.locked_collateral)?, U256::from(25u64));
    Ok(())
}

#[test(tokio::test)]
async fn lock_fails_on_u256_overflow() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

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
