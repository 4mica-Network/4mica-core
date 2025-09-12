use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::{collateral_event, sea_orm_active_enums::CollateralEventType, user};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use test_log::test;
use uuid::Uuid;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

#[test(tokio::test)]
async fn deposit_zero_does_not_crash() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

    repo::deposit(&ctx, user_addr.clone(), U256::from(0u64)).await?;
    let u = user::Entity::find()
        .filter(user::Column::Address.eq(user_addr))
        .one(&*ctx.db)
        .await?
        .unwrap();
    assert_eq!(u.collateral, U256::from(0u64).to_string());
    Ok(())
}

#[test(tokio::test)]
async fn deposit_large_value() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = Uuid::new_v4().to_string();

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

    // Manually insert broken collateral
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
