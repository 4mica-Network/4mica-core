use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::{collateral_event, sea_orm_active_enums::CollateralEventType};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use test_log::test;
use uuid::Uuid;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

#[test(tokio::test)]
async fn remuneration_and_payment_recorded_as_events() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    let user_addr = Uuid::new_v4().to_string();
    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set(U256::ZERO.to_string()),
        locked_collateral: Set(U256::ZERO.to_string()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(u_am).exec(&*ctx.db).await?;

    let tab_id = Uuid::new_v4().to_string();
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ttl: Set(300), // <-- added
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(&*ctx.db)
        .await?;

    // Fund user so remuneration of 10 passes strict checks
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    repo::remunerate_recipient(&ctx, tab_id.clone(), U256::from(10u64)).await?;

    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(tab_id))
        .all(&*ctx.db)
        .await?;

    assert_eq!(events.len(), 1);
    assert!(
        events
            .iter()
            .any(|e| e.amount == U256::from(10u64).to_string())
    );
    Ok(())
}

#[test(tokio::test)]
async fn remunerate_without_tab_errors() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;

    let res = repo::remunerate_recipient(&ctx, "missing_tab".into(), U256::from(5u64)).await;
    assert!(res.is_err());
    Ok(())
}

#[test(tokio::test)]
async fn zero_amount_remuneration_is_recorded_once() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    let user_addr = Uuid::new_v4().to_string();
    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set("0".into()),
        locked_collateral: Set("0".into()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(u_am).exec(&*ctx.db).await?;

    let tab_id = Uuid::new_v4().to_string();
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ttl: Set(300), // <-- added
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(&*ctx.db)
        .await?;

    // 0 amount requires only that user exists (already inserted)
    repo::remunerate_recipient(&ctx, tab_id.clone(), U256::ZERO).await?;
    // Duplicate remuneration is a no-op due to idempotency
    repo::remunerate_recipient(&ctx, tab_id.clone(), U256::ZERO).await?;

    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(tab_id))
        .all(&*ctx.db)
        .await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, CollateralEventType::Remunerate);
    assert_eq!(events[0].amount, U256::ZERO.to_string());
    Ok(())
}

#[test(tokio::test)]
async fn duplicate_remuneration_is_noop() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    let user_addr = Uuid::new_v4().to_string();
    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set("0".into()),
        locked_collateral: Set("0".into()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(u_am).exec(&*ctx.db).await?;

    let tab_id = Uuid::new_v4().to_string();
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ttl: Set(300), // <-- added
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(&*ctx.db)
        .await?;

    // Fund for the first remuneration to succeed
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    repo::remunerate_recipient(&ctx, tab_id.clone(), U256::from(10u64)).await?;
    // Second call is a no-op (idempotent), even if amount differs
    repo::remunerate_recipient(&ctx, tab_id.clone(), U256::from(20u64)).await?;

    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(tab_id.clone()))
        .all(&*ctx.db)
        .await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].amount, U256::from(10u64).to_string());
    Ok(())
}
