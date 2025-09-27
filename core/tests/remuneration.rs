use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use core_service::util::u256_to_string;
use entities::{
    collateral_event,
    sea_orm_active_enums::{CollateralEventType, SettlementStatus, TabStatus},
    tabs, user,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use std::str::FromStr;
use test_log::test;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

#[test(tokio::test)]
async fn remuneration_and_payment_recorded_as_events() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set(U256::ZERO.to_string()),
        locked_collateral: Set(U256::ZERO.to_string()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(u_am)
        .exec(ctx.db.as_ref())
        .await?;

    let tab_id = U256::from(rand::random::<u128>());
    let tab_am = entities::tabs::ActiveModel {
        id: Set(u256_to_string(tab_id)),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        ttl: Set(300),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(ctx.db.as_ref())
        .await?;

    // Fund user so remuneration of 10 passes strict checks
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    repo::remunerate_recipient(&ctx, tab_id, U256::from(10u64)).await?;

    // Event recorded once
    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(u256_to_string(tab_id)))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(events.len(), 1);
    assert!(
        events
            .iter()
            .any(|e| e.amount == U256::from(10u64).to_string())
    );

    // Status flipped to Settled
    let tab = tabs::Entity::find_by_id(u256_to_string(tab_id))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(tab.settlement_status, SettlementStatus::Settled);

    // Collateral debited
    let u = user::Entity::find_by_id(user_addr.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(U256::from_str(&u.collateral).unwrap(), U256::ZERO);

    Ok(())
}

#[test(tokio::test)]
async fn remunerate_without_tab_errors() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;

    let res = repo::remunerate_recipient(&ctx, U256::from(999u64), U256::from(5u64)).await;
    assert!(res.is_err());
    Ok(())
}

#[test(tokio::test)]
async fn zero_amount_remuneration_is_recorded_once() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set("0".into()),
        locked_collateral: Set("0".into()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(u_am)
        .exec(ctx.db.as_ref())
        .await?;

    let tab_id = U256::from(rand::random::<u128>());
    let tab_am = entities::tabs::ActiveModel {
        id: Set(u256_to_string(tab_id)),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        ttl: Set(300),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(ctx.db.as_ref())
        .await?;

    // 0 amount requires only that user exists (already inserted)
    repo::remunerate_recipient(&ctx, tab_id, U256::ZERO).await?;
    // Duplicate remuneration is a no-op due to status CAS
    repo::remunerate_recipient(&ctx, tab_id, U256::ZERO).await?;

    // Event recorded exactly once with amount 0
    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(u256_to_string(tab_id)))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, CollateralEventType::Remunerate);
    assert_eq!(events[0].amount, U256::ZERO.to_string());

    // Status is Settled; collateral unchanged (still 0)
    let tab = tabs::Entity::find_by_id(u256_to_string(tab_id))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(tab.settlement_status, SettlementStatus::Settled);
    let u = user::Entity::find_by_id(user_addr.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(U256::from_str(&u.collateral).unwrap(), U256::ZERO);

    Ok(())
}

#[test(tokio::test)]
async fn duplicate_remuneration_is_noop() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set("0".into()),
        locked_collateral: Set("0".into()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(u_am)
        .exec(ctx.db.as_ref())
        .await?;

    let tab_id = U256::from(rand::random::<u128>());
    let tab_am = entities::tabs::ActiveModel {
        id: Set(u256_to_string(tab_id)),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        ttl: Set(300),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(ctx.db.as_ref())
        .await?;

    // Fund for the first remuneration to succeed
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    repo::remunerate_recipient(&ctx, tab_id, U256::from(10u64)).await?;
    // Second call is a no-op (idempotent), even if amount differs
    repo::remunerate_recipient(&ctx, tab_id, U256::from(20u64)).await?;

    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(u256_to_string(tab_id)))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].amount, U256::from(10u64).to_string());

    // Status is Settled and collateral was debited once (to 0)
    let tab = tabs::Entity::find_by_id(u256_to_string(tab_id))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(tab.settlement_status, SettlementStatus::Settled);
    let u = user::Entity::find_by_id(user_addr.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(U256::from_str(&u.collateral).unwrap(), U256::ZERO);

    Ok(())
}

/// If remuneration amount exceeds collateral, the whole txn must roll back:
/// - no event
/// - status remains Pending
/// - collateral unchanged
#[test(tokio::test)]
async fn insufficient_collateral_rolls_back_and_keeps_status_pending() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set("0".into()),
        locked_collateral: Set("0".into()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(u_am)
        .exec(ctx.db.as_ref())
        .await?;

    let tab_id = U256::from(rand::random::<u128>());
    let tab_am = entities::tabs::ActiveModel {
        id: Set(u256_to_string(tab_id)),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        ttl: Set(300),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(ctx.db.as_ref())
        .await?;

    // Give the user only 5, then try to remunerate 10
    repo::deposit(&ctx, user_addr.clone(), U256::from(5u64)).await?;
    let res = repo::remunerate_recipient(&ctx, tab_id, U256::from(10u64)).await;
    assert!(res.is_err());

    // No event
    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(u256_to_string(tab_id)))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(events.len(), 0);

    // Status still Pending and collateral still 5
    let tab = tabs::Entity::find_by_id(u256_to_string(tab_id))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(tab.settlement_status, SettlementStatus::Pending);
    let u = user::Entity::find_by_id(user_addr.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(U256::from_str(&u.collateral).unwrap(), U256::from(5u64));

    Ok(())
}

/// Two concurrent remunerations should settle exactly once.
#[test(tokio::test)]
async fn concurrent_remunerations_settle_once() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    let user_addr = format!("0x{:040x}", rand::random::<u128>());

    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set("0".into()),
        locked_collateral: Set("0".into()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(u_am)
        .exec(ctx.db.as_ref())
        .await?;

    let tab_id = U256::from(rand::random::<u128>());
    let tab_am = entities::tabs::ActiveModel {
        id: Set(u256_to_string(tab_id)),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        ttl: Set(300),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(ctx.db.as_ref())
        .await?;

    // Fund enough for a single remuneration
    repo::deposit(&ctx, user_addr.clone(), U256::from(10u64)).await?;

    // Race two calls
    let (r1, r2) = tokio::join!(
        repo::remunerate_recipient(&ctx, tab_id, U256::from(10u64)),
        repo::remunerate_recipient(&ctx, tab_id, U256::from(10u64))
    );
    // One should succeed, the other should be Ok(()) as a no-op (depending on impl),
    // but neither should error.
    assert!(r1.is_ok());
    assert!(r2.is_ok());

    // Exactly one event
    let events = collateral_event::Entity::find()
        .filter(collateral_event::Column::TabId.eq(u256_to_string(tab_id)))
        .all(ctx.db.as_ref())
        .await?;
    assert_eq!(events.len(), 1);

    // Status is Settled and collateral debited once
    let tab = tabs::Entity::find_by_id(u256_to_string(tab_id))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(tab.settlement_status, SettlementStatus::Settled);
    let u = user::Entity::find_by_id(user_addr.clone())
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(U256::from_str(&u.collateral).unwrap(), U256::ZERO);

    Ok(())
}
