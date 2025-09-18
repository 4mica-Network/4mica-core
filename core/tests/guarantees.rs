use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use entities::{guarantee, user};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use test_log::test;
use uuid::Uuid;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

// --- helper to insert a test tab with required fields (NOT NULL ttl) ---
async fn insert_test_tab(
    ctx: &PersistCtx,
    id: String,
    user_address: String,
    now: chrono::NaiveDateTime,
) -> anyhow::Result<()> {
    let tab_am = entities::tabs::ActiveModel {
        id: Set(id),
        user_address: Set(user_address.clone()),
        server_address: Set(user_address),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ttl: Set(300), // <-- if Option<i32>: Set(Some(300))
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(ctx.db.as_ref())
        .await?;
    Ok(())
}

#[test(tokio::test)]
async fn store_guarantee_autocreates_users() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    // Tab & primary user
    let user_addr = Uuid::new_v4().to_string();
    let tab_id = Uuid::new_v4().to_string();
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
    insert_test_tab(&ctx, tab_id.clone(), user_addr.clone(), now).await?;

    // Unknown addresses that should be auto-created
    let from_addr = Uuid::new_v4().to_string();
    let to_addr = Uuid::new_v4().to_string();

    repo::store_guarantee(
        &ctx,
        tab_id.clone(),
        Uuid::new_v4().to_string(),
        from_addr.clone(),
        to_addr.clone(),
        U256::from(42u64),
        now,
        "cert".into(),
    )
    .await?;

    // from & to must exist now
    let from = user::Entity::find()
        .filter(user::Column::Address.eq(from_addr))
        .one(ctx.db.as_ref())
        .await?;
    let to = user::Entity::find()
        .filter(user::Column::Address.eq(to_addr))
        .one(ctx.db.as_ref())
        .await?;
    assert!(from.is_some() && to.is_some());
    Ok(())
}

#[test(tokio::test)]
async fn duplicate_guarantee_insert_is_noop() -> anyhow::Result<()> {
    use entities::sea_orm_active_enums::{SettlementStatus, TabStatus};

    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    let tab_id = Uuid::new_v4().to_string();
    let req_id = Uuid::new_v4().to_string();
    let from_addr = Uuid::new_v4().to_string();
    let to_addr = Uuid::new_v4().to_string();

    let from_user = entities::user::ActiveModel {
        address: Set(from_addr.clone()),
        collateral: Set("0".into()),
        locked_collateral: Set("0".into()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(from_user)
        .exec(ctx.db.as_ref())
        .await?;

    // (kept explicit here in case you want to vary fields)
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(from_addr.clone()),
        server_address: Set(from_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        ttl: Set(300), // <-- if Option<i32>: Set(Some(300))
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(ctx.db.as_ref())
        .await?;

    // ── First insert of the guarantee ──
    repo::store_guarantee(
        &ctx,
        tab_id.clone(),
        req_id.clone(),
        from_addr.clone(),
        to_addr.clone(),
        U256::from(100u64),
        now,
        "cert".into(),
    )
    .await?;

    // ── Second insert with same (tab_id, req_id) must be a no-op ──
    repo::store_guarantee(
        &ctx,
        tab_id.clone(),
        req_id.clone(),
        from_addr,
        to_addr,
        U256::from(200u64),
        now,
        "cert2".into(),
    )
    .await?;

    // ── Verify only the first value persisted ──
    let g = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(tab_id))
        .filter(guarantee::Column::ReqId.eq(req_id))
        .one(ctx.db.as_ref())
        .await?
        .unwrap();

    assert_eq!(g.value, U256::from(100u64).to_string());
    Ok(())
}

#[test(tokio::test)]
async fn get_missing_guarantee_returns_none() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let cert = repo::get_guarantee(&ctx, "nope".into(), "nope".into()).await?;
    assert!(cert.is_none());
    Ok(())
}

// ────────────────────── NEW TESTS for new repo helpers ──────────────────────

#[test(tokio::test)]
async fn get_last_guarantee_for_tab_returns_most_recent() -> anyhow::Result<()> {
    use tokio::time::{Duration, sleep};

    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    // base user + tab
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
    entities::user::Entity::insert(u_am)
        .exec(ctx.db.as_ref())
        .await?;
    let tab_id = Uuid::new_v4().to_string();
    insert_test_tab(&ctx, tab_id.clone(), user_addr.clone(), now).await?;

    // two guarantees with increasing req_id and later created_at
    repo::store_guarantee(
        &ctx,
        tab_id.clone(),
        "1".into(),
        user_addr.clone(),
        Uuid::new_v4().to_string(),
        U256::from(10u64),
        now,
        "cert1".into(),
    )
    .await?;
    // ensure created_at differs
    sleep(Duration::from_millis(10)).await;
    repo::store_guarantee(
        &ctx,
        tab_id.clone(),
        "2".into(),
        user_addr,
        Uuid::new_v4().to_string(),
        U256::from(20u64),
        now,
        "cert2".into(),
    )
    .await?;

    let last = repo::get_last_guarantee_for_tab(&ctx, &tab_id).await?;
    assert!(last.is_some());
    let last = last.unwrap();
    assert_eq!(last.req_id, "2");
    assert_eq!(last.value, U256::from(20u64).to_string());
    Ok(())
}

#[test(tokio::test)]
async fn get_tab_ttl_seconds_ok_and_missing_errors() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    // insert a tab with ttl = 123
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
    entities::user::Entity::insert(u_am)
        .exec(ctx.db.as_ref())
        .await?;
    let tab_id = Uuid::new_v4().to_string();

    // direct insert to control ttl value
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ttl: Set(123), // <-- if Option<i32>: Set(Some(123))
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(ctx.db.as_ref())
        .await?;

    // happy path
    let ttl = repo::get_tab_ttl_seconds(&ctx, &tab_id).await?;
    assert_eq!(ttl, 123);

    // missing tab → Err
    let missing = repo::get_tab_ttl_seconds(&ctx, "does-not-exist").await;
    assert!(missing.is_err());

    Ok(())
}
