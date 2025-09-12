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
        revenue: Set("0".into()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(u_am).exec(&*ctx.db).await?;
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(&*ctx.db)
        .await?;

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
        .one(&*ctx.db)
        .await?;
    let to = user::Entity::find()
        .filter(user::Column::Address.eq(to_addr))
        .one(&*ctx.db)
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
        revenue: Set("0".into()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    entities::user::Entity::insert(from_user)
        .exec(&*ctx.db)
        .await?;
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.clone()),
        user_address: Set(from_addr.clone()),
        server_address: Set(from_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(&*ctx.db)
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
        .one(&*ctx.db)
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
