use alloy::primitives::U256;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::error::PersistDbError;
use core_service::persist::PersistCtx;
use core_service::persist::repo;
use crypto::bls::BLSCert;
use entities::{guarantee, user};
use rpc::common::PaymentGuaranteeClaims;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use test_log::test;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    Ok(AppConfig::fetch())
}

// helper to build a random valid 0x… address
fn random_eth_address() -> String {
    format!("0x{:040x}", rand::random::<u128>())
}

// --- helper to insert a test tab using new repo::create_tab ---
async fn insert_test_tab(
    ctx: &PersistCtx,
    id: U256,
    user_address: String,
    recipient_address: String,
) -> anyhow::Result<()> {
    // give a small default ttl (e.g. 300s) for tests
    repo::create_tab(
        ctx,
        id,
        &user_address,
        &recipient_address,
        Utc::now().naive_utc(),
        300,
    )
    .await?;
    Ok(())
}

#[test(tokio::test)]
async fn store_guarantee_autocreates_users() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    // Tab & primary user
    let user_addr = random_eth_address();
    let recipient_addr = random_eth_address();
    let tab_id = U256::from(rand::random::<u128>());
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
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    // Unknown addresses that should be auto-created
    let from_addr = random_eth_address();
    let to_addr = random_eth_address();

    repo::store_guarantee_on(
        ctx.db.as_ref(),
        tab_id,
        U256::from(42u64),
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

    let tab_id = U256::from(rand::random::<u128>());
    let req_id = U256::from(1u64);
    let from_addr = random_eth_address();
    let to_addr = random_eth_address();

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

    // manual insert to control TTL etc.
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.to_string()),
        user_address: Set(from_addr.clone()),
        server_address: Set(from_addr.clone()),
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

    // ── First insert of the guarantee ──
    repo::store_guarantee_on(
        ctx.db.as_ref(),
        tab_id,
        req_id,
        from_addr.clone(),
        to_addr.clone(),
        U256::from(100u64),
        now,
        "cert".into(),
    )
    .await?;

    // ── Second insert with same (tab_id, req_id) must be a no-op ──
    repo::store_guarantee_on(
        ctx.db.as_ref(),
        tab_id,
        req_id,
        from_addr,
        to_addr,
        U256::from(200u64),
        now,
        "cert2".into(),
    )
    .await?;

    // ── Verify only the first value persisted ──
    let g = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(tab_id.to_string()))
        .filter(guarantee::Column::ReqId.eq(req_id.to_string()))
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
    let cert = repo::get_guarantee(&ctx, U256::from(0u64), U256::from(0u64)).await?;
    assert!(cert.is_none());
    Ok(())
}

#[test(tokio::test)]
async fn get_last_guarantee_for_tab_returns_most_recent() -> anyhow::Result<()> {
    use tokio::time::{Duration, sleep};

    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    // base user + tab
    let user_addr = random_eth_address();
    let recipient_addr = random_eth_address();
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
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    // two guarantees with increasing req_id and later created_at
    repo::store_guarantee_on(
        ctx.db.as_ref(),
        tab_id,
        U256::from(1u64),
        user_addr.clone(),
        random_eth_address(),
        U256::from(10u64),
        now,
        "cert1".into(),
    )
    .await?;
    // ensure created_at differs
    sleep(Duration::from_millis(10)).await;
    repo::store_guarantee_on(
        ctx.db.as_ref(),
        tab_id,
        U256::from(2u64),
        user_addr,
        random_eth_address(),
        U256::from(20u64),
        now,
        "cert2".into(),
    )
    .await?;

    let last = repo::get_last_guarantee_for_tab(&ctx, tab_id).await?;
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
    let user_addr = random_eth_address();

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

    // direct insert to control ttl value
    let tab_am = entities::tabs::ActiveModel {
        id: Set(tab_id.to_string()),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ttl: Set(123),
        ..Default::default()
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(ctx.db.as_ref())
        .await?;

    // happy path
    let ttl = repo::get_tab_ttl_seconds(&ctx, tab_id).await?;
    assert_eq!(ttl, 123);

    // missing tab → Err
    let missing = repo::get_tab_ttl_seconds(&ctx, U256::from(999u64)).await;
    assert!(missing.is_err());

    Ok(())
}

#[test(tokio::test)]
async fn get_last_guarantee_for_tab_orders_by_req_id() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    // Create a user and a tab
    let user_addr = random_eth_address();
    let recipient_addr = random_eth_address();
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
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    // Insert two guarantees with different req_ids
    repo::store_guarantee_on(
        ctx.db.as_ref(),
        tab_id,
        U256::from(1u64),
        user_addr.clone(),
        random_eth_address(),
        U256::from(10u64),
        now,
        "cert-A".into(),
    )
    .await?;
    repo::store_guarantee_on(
        ctx.db.as_ref(),
        tab_id,
        U256::from(2u64),
        user_addr,
        random_eth_address(),
        U256::from(20u64),
        now,
        "cert-B".into(),
    )
    .await?;

    // The function should return the row with req_id = "B"
    let last = repo::get_last_guarantee_for_tab(&ctx, tab_id).await?;
    assert!(last.is_some());
    let last = last.unwrap();
    assert_eq!(last.req_id, "2");
    assert_eq!(last.value, U256::from(20u64).to_string());

    Ok(())
}

#[test(tokio::test)]
async fn lock_and_store_guarantee_locks_and_inserts_atomically() -> anyhow::Result<()> {
    let config = init()?;
    let ctx = PersistCtx::new().await?;

    // create a user with some collateral
    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    repo::ensure_user_exists_on(ctx.db.as_ref(), &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(100u64)).await?;

    // recipient + tab
    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    let tab_id = U256::from(rand::random::<u128>());
    repo::create_tab(
        &ctx,
        tab_id,
        &user_addr,
        &recipient_addr,
        Utc::now().naive_utc(),
        300,
    )
    .await?;

    // build a minimal PaymentGuaranteeClaims and dummy cert
    let promise = PaymentGuaranteeClaims {
        tab_id: tab_id,
        req_id: U256::from(0u64),
        user_address: user_addr.clone(),
        recipient_address: recipient_addr.clone(),
        amount: U256::from(40u64),
        timestamp: Utc::now().timestamp() as u64,
    };
    let cert = BLSCert::new(&config.secrets.bls_private_key, promise.clone())?;

    // --- call the new atomic repo method ---
    repo::lock_and_store_guarantee(&ctx, &promise, &cert).await?;

    // check locked collateral updated
    let u = user::Entity::find_by_id(&user_addr)
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(u.locked_collateral.parse::<U256>()?, U256::from(40u64));

    // check guarantee row inserted
    let g = entities::guarantee::Entity::find()
        .filter(entities::guarantee::Column::TabId.eq(tab_id.to_string()))
        .filter(entities::guarantee::Column::ReqId.eq(U256::from(0u64).to_string()))
        .one(ctx.db.as_ref())
        .await?;
    assert!(g.is_some());

    Ok(())
}

#[test(tokio::test)]
async fn lock_and_store_guarantee_invalid_timestamp_errors() -> anyhow::Result<()> {
    let config = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    repo::ensure_user_exists_on(ctx.db.as_ref(), &user_addr).await?;
    repo::deposit(&ctx, user_addr.clone(), U256::from(50u64)).await?;

    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    let tab_id = U256::from(rand::random::<u128>());
    repo::create_tab(
        &ctx,
        tab_id,
        &user_addr,
        &recipient_addr,
        Utc::now().naive_utc(),
        300,
    )
    .await?;

    let promise = PaymentGuaranteeClaims {
        tab_id: tab_id,
        req_id: U256::from(1u64),
        user_address: user_addr.clone(),
        recipient_address: recipient_addr.clone(),
        amount: U256::from(10u64),
        // deliberately invalid: chrono cannot represent this
        timestamp: i64::MAX as u64,
    };
    let cert = BLSCert::new(&config.secrets.bls_private_key, promise.clone())?;

    let res = repo::lock_and_store_guarantee(&ctx, &promise, &cert).await;
    assert!(matches!(res, Err(PersistDbError::InvalidTimestamp(_))));

    // locked collateral unchanged
    let u = user::Entity::find_by_id(&user_addr)
        .one(ctx.db.as_ref())
        .await?
        .unwrap();
    assert_eq!(u.locked_collateral.parse::<U256>()?, U256::ZERO);

    // no guarantee row inserted
    let g = entities::guarantee::Entity::find()
        .filter(entities::guarantee::Column::TabId.eq(tab_id.to_string()))
        .filter(entities::guarantee::Column::ReqId.eq("bad-ts"))
        .one(ctx.db.as_ref())
        .await?;
    assert!(g.is_none());
    Ok(())
}
