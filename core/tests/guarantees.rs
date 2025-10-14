use alloy::primitives::{Address, U256};
use anyhow::anyhow;
use chrono::Utc;
use core_service::config::AppConfig;
use core_service::error::PersistDbError;
use core_service::persist::*;
use core_service::util::u256_to_string;
use crypto::bls::BLSCert;
use entities::{guarantee, user};
use rpc::common::PaymentGuaranteeClaims;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use std::str::FromStr;
use test_log::test;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    let cfg = AppConfig::fetch();
    let contract = Address::from_str(&cfg.ethereum_config.contract_address)
        .map_err(|e| anyhow!("invalid contract address: {}", e))?;
    crypto::guarantee::init_guarantee_domain_separator(cfg.ethereum_config.chain_id, contract)?;
    Ok(cfg)
}

// helper to build a random valid 0x… address
fn random_eth_address() -> String {
    format!("0x{:040x}", rand::random::<u128>())
}

// helper to build a random U256 id
fn random_u256() -> U256 {
    U256::from_be_bytes(rand::random::<[u8; 32]>())
}

// --- helper to insert a test tab using new repo::create_tab ---
async fn insert_test_tab(
    ctx: &PersistCtx,
    id: U256,
    user_address: String,
    recipient_address: String,
) -> anyhow::Result<()> {
    use sea_orm::ActiveValue::Set;
    let now = Utc::now().naive_utc();
    let new_tab = entities::tabs::ActiveModel {
        id: Set(u256_to_string(id)),
        user_address: Set(user_address.to_owned()),
        server_address: Set(recipient_address.to_owned()),
        start_ts: Set(now),
        ttl: Set(300),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
    };

    entities::tabs::Entity::insert(new_tab)
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
    let user_addr = random_eth_address();
    let recipient_addr = random_eth_address();
    let tab_id = random_u256();
    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        collateral: Set("0".into()),
        locked_collateral: Set("0".into()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
    };
    entities::user::Entity::insert(u_am)
        .exec(ctx.db.as_ref())
        .await?;
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    // Unknown addresses that should be auto-created
    let from_addr = random_eth_address();
    let to_addr = random_eth_address();
    let req_id = random_u256();

    let data = GuaranteeData {
        tab_id,
        req_id,
        from: from_addr.clone(),
        to: to_addr.clone(),
        value: U256::from(42u64),
        start_ts: now,
        cert: "cert".into(),
    };
    repo::store_guarantee_on(ctx.db.as_ref(), data).await?;

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

    let tab_id = random_u256();
    let req_id = random_u256();
    let from_addr = random_eth_address();
    let to_addr = random_eth_address();

    let from_user = entities::user::ActiveModel {
        address: Set(from_addr.clone()),
        collateral: Set("0".into()),
        locked_collateral: Set("0".into()),
        version: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
    };
    entities::user::Entity::insert(from_user)
        .exec(ctx.db.as_ref())
        .await?;

    // manual insert to control TTL etc.
    let tab_am = entities::tabs::ActiveModel {
        id: Set(u256_to_string(tab_id)),
        user_address: Set(from_addr.clone()),
        server_address: Set(from_addr.clone()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        ttl: Set(300),
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(ctx.db.as_ref())
        .await?;

    // ── First insert of the guarantee ──
    let data1 = GuaranteeData {
        tab_id,
        req_id,
        from: from_addr.clone(),
        to: to_addr.clone(),
        value: U256::from(100u64),
        start_ts: now,
        cert: "cert".into(),
    };
    repo::store_guarantee_on(ctx.db.as_ref(), data1).await?;

    // ── Second insert with same (tab_id, req_id) must be a no-op ──
    let data2 = GuaranteeData {
        tab_id,
        req_id,
        from: from_addr,
        to: to_addr,
        value: U256::from(200u64),
        start_ts: now,
        cert: "cert2".into(),
    };
    repo::store_guarantee_on(ctx.db.as_ref(), data2).await?;

    // ── Verify only the first value persisted ──
    let g = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(u256_to_string(tab_id)))
        .filter(guarantee::Column::ReqId.eq(u256_to_string(req_id)))
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
    let cert = repo::get_guarantee(&ctx, random_u256(), random_u256()).await?;
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
    };
    entities::user::Entity::insert(u_am)
        .exec(ctx.db.as_ref())
        .await?;
    let tab_id = random_u256();
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    // two guarantees with increasing req_id and later created_at
    let g1 = GuaranteeData {
        tab_id,
        req_id: U256::from(1u64),
        from: user_addr.clone(),
        to: random_eth_address(),
        value: U256::from(10u64),
        start_ts: now,
        cert: "cert1".into(),
    };
    repo::store_guarantee_on(ctx.db.as_ref(), g1).await?;
    // ensure created_at differs
    sleep(Duration::from_millis(10)).await;
    let g2 = GuaranteeData {
        tab_id,
        req_id: U256::from(2u64),
        from: user_addr,
        to: random_eth_address(),
        value: U256::from(20u64),
        start_ts: now,
        cert: "cert2".into(),
    };
    repo::store_guarantee_on(ctx.db.as_ref(), g2).await?;

    let last = repo::get_last_guarantee_for_tab(&ctx, tab_id).await?;
    assert!(last.is_some());
    let last = last.unwrap();
    assert_eq!(last.req_id, "0x2");
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
    };
    entities::user::Entity::insert(u_am)
        .exec(ctx.db.as_ref())
        .await?;
    let tab_id = random_u256();

    // direct insert to control ttl value
    let tab_am = entities::tabs::ActiveModel {
        id: Set(u256_to_string(tab_id)),
        user_address: Set(user_addr.clone()),
        server_address: Set(user_addr),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        ttl: Set(123),
    };
    entities::tabs::Entity::insert(tab_am)
        .exec(ctx.db.as_ref())
        .await?;

    // happy path
    let ttl = repo::get_tab_ttl_seconds(&ctx, tab_id).await?;
    assert_eq!(ttl, 123);

    // missing tab → Err
    let missing = repo::get_tab_ttl_seconds(&ctx, random_u256()).await;
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
    };
    entities::user::Entity::insert(u_am)
        .exec(ctx.db.as_ref())
        .await?;
    let tab_id = random_u256();
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    // Insert two guarantees with different req_ids
    let g1 = GuaranteeData {
        tab_id,
        req_id: U256::from(0xA),
        from: user_addr.clone(),
        to: random_eth_address(),
        value: U256::from(10u64),
        start_ts: now,
        cert: "cert-A".into(),
    };
    repo::store_guarantee_on(ctx.db.as_ref(), g1).await?;
    let g2 = GuaranteeData {
        tab_id,
        req_id: U256::from(0xB),
        from: user_addr,
        to: random_eth_address(),
        value: U256::from(20u64),
        start_ts: now,
        cert: "cert-B".into(),
    };
    repo::store_guarantee_on(ctx.db.as_ref(), g2).await?;

    // The function should return the row with req_id = 0xB
    let last = repo::get_last_guarantee_for_tab(&ctx, tab_id).await?;
    assert!(last.is_some());
    let last = last.unwrap();
    assert_eq!(last.req_id, "0xb");
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
    let tab_id = random_u256();
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    // build a minimal PaymentGuaranteeClaims and dummy cert
    let promise = PaymentGuaranteeClaims {
        tab_id,
        req_id: U256::from(0u64),
        user_address: user_addr.clone(),
        recipient_address: recipient_addr.clone(),
        amount: U256::from(40u64),
        timestamp: Utc::now().timestamp() as u64,
        asset_address: "0x0000000000000000000000000000000000000000".into(),
    };

    // BLSCert::new requires an exact 32-byte scalar
    let mut sk_be32 = [0u8; 32];
    sk_be32.copy_from_slice(config.secrets.bls_private_key.as_ref());
    let cert = BLSCert::new(&sk_be32, promise.clone())?;

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
        .filter(entities::guarantee::Column::TabId.eq(u256_to_string(tab_id)))
        .filter(entities::guarantee::Column::ReqId.eq(u256_to_string(promise.req_id)))
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
    let tab_id = random_u256();
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    let promise = PaymentGuaranteeClaims {
        tab_id,
        req_id: random_u256(),
        user_address: user_addr.clone(),
        recipient_address: recipient_addr.clone(),
        amount: U256::from(10u64),
        // deliberately invalid: chrono cannot represent this
        timestamp: i64::MAX as u64,
        asset_address: "0x0000000000000000000000000000000000000000".into(),
    };

    // BLSCert::new requires an exact 32-byte scalar
    let mut sk_be32 = [0u8; 32];
    sk_be32.copy_from_slice(config.secrets.bls_private_key.as_ref());
    let cert = BLSCert::new(&sk_be32, promise.clone())?;

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
        .filter(entities::guarantee::Column::TabId.eq(u256_to_string(tab_id)))
        .filter(entities::guarantee::Column::ReqId.eq(u256_to_string(promise.req_id)))
        .one(ctx.db.as_ref())
        .await?;
    assert!(g.is_none());
    Ok(())
}
