use std::{
    panic,
    str::FromStr,
    sync::{Arc, Once},
};

use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use chrono::{Duration, Utc};
use core_service::{
    config::{AppConfig, DEFAULT_ASSET_ADDRESS},
    error::PersistDbError,
    ethereum::CoreContractApi,
    persist::*,
    service::{CoreService, CoreServiceDeps},
    util::u256_to_string,
};
use crypto::bls::BLSCert;
use entities::sea_orm_active_enums::{SettlementStatus, TabStatus};
use entities::{guarantee, user};
use rand::random;
use rpc::{PaymentGuaranteeClaims, PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use test_log::test;

mod common;
use common::fixtures::read_locked_collateral;

fn init() -> anyhow::Result<AppConfig> {
    dotenv::dotenv().ok();
    AppConfig::fetch()
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
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(now),
        ttl: Set(300),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        total_amount: Set("0".to_string()),
        paid_amount: Set("0".to_string()),
        last_req_id: Set("0x0".to_string()),
        version: Set(1),
        created_at: Set(now),
        updated_at: Set(now),
    };

    entities::tabs::Entity::insert(new_tab)
        .exec(ctx.db.as_ref())
        .await?;

    Ok(())
}

fn load_env() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        dotenv::dotenv().ok();
        dotenv::from_filename("../.env").ok();
    });
}

struct MockContractApi {
    chain_id: u64,
    domain: [u8; 32],
    tab_expiration_time: u64,
}

#[async_trait::async_trait]
impl CoreContractApi for MockContractApi {
    async fn get_chain_id(&self) -> Result<u64, core_service::error::CoreContractApiError> {
        Ok(self.chain_id)
    }

    async fn get_guarantee_domain_separator(
        &self,
    ) -> Result<[u8; 32], core_service::error::CoreContractApiError> {
        Ok(self.domain)
    }

    async fn get_tab_expiration_time(
        &self,
    ) -> Result<u64, core_service::error::CoreContractApiError> {
        Ok(self.tab_expiration_time)
    }

    async fn record_payment(
        &self,
        _tab_id: U256,
        _asset: alloy::primitives::Address,
        _amount: U256,
    ) -> Result<(), core_service::error::CoreContractApiError> {
        Ok(())
    }
}

fn build_read_provider() -> anyhow::Result<DynProvider> {
    let provider_res = panic::catch_unwind(|| {
        ProviderBuilder::new().connect_anvil_with_wallet_and_config(|anvil| anvil.port(40105u16))
    });

    let provider = match provider_res {
        Ok(Ok(p)) => p,
        Ok(Err(err)) => return Err(anyhow::Error::from(err)),
        Err(_) => return Err(anyhow::anyhow!("failed to start anvil provider (panic)")),
    };

    Ok(provider.erased())
}

async fn build_core_service(persist_ctx: PersistCtx) -> anyhow::Result<CoreService> {
    let config = AppConfig::fetch()?;
    let read_provider = build_read_provider()?;
    let chain_id = read_provider.get_chain_id().await?;

    let contract_api: Arc<dyn CoreContractApi> = Arc::new(MockContractApi {
        chain_id,
        domain: [0u8; 32],
        tab_expiration_time: 3600,
    });

    let (_ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let core_service = CoreService::new_with_dependencies(
        config,
        CoreServiceDeps {
            persist_ctx,
            contract_api,
            chain_id,
            read_provider,
            guarantee_domain: [0u8; 32],
            tab_expiration_time: 3600,
            listener_ready_rx: ready_rx,
        },
    )?;
    Ok(core_service)
}

async fn seed_user(ctx: &PersistCtx, addr: &str) {
    use core_service::persist::repo::users::ensure_user_exists_on;

    ensure_user_exists_on(ctx.db.as_ref(), addr)
        .await
        .expect("seed user");
}

struct TestTabSpec {
    tab_id: U256,
    user_address: String,
    recipient_address: String,
    start_ts: chrono::NaiveDateTime,
    ttl: i64,
    status: TabStatus,
    settlement_status: SettlementStatus,
}

async fn insert_tab_with_status(ctx: &PersistCtx, spec: TestTabSpec) {
    let now = Utc::now().naive_utc();
    let tab = entities::tabs::ActiveModel {
        id: Set(u256_to_string(spec.tab_id)),
        user_address: Set(spec.user_address),
        server_address: Set(spec.recipient_address),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(spec.start_ts),
        ttl: Set(spec.ttl),
        status: Set(spec.status),
        settlement_status: Set(spec.settlement_status),
        total_amount: Set("0".to_string()),
        paid_amount: Set("0".to_string()),
        last_req_id: Set("0x0".to_string()),
        version: Set(1),
        created_at: Set(now),
        updated_at: Set(now),
    };

    entities::tabs::Entity::insert(tab)
        .exec(ctx.db.as_ref())
        .await
        .expect("insert tab");
}

async fn insert_pending_tab(
    ctx: &PersistCtx,
    tab_id: U256,
    user_address: String,
    recipient_address: String,
    start_ts: chrono::NaiveDateTime,
    ttl: i64,
) {
    insert_tab_with_status(
        ctx,
        TestTabSpec {
            tab_id,
            user_address,
            recipient_address,
            start_ts,
            ttl,
            status: TabStatus::Pending,
            settlement_status: SettlementStatus::Pending,
        },
    )
    .await;
}

fn build_claims(
    tab_id: U256,
    user_address: String,
    recipient_address: String,
    req_id: U256,
    timestamp: u64,
) -> PaymentGuaranteeRequestClaimsV1 {
    PaymentGuaranteeRequestClaimsV1 {
        tab_id,
        user_address,
        recipient_address,
        req_id,
        asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        amount: U256::from(1u64),
        timestamp,
    }
}

#[test]
#[serial_test::serial]
fn domain_separator_matches_contract_logic() {
    let addr = Address::from_str("0xA15BB66138824a1c7167f5E85b957d04Dd34E468").unwrap();
    let domain = common::fixtures::compute_guarantee_domain_separator(31337, addr).unwrap();
    assert_eq!(
        crypto::hex::encode_hex(&domain),
        "0xeec6b300414b6ac9eee0690bac03714ce16850fc71bd815b15f85beba53f16b1"
    );
}

#[test(tokio::test)]
#[serial_test::serial]
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
        version: Set(0),
        is_suspended: Set(false),
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
        asset: DEFAULT_ASSET_ADDRESS.to_string(),
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
#[serial_test::serial]
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
        version: Set(0),
        is_suspended: Set(false),
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
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(TabStatus::Open),
        settlement_status: Set(SettlementStatus::Pending),
        total_amount: Set("0".to_string()),
        paid_amount: Set("0".to_string()),
        last_req_id: Set("0x0".to_string()),
        version: Set(1),
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
        asset: DEFAULT_ASSET_ADDRESS.to_string(),
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
        asset: DEFAULT_ASSET_ADDRESS.to_string(),
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
#[serial_test::serial]
async fn get_missing_guarantee_returns_none() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let cert = repo::get_guarantee(&ctx, random_u256(), random_u256()).await?;
    assert!(cert.is_none());
    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn get_tab_ttl_seconds_ok_and_missing_errors() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    // insert a tab with ttl = 123
    let user_addr = random_eth_address();

    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        version: Set(0),
        is_suspended: Set(false),
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
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(now),
        created_at: Set(now),
        updated_at: Set(now),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        total_amount: Set("0".to_string()),
        paid_amount: Set("0".to_string()),
        last_req_id: Set("0x0".to_string()),
        version: Set(1),
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
#[serial_test::serial]
async fn get_last_guarantee_for_tab_orders_by_created_at() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let now = Utc::now().naive_utc();

    // Create a user and a tab
    let user_addr = random_eth_address();
    let recipient_addr = random_eth_address();
    let u_am = entities::user::ActiveModel {
        address: Set(user_addr.clone()),
        version: Set(0),
        is_suspended: Set(false),
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
        req_id: U256::from(0x12),
        from: user_addr.clone(),
        to: random_eth_address(),
        asset: DEFAULT_ASSET_ADDRESS.to_string(),
        value: U256::from(10u64),
        start_ts: now,
        cert: "cert-A".into(),
    };
    repo::store_guarantee_on(ctx.db.as_ref(), g1).await?;

    let g2 = GuaranteeData {
        tab_id,
        req_id: U256::from(0x10),
        from: user_addr,
        to: random_eth_address(),
        asset: DEFAULT_ASSET_ADDRESS.to_string(),
        value: U256::from(20u64),
        start_ts: now,
        cert: "cert-B".into(),
    };
    repo::store_guarantee_on(ctx.db.as_ref(), g2).await?;

    // The function should return the row with req_id 0x10 because it was created later
    let last = repo::get_last_guarantee_for_tab(&ctx, tab_id).await?;
    assert!(last.is_some());
    let last = last.unwrap();
    assert_eq!(last.req_id, "0x10");
    assert_eq!(last.value, U256::from(20u64).to_string());

    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_locks_and_inserts_atomically() -> anyhow::Result<()> {
    let config = init()?;
    let ctx = PersistCtx::new().await?;

    // create a user with some collateral
    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    repo::ensure_user_exists_on(ctx.db.as_ref(), &user_addr).await?;
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let domain = common::fixtures::compute_guarantee_domain_separator(
        config.ethereum_config.chain_id,
        config.ethereum_config.contract_address.parse()?,
    )?;

    // recipient + tab
    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    let tab_id = random_u256();
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    // build a minimal PaymentGuaranteeClaims and dummy cert
    let claims = PaymentGuaranteeRequestClaimsV1 {
        tab_id,
        user_address: user_addr.clone(),
        recipient_address: recipient_addr.clone(),
        req_id: U256::ZERO,
        asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        amount: U256::from(40u64),
        timestamp: Utc::now().timestamp() as u64,
    };

    let mut sk_be32 = [0u8; 32];
    sk_be32.copy_from_slice(config.secrets.bls_private_key.as_ref());

    let txn = ctx.db.begin().await?;
    let total_amount = repo::update_user_balance_and_tab_for_guarantee_on(&txn, &claims).await?;

    assert_eq!(total_amount, U256::from(40u64));

    let promise = PaymentGuaranteeClaims::from_request(
        &PaymentGuaranteeRequestClaims::V1(claims),
        domain,
        total_amount,
    );
    let cert = BLSCert::new(&sk_be32, promise.clone())?;

    repo::prepare_and_store_guarantee_on(&txn, &promise, &cert).await?;
    txn.commit().await?;

    // check locked collateral updated
    assert_eq!(
        read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(40u64)
    );

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
#[serial_test::serial]
async fn issue_guarantee_respects_pending_withdrawal() -> anyhow::Result<()> {
    let _config = init()?;
    let ctx = PersistCtx::new().await?;

    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    repo::ensure_user_exists_on(ctx.db.as_ref(), &user_addr).await?;
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        Utc::now().timestamp(),
        U256::from(80u64),
    )
    .await?;

    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    let tab_id = random_u256();
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    let claims = PaymentGuaranteeRequestClaimsV1 {
        tab_id,
        user_address: user_addr.clone(),
        recipient_address: recipient_addr.clone(),
        req_id: U256::ZERO,
        asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        amount: U256::from(30u64),
        timestamp: Utc::now().timestamp() as u64,
    };

    let res = repo::update_user_balance_and_tab_for_guarantee_on(ctx.db.as_ref(), &claims).await;
    assert!(matches!(res, Err(PersistDbError::InsufficientCollateral)));

    assert_eq!(
        read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::ZERO
    );
    let g = entities::guarantee::Entity::find()
        .filter(entities::guarantee::Column::TabId.eq(u256_to_string(tab_id)))
        .filter(entities::guarantee::Column::ReqId.eq(u256_to_string(claims.req_id)))
        .one(ctx.db.as_ref())
        .await?;
    assert!(g.is_none());

    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_allows_with_pending_withdrawal_headroom() -> anyhow::Result<()> {
    let config = init()?;
    let ctx = PersistCtx::new().await?;

    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    repo::ensure_user_exists_on(ctx.db.as_ref(), &user_addr).await?;
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;
    repo::request_withdrawal(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        Utc::now().timestamp(),
        U256::from(40u64),
    )
    .await?;

    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    let tab_id = random_u256();
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    let domain = common::fixtures::compute_guarantee_domain_separator(
        config.ethereum_config.chain_id,
        config.ethereum_config.contract_address.parse()?,
    )?;

    let claims = PaymentGuaranteeRequestClaimsV1 {
        tab_id,
        user_address: user_addr.clone(),
        recipient_address: recipient_addr.clone(),
        req_id: U256::ZERO,
        asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        amount: U256::from(30u64),
        timestamp: Utc::now().timestamp() as u64,
    };

    let txn = ctx.db.begin().await?;
    let total_amount = repo::update_user_balance_and_tab_for_guarantee_on(&txn, &claims).await?;

    assert_eq!(total_amount, U256::from(30u64));

    let promise = PaymentGuaranteeClaims::from_request(
        &PaymentGuaranteeRequestClaims::V1(claims),
        domain,
        total_amount,
    );

    let mut sk_be32 = [0u8; 32];
    sk_be32.copy_from_slice(config.secrets.bls_private_key.as_ref());
    let cert = BLSCert::new(&sk_be32, promise.clone())?;

    repo::prepare_and_store_guarantee_on(&txn, &promise, &cert).await?;
    txn.commit().await?;

    assert_eq!(
        read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(30u64)
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::serial]
async fn issue_guarantee_invalid_timestamp_errors() -> anyhow::Result<()> {
    let _config = init()?;
    let ctx = PersistCtx::new().await?;
    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    repo::ensure_user_exists_on(ctx.db.as_ref(), &user_addr).await?;
    repo::deposit(
        &ctx,
        user_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(50u64),
    )
    .await?;

    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    let tab_id = random_u256();
    insert_test_tab(&ctx, tab_id, user_addr.clone(), recipient_addr.clone()).await?;

    let claims = PaymentGuaranteeRequestClaimsV1 {
        tab_id,
        user_address: user_addr.clone(),
        recipient_address: recipient_addr.clone(),
        req_id: random_u256(),
        asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        amount: U256::from(10u64),
        timestamp: i64::MAX as u64,
    };

    let res = repo::update_user_balance_and_tab_for_guarantee_on(ctx.db.as_ref(), &claims).await;
    assert!(matches!(res, Err(PersistDbError::InvalidTimestamp(_))));

    // locked collateral unchanged
    assert_eq!(
        read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::ZERO
    );

    // no guarantee row inserted
    let g = entities::guarantee::Entity::find()
        .filter(entities::guarantee::Column::TabId.eq(u256_to_string(tab_id)))
        .filter(entities::guarantee::Column::ReqId.eq(u256_to_string(claims.req_id)))
        .one(ctx.db.as_ref())
        .await?;
    assert!(g.is_none());
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn accepts_timestamp_within_tab_window_without_opening_tab() {
    load_env();
    let ctx = match PersistCtx::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("skipping accepts_timestamp_within_tab_window: {err}");
            return;
        }
    };
    let core_service = match build_core_service(ctx.clone()).await {
        Ok(cs) => cs,
        Err(err) => {
            eprintln!("skipping accepts_timestamp_within_tab_window: {err}");
            return;
        }
    };

    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_addr).await;
    seed_user(&ctx, &recipient_addr).await;

    let tab_id = U256::from(random::<u64>());
    let start_ts = (Utc::now() - Duration::seconds(300)).naive_utc();
    let ttl = 600i64;
    insert_pending_tab(
        &ctx,
        tab_id,
        user_addr.clone(),
        recipient_addr.clone(),
        start_ts,
        ttl,
    )
    .await;

    let claims_ts = (start_ts + Duration::seconds(120)).and_utc().timestamp() as u64;
    let claims = build_claims(tab_id, user_addr, recipient_addr, U256::ZERO, claims_ts);

    core_service
        .verify_guarantee_request_claims_v1(&claims)
        .await
        .expect("claims should be valid");

    let tab = repo::get_tab_by_id(&ctx, tab_id)
        .await
        .expect("tab fetch")
        .expect("tab exists");
    assert_eq!(tab.status, TabStatus::Pending);
    assert_eq!(
        tab.start_ts.and_utc().timestamp(),
        start_ts.and_utc().timestamp()
    );
}

#[tokio::test]
#[serial_test::serial]
async fn rejects_timestamp_outside_tab_window() {
    load_env();
    let ctx = match PersistCtx::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("skipping rejects_timestamp_outside_tab_window: {err}");
            return;
        }
    };
    let core_service = match build_core_service(ctx.clone()).await {
        Ok(cs) => cs,
        Err(err) => {
            eprintln!("skipping rejects_timestamp_outside_tab_window: {err}");
            return;
        }
    };

    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_addr).await;
    seed_user(&ctx, &recipient_addr).await;

    let tab_id = U256::from(random::<u64>());
    let start_ts = (Utc::now() - Duration::seconds(600)).naive_utc();
    let ttl = 300i64;
    insert_pending_tab(
        &ctx,
        tab_id,
        user_addr.clone(),
        recipient_addr.clone(),
        start_ts,
        ttl,
    )
    .await;

    // Seed the first guarantee so the pending tab is opened and subsequent requests are treated as follow-ups.
    repo::open_tab(&ctx, tab_id, start_ts)
        .await
        .expect("open pending tab");
    repo::store_guarantee_on(
        ctx.db.as_ref(),
        core_service::persist::GuaranteeData {
            tab_id,
            req_id: U256::ZERO,
            from: user_addr.clone(),
            to: recipient_addr.clone(),
            asset: DEFAULT_ASSET_ADDRESS.to_string(),
            value: U256::from(1u64),
            start_ts,
            cert: "{}".into(),
        },
    )
    .await
    .expect("seed initial guarantee");

    let before_start = (start_ts - Duration::seconds(1)).and_utc().timestamp() as u64;
    let claims = build_claims(
        tab_id,
        user_addr.clone(),
        recipient_addr.clone(),
        U256::from(1u64),
        before_start,
    );
    let err = core_service
        .verify_guarantee_request_claims_v1(&claims)
        .await
        .expect_err("timestamp before start should fail");
    assert!(matches!(
        err,
        core_service::error::ServiceError::ModifiedStartTs
    ));

    let after_expiry = (start_ts + Duration::seconds(ttl + 1))
        .and_utc()
        .timestamp() as u64;
    let claims = build_claims(
        tab_id,
        user_addr,
        recipient_addr,
        U256::from(1u64),
        after_expiry,
    );
    let err = core_service
        .verify_guarantee_request_claims_v1(&claims)
        .await
        .expect_err("timestamp after expiry should fail");
    assert!(matches!(
        err,
        core_service::error::ServiceError::ModifiedStartTs
    ));

    let tab = repo::get_tab_by_id(&ctx, tab_id)
        .await
        .expect("tab fetch")
        .expect("tab exists");
    assert_eq!(tab.status, TabStatus::Open);
    assert_eq!(
        tab.start_ts.and_utc().timestamp(),
        start_ts.and_utc().timestamp()
    );
}

#[tokio::test]
#[serial_test::serial]
async fn rejects_guarantee_when_tab_settlement_finalized() {
    load_env();
    let ctx = match PersistCtx::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("skipping rejects_guarantee_when_tab_settlement_finalized: {err}");
            return;
        }
    };
    let core_service = match build_core_service(ctx.clone()).await {
        Ok(cs) => cs,
        Err(err) => {
            eprintln!("skipping rejects_guarantee_when_tab_settlement_finalized: {err}");
            return;
        }
    };

    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_addr).await;
    seed_user(&ctx, &recipient_addr).await;

    for settlement_status in [SettlementStatus::Settled, SettlementStatus::Remunerated] {
        let tab_id = U256::from(random::<u64>());
        let start_ts = (Utc::now() - Duration::seconds(300)).naive_utc();
        let ttl = 600i64;
        insert_tab_with_status(
            &ctx,
            TestTabSpec {
                tab_id,
                user_address: user_addr.clone(),
                recipient_address: recipient_addr.clone(),
                start_ts,
                ttl,
                status: TabStatus::Open,
                settlement_status,
            },
        )
        .await;

        repo::store_guarantee_on(
            ctx.db.as_ref(),
            core_service::persist::GuaranteeData {
                tab_id,
                req_id: U256::ZERO,
                from: user_addr.clone(),
                to: recipient_addr.clone(),
                asset: DEFAULT_ASSET_ADDRESS.to_string(),
                value: U256::from(1u64),
                start_ts,
                cert: "{}".into(),
            },
        )
        .await
        .expect("seed initial guarantee");

        let claims_ts = (Utc::now() - Duration::seconds(60)).timestamp() as u64;
        let claims = build_claims(
            tab_id,
            user_addr.clone(),
            recipient_addr.clone(),
            U256::from(1u64),
            claims_ts,
        );

        let err = core_service
            .verify_guarantee_request_claims_v1(&claims)
            .await
            .expect_err("finalized settlement should reject guarantees");
        assert!(matches!(err, core_service::error::ServiceError::TabClosed));
    }
}

#[tokio::test]
#[serial_test::serial]
async fn pending_tab_expired_accepts_first_claim_without_reopening() {
    load_env();
    let ctx = match PersistCtx::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("skipping pending_tab_expired_reopens_with_first_claim_timestamp: {err}");
            return;
        }
    };
    let core_service = match build_core_service(ctx.clone()).await {
        Ok(cs) => cs,
        Err(err) => {
            eprintln!("skipping pending_tab_expired_reopens_with_first_claim_timestamp: {err}");
            return;
        }
    };

    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_addr).await;
    seed_user(&ctx, &recipient_addr).await;

    let tab_id = U256::from(random::<u64>());
    let expired_start = (Utc::now() - Duration::seconds(600)).naive_utc();
    let ttl = 120i64;
    insert_pending_tab(
        &ctx,
        tab_id,
        user_addr.clone(),
        recipient_addr.clone(),
        expired_start,
        ttl,
    )
    .await;

    let claim_ts = Utc::now().timestamp() as u64;
    let claims = build_claims(tab_id, user_addr, recipient_addr, U256::ZERO, claim_ts);

    core_service
        .verify_guarantee_request_claims_v1(&claims)
        .await
        .expect("expired pending tab should be reopened");

    let tab = repo::get_tab_by_id(&ctx, tab_id)
        .await
        .expect("tab fetch")
        .expect("tab exists");
    assert_eq!(tab.status, TabStatus::Pending);
    assert_eq!(
        tab.start_ts.and_utc().timestamp(),
        expired_start.and_utc().timestamp()
    );
    assert_eq!(tab.ttl, ttl);
}

#[tokio::test]
#[serial_test::serial]
async fn rejects_tab_ttl_exceeding_tab_expiration_time() {
    load_env();
    let ctx = match PersistCtx::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("skipping rejects_tab_ttl_exceeding_tab_expiration_time: {err}");
            return;
        }
    };
    let core_service = match build_core_service(ctx.clone()).await {
        Ok(cs) => cs,
        Err(err) => {
            eprintln!("skipping rejects_tab_ttl_exceeding_tab_expiration_time: {err}");
            return;
        }
    };

    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_addr).await;
    seed_user(&ctx, &recipient_addr).await;

    let tab_id = U256::from(random::<u64>());
    let start_ts = (Utc::now() - Duration::seconds(60)).naive_utc();
    let ttl = 7200i64;
    insert_pending_tab(
        &ctx,
        tab_id,
        user_addr.clone(),
        recipient_addr.clone(),
        start_ts,
        ttl,
    )
    .await;

    let claims_ts = Utc::now().timestamp() as u64;
    let claims = build_claims(tab_id, user_addr, recipient_addr, U256::ZERO, claims_ts);

    let err = core_service
        .verify_guarantee_request_claims_v1(&claims)
        .await
        .expect_err("ttl exceeding tab expiration should be rejected");
    assert!(matches!(
        err,
        core_service::error::ServiceError::InvalidParams(msg)
            if msg.contains("tab expiration time")
    ));
}
