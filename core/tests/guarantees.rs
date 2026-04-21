use std::{
    net::TcpListener,
    panic,
    str::FromStr,
    sync::{
        Arc, Once,
        atomic::{AtomicU16, Ordering},
    },
};

use alloy::primitives::{Address, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolStruct, eip712_domain, sol};
use chrono::{Duration, Utc};
use core_service::{
    auth::{access::AccessContext, constants::SCOPE_GUARANTEE_ISSUE},
    config::{AppConfig, DEFAULT_ASSET_ADDRESS},
    error::PersistDbError,
    error::ServiceError,
    ethereum::{CoreContractApi, GuaranteeVersionConfig, RecordPaymentTx},
    persist::*,
    service::{CoreService, CoreServiceDeps},
    util::u256_to_string,
};
use crypto::bls::{BLSCert, BlsClaims};
use entities::sea_orm_active_enums::{SettlementStatus, TabStatus};
use entities::{guarantee, user};
use rand::random;
use rpc::{
    GUARANTEE_CLAIMS_VERSION, PaymentGuaranteeClaims, PaymentGuaranteeRequest,
    PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1,
    PaymentGuaranteeRequestClaimsV2, PaymentGuaranteeValidationPolicyV2, SigningScheme,
    compute_validation_request_hash, compute_validation_subject_hash,
};
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

fn normalize_address(raw: &str) -> String {
    format!(
        "{:#x}",
        Address::from_str(raw).expect("valid address for test")
    )
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
    let user_address = normalize_address(&user_address);
    let recipient_address = normalize_address(&recipient_address);
    let new_tab = entities::tabs::ActiveModel {
        id: Set(u256_to_string(id)),
        user_address: Set(user_address),
        server_address: Set(recipient_address),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(now),
        ttl: Set(300),
        status: Set(entities::sea_orm_active_enums::TabStatus::Open),
        settlement_status: Set(entities::sea_orm_active_enums::SettlementStatus::Pending),
        total_amount: Set("0".to_string()),
        paid_amount: Set("0".to_string()),
        last_req_id: Set("0x0".to_string()),
        accepted_guarantee_version: Set(Some(1)),
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

fn allocate_anvil_port() -> anyhow::Result<u16> {
    static NEXT_PORT: AtomicU16 = AtomicU16::new(40105);

    for _ in 0..200 {
        let candidate = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let listener = match TcpListener::bind(("127.0.0.1", candidate)) {
            Ok(listener) => listener,
            Err(_) => continue,
        };
        let port = listener.local_addr()?.port();
        drop(listener);
        return Ok(port);
    }

    anyhow::bail!("could not allocate anvil port")
}

fn build_read_provider() -> anyhow::Result<DynProvider> {
    let anvil_port = allocate_anvil_port()?;
    let provider_res = panic::catch_unwind(|| {
        ProviderBuilder::new().connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))
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
    let accepted_request_versions = config
        .guarantee
        .accepted_request_versions()?
        .into_iter()
        .map(|version| version.to_string())
        .collect::<Vec<_>>()
        .join(",");
    build_core_service_with_guarantee_config(
        persist_ctx,
        config.guarantee.max_accepted_version,
        accepted_request_versions,
        config.guarantee.trusted_validation_registries,
    )
    .await
}

async fn build_core_service_with_active_version(
    persist_ctx: PersistCtx,
    max_accepted_guarantee_version: u64,
) -> anyhow::Result<CoreService> {
    let trusted_validation_registries = if max_accepted_guarantee_version == 2 {
        "0x1111111111111111111111111111111111111111".to_string()
    } else {
        String::new()
    };
    build_core_service_with_guarantee_config(
        persist_ctx,
        max_accepted_guarantee_version,
        max_accepted_guarantee_version.to_string(),
        trusted_validation_registries,
    )
    .await
}

async fn build_core_service_with_guarantee_config(
    persist_ctx: PersistCtx,
    max_accepted_guarantee_version: u64,
    accepted_request_versions: String,
    trusted_validation_registries: String,
) -> anyhow::Result<CoreService> {
    let mut config = AppConfig::fetch()?;
    config.guarantee.max_accepted_version = max_accepted_guarantee_version;
    config.guarantee.accepted_request_versions = accepted_request_versions.clone();
    config.guarantee.trusted_validation_registries = trusted_validation_registries;
    let read_provider = build_read_provider()?;
    let chain_id = read_provider.get_chain_id().await?;

    let contract_api: Arc<dyn CoreContractApi> = Arc::new(MockContractApi {
        chain_id,
        domain: [0u8; 32],
        tab_expiration_time: 3600,
    });

    let core_service = CoreService::new_with_dependencies(
        config,
        CoreServiceDeps {
            persist_ctx,
            contract_api,
            chain_id,
            read_provider,
            guarantee_domains: accepted_request_versions
                .split(',')
                .map(str::trim)
                .filter(|version| !version.is_empty())
                .map(|version| {
                    version
                        .parse::<u64>()
                        .map(|version| (version, [0u8; 32]))
                        .expect("accepted guarantee version must parse in test helper")
                })
                .collect(),
            tab_expiration_time: 3600,
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
    guarantee_version: u64,
    start_ts: chrono::NaiveDateTime,
    ttl: i64,
    status: TabStatus,
    settlement_status: SettlementStatus,
}

async fn insert_tab_with_status(ctx: &PersistCtx, spec: TestTabSpec) {
    let now = Utc::now().naive_utc();
    let user_address = normalize_address(&spec.user_address);
    let recipient_address = normalize_address(&spec.recipient_address);
    let tab = entities::tabs::ActiveModel {
        id: Set(u256_to_string(spec.tab_id)),
        user_address: Set(user_address),
        server_address: Set(recipient_address),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(spec.start_ts),
        ttl: Set(spec.ttl),
        status: Set(spec.status),
        settlement_status: Set(spec.settlement_status),
        total_amount: Set("0".to_string()),
        paid_amount: Set("0".to_string()),
        last_req_id: Set("0x0".to_string()),
        accepted_guarantee_version: Set(Some(spec.guarantee_version as i32)),
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
    insert_pending_tab_with_version(
        ctx,
        tab_id,
        user_address,
        recipient_address,
        1,
        start_ts,
        ttl,
    )
    .await;
}

async fn insert_pending_tab_with_version(
    ctx: &PersistCtx,
    tab_id: U256,
    user_address: String,
    recipient_address: String,
    guarantee_version: u64,
    start_ts: chrono::NaiveDateTime,
    ttl: i64,
) {
    insert_tab_with_status(
        ctx,
        TestTabSpec {
            tab_id,
            user_address,
            recipient_address,
            guarantee_version,
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

sol! {
    struct SolGuaranteeRequestClaimsV1 {
        address user;
        address recipient;
        uint256 tabId;
        uint256 reqId;
        uint256 amount;
        address asset;
        uint64 timestamp;
    }

    struct SolGuaranteeRequestClaimsV2 {
        address user;
        address recipient;
        uint256 tabId;
        uint256 reqId;
        uint256 amount;
        address asset;
        uint64 timestamp;
        address validationRegistryAddress;
        bytes32 validationRequestHash;
        uint256 validationChainId;
        address validatorAddress;
        uint256 validatorAgentId;
        uint8 minValidationScore;
        bytes32 validationSubjectHash;
        bytes32 jobHash;
        string requiredValidationTag;
    }
}

#[allow(clippy::too_many_arguments)]
fn build_v2_claims(
    chain_id: u64,
    user_address: String,
    recipient_address: String,
    tab_id: U256,
    req_id: U256,
    amount: U256,
    asset_address: String,
    timestamp: u64,
) -> anyhow::Result<PaymentGuaranteeRequestClaimsV2> {
    let validation_subject_hash = compute_validation_subject_hash(
        &user_address,
        &recipient_address,
        tab_id,
        req_id,
        amount,
        &asset_address,
        timestamp,
    )?;

    let mut validation_policy = PaymentGuaranteeValidationPolicyV2 {
        validation_registry_address: Address::from_str(
            "0x1111111111111111111111111111111111111111",
        )
        .expect("valid validation registry"),
        validation_request_hash: B256::ZERO,
        validation_chain_id: chain_id,
        validator_address: Address::from_str("0x2222222222222222222222222222222222222222")
            .expect("valid validator"),
        validator_agent_id: U256::from(77u64),
        min_validation_score: 80,
        validation_subject_hash: B256::from(validation_subject_hash),
        job_hash: B256::repeat_byte(0x11),
        required_validation_tag: "hard-finality".to_string(),
    };
    validation_policy.validation_request_hash =
        B256::from(compute_validation_request_hash(&validation_policy)?);

    Ok(PaymentGuaranteeRequestClaimsV2 {
        user_address,
        recipient_address,
        tab_id,
        req_id,
        amount,
        asset_address,
        timestamp,
        validation_policy,
    })
}

async fn sign_v2_request(
    params: &rpc::CorePublicParameters,
    wallet: &PrivateKeySigner,
    claims: PaymentGuaranteeRequestClaimsV2,
) -> anyhow::Result<PaymentGuaranteeRequest> {
    let domain = eip712_domain!(
        name: params.eip712_name.clone(),
        version: params.eip712_version.clone(),
        chain_id: params.chain_id,
    );
    let msg = SolGuaranteeRequestClaimsV2 {
        user: Address::from_str(&claims.user_address)?,
        recipient: Address::from_str(&claims.recipient_address)?,
        tabId: claims.tab_id,
        reqId: claims.req_id,
        amount: claims.amount,
        asset: Address::from_str(&claims.asset_address)?,
        timestamp: claims.timestamp,
        validationRegistryAddress: claims.validation_policy.validation_registry_address,
        validationRequestHash: claims.validation_policy.validation_request_hash,
        validationChainId: U256::from(claims.validation_policy.validation_chain_id),
        validatorAddress: claims.validation_policy.validator_address,
        validatorAgentId: claims.validation_policy.validator_agent_id,
        minValidationScore: claims.validation_policy.min_validation_score,
        validationSubjectHash: claims.validation_policy.validation_subject_hash,
        jobHash: claims.validation_policy.job_hash,
        requiredValidationTag: claims.validation_policy.required_validation_tag.clone(),
    };
    let digest = msg.eip712_signing_hash(&domain);
    let sig = wallet.sign_hash(&digest).await?;

    Ok(PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V2(Box::new(claims)),
        crypto::hex::encode_hex(&sig.as_bytes()),
        SigningScheme::Eip712,
    ))
}

async fn sign_v1_request(
    params: &rpc::CorePublicParameters,
    wallet: &PrivateKeySigner,
    claims: PaymentGuaranteeRequestClaimsV1,
) -> anyhow::Result<PaymentGuaranteeRequest> {
    let domain = eip712_domain!(
        name: params.eip712_name.clone(),
        version: params.eip712_version.clone(),
        chain_id: params.chain_id,
    );
    let msg = SolGuaranteeRequestClaimsV1 {
        user: Address::from_str(&claims.user_address)?,
        recipient: Address::from_str(&claims.recipient_address)?,
        tabId: claims.tab_id,
        reqId: claims.req_id,
        amount: claims.amount,
        asset: Address::from_str(&claims.asset_address)?,
        timestamp: claims.timestamp,
    };
    let digest = msg.eip712_signing_hash(&domain);
    let sig = wallet.sign_hash(&digest).await?;

    Ok(PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(claims),
        crypto::hex::encode_hex(&sig.as_bytes()),
        SigningScheme::Eip712,
    ))
}

#[test]
#[serial_test::file_serial]
fn domain_separator_matches_contract_logic() {
    let addr = Address::from_str("0xA15BB66138824a1c7167f5E85b957d04Dd34E468").unwrap();
    let domain = common::fixtures::compute_guarantee_domain_separator(31337, addr).unwrap();
    assert_eq!(
        crypto::hex::encode_hex(&domain),
        "0xeec6b300414b6ac9eee0690bac03714ce16850fc71bd815b15f85beba53f16b1"
    );
}

#[test(tokio::test)]
#[serial_test::file_serial]
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
        version: 1,
        from: from_addr.clone(),
        to: to_addr.clone(),
        asset: DEFAULT_ASSET_ADDRESS.to_string(),
        value: U256::from(42u64),
        start_ts: now,
        cert: "cert".into(),
        request: None,
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
#[serial_test::file_serial]
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
        accepted_guarantee_version: Set(Some(1)),
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
        version: 1,
        from: from_addr.clone(),
        to: to_addr.clone(),
        asset: DEFAULT_ASSET_ADDRESS.to_string(),
        value: U256::from(100u64),
        start_ts: now,
        cert: "cert".into(),
        request: None,
    };
    repo::store_guarantee_on(ctx.db.as_ref(), data1).await?;

    // ── Second insert with same (tab_id, req_id) must be a no-op ──
    let data2 = GuaranteeData {
        tab_id,
        req_id,
        version: 1,
        from: from_addr,
        to: to_addr,
        asset: DEFAULT_ASSET_ADDRESS.to_string(),
        value: U256::from(200u64),
        start_ts: now,
        cert: "cert2".into(),
        request: None,
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
#[serial_test::file_serial]
async fn get_missing_guarantee_returns_none() -> anyhow::Result<()> {
    let _ = init()?;
    let ctx = PersistCtx::new().await?;
    let cert = repo::get_guarantee(&ctx, random_u256(), random_u256()).await?;
    assert!(cert.is_none());
    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial]
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
        accepted_guarantee_version: Set(Some(1)),
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
#[serial_test::file_serial]
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
        version: 1,
        from: user_addr.clone(),
        to: random_eth_address(),
        asset: DEFAULT_ASSET_ADDRESS.to_string(),
        value: U256::from(10u64),
        start_ts: now,
        cert: "cert-A".into(),
        request: None,
    };
    repo::store_guarantee_on(ctx.db.as_ref(), g1).await?;

    let g2 = GuaranteeData {
        tab_id,
        req_id: U256::from(0x10),
        version: 1,
        from: user_addr,
        to: random_eth_address(),
        asset: DEFAULT_ASSET_ADDRESS.to_string(),
        value: U256::from(20u64),
        start_ts: now,
        cert: "cert-B".into(),
        request: None,
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
#[serial_test::file_serial]
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

    let txn = ctx.db.begin().await?;
    let total_amount = repo::update_user_balance_and_tab_for_guarantee_on(&txn, &claims, 1).await?;

    assert_eq!(total_amount, U256::from(40u64));

    let promise = PaymentGuaranteeClaims::from_request(
        &PaymentGuaranteeRequestClaims::V1(claims.clone()),
        domain,
        total_amount,
    );
    let claims_bytes: Vec<u8> = promise.clone().try_into()?;
    let cert = BLSCert::sign(
        &config.secrets.bls_secret_key,
        BlsClaims::from_bytes(claims_bytes),
    )?;
    let req = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(claims),
        "0x".to_string() + &"0".repeat(130),
        SigningScheme::Eip712,
    );

    repo::prepare_and_store_guarantee_on(&txn, &promise, &cert, &req).await?;
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
#[serial_test::file_serial]
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

    let res = repo::update_user_balance_and_tab_for_guarantee_on(ctx.db.as_ref(), &claims, 1).await;
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
#[serial_test::file_serial]
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
    let total_amount = repo::update_user_balance_and_tab_for_guarantee_on(&txn, &claims, 1).await?;

    assert_eq!(total_amount, U256::from(30u64));

    let promise = PaymentGuaranteeClaims::from_request(
        &PaymentGuaranteeRequestClaims::V1(claims.clone()),
        domain,
        total_amount,
    );

    let claims_bytes: Vec<u8> = promise.clone().try_into()?;
    let cert = BLSCert::sign(
        &config.secrets.bls_secret_key,
        BlsClaims::from_bytes(claims_bytes),
    )?;
    let req = PaymentGuaranteeRequest::new(
        PaymentGuaranteeRequestClaims::V1(claims),
        "0x".to_string() + &"0".repeat(130),
        SigningScheme::Eip712,
    );

    repo::prepare_and_store_guarantee_on(&txn, &promise, &cert, &req).await?;
    txn.commit().await?;

    assert_eq!(
        read_locked_collateral(&ctx, &user_addr, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(30u64)
    );

    Ok(())
}

#[test(tokio::test)]
#[serial_test::file_serial]
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

    let res = repo::update_user_balance_and_tab_for_guarantee_on(ctx.db.as_ref(), &claims, 1).await;
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
#[serial_test::file_serial]
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
        .verify_guarantee_request_claims_v1(&claims, 1)
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
#[serial_test::file_serial]
async fn rejects_recipient_mismatch_on_guarantee_claims() {
    load_env();
    let ctx = match PersistCtx::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("skipping rejects_recipient_mismatch_on_guarantee_claims: {err}");
            return;
        }
    };
    let core_service = match build_core_service(ctx.clone()).await {
        Ok(cs) => cs,
        Err(err) => {
            eprintln!("skipping rejects_recipient_mismatch_on_guarantee_claims: {err}");
            return;
        }
    };

    let user_addr = format!("0x{:040x}", rand::random::<u128>());
    let recipient_addr = format!("0x{:040x}", rand::random::<u128>());
    let mut wrong_recipient = format!("0x{:040x}", rand::random::<u128>());
    while wrong_recipient == recipient_addr {
        wrong_recipient = format!("0x{:040x}", rand::random::<u128>());
    }
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

    let claims_ts = (start_ts + Duration::seconds(60)).and_utc().timestamp() as u64;
    let claims = build_claims(tab_id, user_addr, wrong_recipient, U256::ZERO, claims_ts);

    let err = core_service
        .verify_guarantee_request_claims_v1(&claims, 1)
        .await
        .expect_err("recipient mismatch should be rejected");
    assert!(matches!(
        err,
        core_service::error::ServiceError::InvalidParams(msg)
            if msg.contains("Recipient address does not match tab")
    ));
}

#[tokio::test]
#[serial_test::file_serial]
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
            version: 1,
            from: user_addr.clone(),
            to: recipient_addr.clone(),
            asset: DEFAULT_ASSET_ADDRESS.to_string(),
            value: U256::from(1u64),
            start_ts,
            cert: "{}".into(),
            request: None,
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
        .verify_guarantee_request_claims_v1(&claims, 1)
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
        .verify_guarantee_request_claims_v1(&claims, 1)
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
#[serial_test::file_serial]
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
                guarantee_version: 1,
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
                version: 1,
                from: user_addr.clone(),
                to: recipient_addr.clone(),
                asset: DEFAULT_ASSET_ADDRESS.to_string(),
                value: U256::from(1u64),
                start_ts,
                cert: "{}".into(),
                request: None,
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
            .verify_guarantee_request_claims_v1(&claims, 1)
            .await
            .expect_err("finalized settlement should reject guarantees");
        assert!(matches!(err, core_service::error::ServiceError::TabClosed));
    }
}

#[tokio::test]
#[serial_test::file_serial]
async fn rejects_guarantee_when_tab_closed() {
    load_env();
    let ctx = match PersistCtx::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("skipping rejects_guarantee_when_tab_closed: {err}");
            return;
        }
    };
    let core_service = match build_core_service(ctx.clone()).await {
        Ok(cs) => cs,
        Err(err) => {
            eprintln!("skipping rejects_guarantee_when_tab_closed: {err}");
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
    insert_tab_with_status(
        &ctx,
        TestTabSpec {
            tab_id,
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            guarantee_version: 1,
            start_ts,
            ttl,
            status: TabStatus::Closed,
            settlement_status: SettlementStatus::Pending,
        },
    )
    .await;

    let claims_ts = (start_ts + Duration::seconds(120)).and_utc().timestamp() as u64;
    let claims = build_claims(tab_id, user_addr, recipient_addr, U256::ZERO, claims_ts);

    let err = core_service
        .verify_guarantee_request_claims_v1(&claims, 1)
        .await
        .expect_err("closed tab should reject guarantees");
    assert!(matches!(err, core_service::error::ServiceError::TabClosed));
}

#[tokio::test]
#[serial_test::file_serial]
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
        .verify_guarantee_request_claims_v1(&claims, 1)
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
#[serial_test::file_serial]
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
        .verify_guarantee_request_claims_v1(&claims, 1)
        .await
        .expect_err("ttl exceeding tab expiration should be rejected");
    assert!(matches!(
        err,
        core_service::error::ServiceError::InvalidParams(msg)
            if msg.contains("tab expiration time")
    ));
}

fn recipient_issue_auth(recipient_address: &str) -> AccessContext {
    AccessContext {
        wallet_address: recipient_address.to_string(),
        role: "admin".to_string(),
        scopes: vec![SCOPE_GUARANTEE_ISSUE.to_string()],
    }
}

#[tokio::test]
#[serial_test::file_serial]
async fn issue_v2_guarantee_succeeds_when_active_version_is_v2() -> anyhow::Result<()> {
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_active_version(ctx.clone(), 2).await?;

    let user_wallet = PrivateKeySigner::random();
    let user_address = user_wallet.address().to_string();
    let recipient_address = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_address).await;
    seed_user(&ctx, &recipient_address).await;
    repo::deposit(
        &ctx,
        user_address.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tab_id = U256::from(rand::random::<u64>());
    let timestamp = Utc::now().timestamp() as u64;
    insert_pending_tab_with_version(
        &ctx,
        tab_id,
        user_address.clone(),
        recipient_address.clone(),
        2,
        Utc::now().naive_utc(),
        600,
    )
    .await;

    let claims = build_v2_claims(
        core_service.public_params().chain_id,
        user_address,
        recipient_address.clone(),
        tab_id,
        U256::ZERO,
        U256::from(5u64),
        DEFAULT_ASSET_ADDRESS.to_string(),
        timestamp,
    )?;
    let req = sign_v2_request(&core_service.public_params(), &user_wallet, claims).await?;

    let cert = core_service
        .issue_payment_guarantee(&recipient_issue_auth(&recipient_address), req)
        .await?;
    assert!(!serde_json::to_string(&cert)?.is_empty());

    let stored = repo::get_guarantee(&ctx, tab_id, U256::ZERO).await?;
    assert!(stored.is_some(), "v2 guarantee should be persisted");
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn issue_v2_guarantee_rejects_when_active_version_is_v1() -> anyhow::Result<()> {
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_active_version(ctx.clone(), 1).await?;

    let user_wallet = PrivateKeySigner::random();
    let user_address = user_wallet.address().to_string();
    let recipient_address = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_address).await;
    seed_user(&ctx, &recipient_address).await;
    repo::deposit(
        &ctx,
        user_address.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tab_id = U256::from(rand::random::<u64>());
    let timestamp = Utc::now().timestamp() as u64;
    insert_pending_tab_with_version(
        &ctx,
        tab_id,
        user_address.clone(),
        recipient_address.clone(),
        2,
        Utc::now().naive_utc(),
        600,
    )
    .await;

    let claims = build_v2_claims(
        core_service.public_params().chain_id,
        user_address,
        recipient_address.clone(),
        tab_id,
        U256::ZERO,
        U256::from(5u64),
        DEFAULT_ASSET_ADDRESS.to_string(),
        timestamp,
    )?;
    let req = sign_v2_request(&core_service.public_params(), &user_wallet, claims).await?;

    let err = core_service
        .issue_payment_guarantee(&recipient_issue_auth(&recipient_address), req)
        .await
        .expect_err("v2 should be rejected when active version is v1");
    assert!(matches!(
        err,
        ServiceError::InvalidParams(msg) if msg.contains("not accepted") && msg.contains("[1]")
    ));
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn issue_v1_guarantee_succeeds_when_active_version_is_v2_and_v1_is_accepted()
-> anyhow::Result<()> {
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_guarantee_config(
        ctx.clone(),
        2,
        "1,2".to_string(),
        "0x1111111111111111111111111111111111111111".to_string(),
    )
    .await?;

    let user_wallet = PrivateKeySigner::random();
    let user_address = user_wallet.address().to_string();
    let recipient_address = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_address).await;
    seed_user(&ctx, &recipient_address).await;
    repo::deposit(
        &ctx,
        user_address.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tab_id = U256::from(rand::random::<u64>());
    let timestamp = Utc::now().timestamp() as u64;
    insert_pending_tab_with_version(
        &ctx,
        tab_id,
        user_address.clone(),
        recipient_address.clone(),
        1,
        Utc::now().naive_utc(),
        600,
    )
    .await;

    let claims = PaymentGuaranteeRequestClaimsV1 {
        user_address,
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id: U256::ZERO,
        amount: U256::from(5u64),
        asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        timestamp,
    };
    let req = sign_v1_request(&core_service.public_params(), &user_wallet, claims).await?;

    let cert = core_service
        .issue_payment_guarantee(&recipient_issue_auth(&recipient_address), req)
        .await?;
    let guarantee = PaymentGuaranteeClaims::try_from(cert.claims().as_bytes())?;
    assert_eq!(guarantee.version, GUARANTEE_CLAIMS_VERSION);
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn issue_first_guarantee_pins_tab_to_that_version() -> anyhow::Result<()> {
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_guarantee_config(
        ctx.clone(),
        2,
        "1,2".to_string(),
        "0x1111111111111111111111111111111111111111".to_string(),
    )
    .await?;

    let user_wallet = PrivateKeySigner::random();
    let user_address = user_wallet.address().to_string();
    let recipient_address = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_address).await;
    seed_user(&ctx, &recipient_address).await;
    repo::deposit(
        &ctx,
        user_address.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tab_id = U256::from(rand::random::<u64>());
    let timestamp = Utc::now().timestamp() as u64;
    insert_pending_tab_with_version(
        &ctx,
        tab_id,
        user_address.clone(),
        recipient_address.clone(),
        1,
        Utc::now().naive_utc(),
        600,
    )
    .await;

    let claims = PaymentGuaranteeRequestClaimsV1 {
        user_address,
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id: U256::ZERO,
        amount: U256::from(5u64),
        asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        timestamp,
    };
    let req = sign_v1_request(&core_service.public_params(), &user_wallet, claims).await?;

    core_service
        .issue_payment_guarantee(&recipient_issue_auth(&recipient_address), req)
        .await?;

    let tab = repo::get_tab_by_id(&ctx, tab_id)
        .await?
        .expect("tab should exist after issuing guarantee");
    assert_eq!(tab.accepted_guarantee_version, Some(1));
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn issue_mixed_guarantee_version_on_same_tab_is_rejected() -> anyhow::Result<()> {
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_guarantee_config(
        ctx.clone(),
        2,
        "1,2".to_string(),
        "0x1111111111111111111111111111111111111111".to_string(),
    )
    .await?;

    let user_wallet = PrivateKeySigner::random();
    let user_address = user_wallet.address().to_string();
    let recipient_address = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_address).await;
    seed_user(&ctx, &recipient_address).await;
    repo::deposit(
        &ctx,
        user_address.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tab_id = U256::from(rand::random::<u64>());
    insert_pending_tab_with_version(
        &ctx,
        tab_id,
        user_address.clone(),
        recipient_address.clone(),
        1,
        Utc::now().naive_utc(),
        600,
    )
    .await;

    let first_timestamp = Utc::now().timestamp() as u64;
    let first_claims = PaymentGuaranteeRequestClaimsV1 {
        user_address: user_address.clone(),
        recipient_address: recipient_address.clone(),
        tab_id,
        req_id: U256::ZERO,
        amount: U256::from(5u64),
        asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        timestamp: first_timestamp,
    };
    let first_req =
        sign_v1_request(&core_service.public_params(), &user_wallet, first_claims).await?;
    core_service
        .issue_payment_guarantee(&recipient_issue_auth(&recipient_address), first_req)
        .await?;

    let second_claims = build_v2_claims(
        core_service.public_params().chain_id,
        user_address,
        recipient_address.clone(),
        tab_id,
        U256::from(1u64),
        U256::from(5u64),
        DEFAULT_ASSET_ADDRESS.to_string(),
        Utc::now().timestamp() as u64,
    )?;
    let second_req =
        sign_v2_request(&core_service.public_params(), &user_wallet, second_claims).await?;

    let err = core_service
        .issue_payment_guarantee(&recipient_issue_auth(&recipient_address), second_req)
        .await
        .expect_err("tab should reject switching guarantee versions");
    assert!(matches!(
        err,
        ServiceError::InvalidParams(msg)
            if msg.contains("only accepts guarantee version 1") && msg.contains("got 2")
    ));

    let tab = repo::get_tab_by_id(&ctx, tab_id)
        .await?
        .expect("tab should exist after rejection");
    assert_eq!(tab.accepted_guarantee_version, Some(1));
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn issue_v2_guarantee_rejects_subject_hash_mismatch() -> anyhow::Result<()> {
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_active_version(ctx.clone(), 2).await?;

    let user_wallet = PrivateKeySigner::random();
    let user_address = user_wallet.address().to_string();
    let recipient_address = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_address).await;
    seed_user(&ctx, &recipient_address).await;
    repo::deposit(
        &ctx,
        user_address.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tab_id = U256::from(rand::random::<u64>());
    let timestamp = Utc::now().timestamp() as u64;
    insert_pending_tab_with_version(
        &ctx,
        tab_id,
        user_address.clone(),
        recipient_address.clone(),
        2,
        Utc::now().naive_utc(),
        600,
    )
    .await;

    let mut claims = build_v2_claims(
        core_service.public_params().chain_id,
        user_address,
        recipient_address.clone(),
        tab_id,
        U256::ZERO,
        U256::from(5u64),
        DEFAULT_ASSET_ADDRESS.to_string(),
        timestamp,
    )?;
    claims.validation_policy.validation_subject_hash = B256::repeat_byte(0xAA);
    let req = sign_v2_request(&core_service.public_params(), &user_wallet, claims).await?;

    let err = core_service
        .issue_payment_guarantee(&recipient_issue_auth(&recipient_address), req)
        .await
        .expect_err("subject hash mismatch must fail");
    assert!(matches!(
        err,
        ServiceError::InvalidParams(msg) if msg.contains("validation_subject_hash")
    ));
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn issue_v2_guarantee_rejects_request_hash_mismatch() -> anyhow::Result<()> {
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_active_version(ctx.clone(), 2).await?;

    let user_wallet = PrivateKeySigner::random();
    let user_address = user_wallet.address().to_string();
    let recipient_address = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_address).await;
    seed_user(&ctx, &recipient_address).await;
    repo::deposit(
        &ctx,
        user_address.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tab_id = U256::from(rand::random::<u64>());
    let timestamp = Utc::now().timestamp() as u64;
    insert_pending_tab_with_version(
        &ctx,
        tab_id,
        user_address.clone(),
        recipient_address.clone(),
        2,
        Utc::now().naive_utc(),
        600,
    )
    .await;

    let mut claims = build_v2_claims(
        core_service.public_params().chain_id,
        user_address,
        recipient_address.clone(),
        tab_id,
        U256::ZERO,
        U256::from(5u64),
        DEFAULT_ASSET_ADDRESS.to_string(),
        timestamp,
    )?;
    claims.validation_policy.validation_request_hash = B256::repeat_byte(0xBB);
    let req = sign_v2_request(&core_service.public_params(), &user_wallet, claims).await?;

    let err = core_service
        .issue_payment_guarantee(&recipient_issue_auth(&recipient_address), req)
        .await
        .expect_err("request hash mismatch must fail");
    assert!(matches!(
        err,
        ServiceError::InvalidParams(msg) if msg.contains("validation_request_hash")
    ));
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn issue_v2_guarantee_rejects_min_validation_score_zero() -> anyhow::Result<()> {
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_active_version(ctx.clone(), 2).await?;

    let user_wallet = PrivateKeySigner::random();
    let user_address = user_wallet.address().to_string();
    let recipient_address = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_address).await;
    seed_user(&ctx, &recipient_address).await;
    repo::deposit(
        &ctx,
        user_address.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tab_id = U256::from(rand::random::<u64>());
    let timestamp = Utc::now().timestamp() as u64;
    insert_pending_tab_with_version(
        &ctx,
        tab_id,
        user_address.clone(),
        recipient_address.clone(),
        2,
        Utc::now().naive_utc(),
        600,
    )
    .await;

    let mut claims = build_v2_claims(
        core_service.public_params().chain_id,
        user_address,
        recipient_address.clone(),
        tab_id,
        U256::ZERO,
        U256::from(5u64),
        DEFAULT_ASSET_ADDRESS.to_string(),
        timestamp,
    )?;
    claims.validation_policy.min_validation_score = 0;
    let req = sign_v2_request(&core_service.public_params(), &user_wallet, claims).await?;

    let err = core_service
        .issue_payment_guarantee(&recipient_issue_auth(&recipient_address), req)
        .await
        .expect_err("min_validation_score=0 must fail");
    assert!(matches!(
        err,
        ServiceError::InvalidParams(msg) if msg.contains("min_validation_score")
    ));
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn issue_v2_guarantee_rejects_untrusted_validation_registry() -> anyhow::Result<()> {
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_guarantee_config(
        ctx.clone(),
        2,
        "2".to_string(),
        "0x3333333333333333333333333333333333333333".to_string(),
    )
    .await?;

    let user_wallet = PrivateKeySigner::random();
    let user_address = user_wallet.address().to_string();
    let recipient_address = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_address).await;
    seed_user(&ctx, &recipient_address).await;
    repo::deposit(
        &ctx,
        user_address.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tab_id = U256::from(rand::random::<u64>());
    let timestamp = Utc::now().timestamp() as u64;
    insert_pending_tab_with_version(
        &ctx,
        tab_id,
        user_address.clone(),
        recipient_address.clone(),
        2,
        Utc::now().naive_utc(),
        600,
    )
    .await;

    let claims = build_v2_claims(
        core_service.public_params().chain_id,
        user_address,
        recipient_address.clone(),
        tab_id,
        U256::ZERO,
        U256::from(5u64),
        DEFAULT_ASSET_ADDRESS.to_string(),
        timestamp,
    )?;
    let req = sign_v2_request(&core_service.public_params(), &user_wallet, claims).await?;

    let err = core_service
        .issue_payment_guarantee(&recipient_issue_auth(&recipient_address), req)
        .await
        .expect_err("untrusted validation registry must fail");
    assert!(matches!(
        err,
        ServiceError::InvalidParams(msg)
            if msg.contains("validation registry") && msg.contains("not trusted")
    ));
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn issue_v2_guarantee_accepts_trusted_validation_registry() -> anyhow::Result<()> {
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_guarantee_config(
        ctx.clone(),
        2,
        "2".to_string(),
        "0x1111111111111111111111111111111111111111".to_string(),
    )
    .await?;

    let user_wallet = PrivateKeySigner::random();
    let user_address = user_wallet.address().to_string();
    let recipient_address = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user_address).await;
    seed_user(&ctx, &recipient_address).await;
    repo::deposit(
        &ctx,
        user_address.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(100u64),
    )
    .await?;

    let tab_id = U256::from(rand::random::<u64>());
    let timestamp = Utc::now().timestamp() as u64;
    insert_pending_tab_with_version(
        &ctx,
        tab_id,
        user_address.clone(),
        recipient_address.clone(),
        2,
        Utc::now().naive_utc(),
        600,
    )
    .await;

    let claims = build_v2_claims(
        core_service.public_params().chain_id,
        user_address,
        recipient_address.clone(),
        tab_id,
        U256::ZERO,
        U256::from(5u64),
        DEFAULT_ASSET_ADDRESS.to_string(),
        timestamp,
    )?;
    let req = sign_v2_request(&core_service.public_params(), &user_wallet, claims).await?;

    core_service
        .issue_payment_guarantee(&recipient_issue_auth(&recipient_address), req)
        .await
        .expect("trusted validation registry should pass");
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn core_service_public_params_include_guarantee_metadata() -> anyhow::Result<()> {
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_active_version(ctx, 2).await?;
    let params = core_service.public_params();

    assert_eq!(params.max_accepted_guarantee_version, 2);
    assert!(
        params.active_guarantee_domain_separator.starts_with("0x")
            && params.active_guarantee_domain_separator.len() == 66
    );
    assert_eq!(
        params.validation_hash_canonicalization_version,
        "4MICA_VALIDATION_REQUEST_V2"
    );
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn core_service_public_params_support_max_accepted_guarantee_version_v1() -> anyhow::Result<()>
{
    load_env();
    let ctx = PersistCtx::new().await?;
    let core_service = build_core_service_with_active_version(ctx, 1).await?;
    let params = core_service.public_params();
    assert_eq!(params.max_accepted_guarantee_version, 1);
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial]
async fn contract_api_rejects_disabled_guarantee_version() {
    struct DisabledGuaranteeVersionApi;

    #[async_trait::async_trait]
    impl CoreContractApi for DisabledGuaranteeVersionApi {
        async fn get_chain_id(&self) -> Result<u64, core_service::error::CoreContractApiError> {
            Ok(1)
        }

        async fn get_guarantee_version_config(
            &self,
            version: u64,
        ) -> Result<GuaranteeVersionConfig, core_service::error::CoreContractApiError> {
            Ok(GuaranteeVersionConfig {
                version,
                domain_separator: [0u8; 32],
                decoder: Address::ZERO,
                enabled: false,
            })
        }

        async fn get_tab_expiration_time(
            &self,
        ) -> Result<u64, core_service::error::CoreContractApiError> {
            Ok(3600)
        }

        async fn record_payment(
            &self,
            _tab_id: U256,
            _asset: Address,
            _amount: U256,
        ) -> Result<RecordPaymentTx, core_service::error::CoreContractApiError> {
            Ok(RecordPaymentTx {
                tx_hash: B256::ZERO,
                block_number: None,
                block_hash: None,
            })
        }

        async fn get_supported_tokens(
            &self,
        ) -> Result<Vec<rpc::SupportedTokenInfo>, core_service::error::CoreContractApiError>
        {
            Ok(vec![])
        }
    }

    let api = DisabledGuaranteeVersionApi;
    let err = api
        .get_guarantee_domain_separator()
        .await
        .expect_err("disabled version should fail");
    assert!(matches!(
        err,
        core_service::error::CoreContractApiError::GuaranteeVersionDisabled(1)
    ));
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

    async fn get_guarantee_version_config(
        &self,
        version: u64,
    ) -> Result<GuaranteeVersionConfig, core_service::error::CoreContractApiError> {
        Ok(GuaranteeVersionConfig {
            version,
            domain_separator: self.domain,
            decoder: alloy::primitives::Address::ZERO,
            enabled: true,
        })
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
    ) -> Result<RecordPaymentTx, core_service::error::CoreContractApiError> {
        Ok(RecordPaymentTx {
            tx_hash: B256::ZERO,
            block_number: None,
            block_hash: None,
        })
    }

    async fn get_supported_tokens(
        &self,
    ) -> Result<Vec<rpc::SupportedTokenInfo>, core_service::error::CoreContractApiError> {
        Ok(vec![])
    }
}
