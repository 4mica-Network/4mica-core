use alloy::primitives::U256;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use chrono::{Duration, Utc};
use core_service::{
    config::{AppConfig, DEFAULT_ASSET_ADDRESS},
    ethereum::CoreContractApi,
    persist::{PersistCtx, repo},
    service::CoreService,
    util::u256_to_string,
};
use entities::sea_orm_active_enums::{SettlementStatus, TabStatus};
use rand::random;
use rpc::PaymentGuaranteeRequestClaimsV1;
use sea_orm::{ActiveValue::Set, EntityTrait};
use std::{
    panic,
    sync::{Arc, Once},
};

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
    });

    let core_service = CoreService::new_with_dependencies(
        config,
        persist_ctx,
        contract_api,
        chain_id,
        read_provider,
        [0u8; 32],
    )?;
    Ok(core_service)
}

async fn seed_user(ctx: &PersistCtx, addr: &str) {
    use core_service::persist::repo::users::ensure_user_exists_on;

    ensure_user_exists_on(ctx.db.as_ref(), addr)
        .await
        .expect("seed user");
}

async fn insert_pending_tab(
    ctx: &PersistCtx,
    tab_id: U256,
    user_address: String,
    recipient_address: String,
    start_ts: chrono::NaiveDateTime,
    ttl: i64,
) {
    let now = Utc::now().naive_utc();
    let tab = entities::tabs::ActiveModel {
        id: Set(u256_to_string(tab_id)),
        user_address: Set(user_address),
        server_address: Set(recipient_address),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(start_ts),
        ttl: Set(ttl),
        status: Set(TabStatus::Pending),
        settlement_status: Set(SettlementStatus::Pending),
        created_at: Set(now),
        updated_at: Set(now),
    };

    entities::tabs::Entity::insert(tab)
        .exec(ctx.db.as_ref())
        .await
        .expect("insert tab");
}

fn build_claims(
    tab_id: U256,
    user_address: String,
    recipient_address: String,
    timestamp: u64,
) -> PaymentGuaranteeRequestClaimsV1 {
    PaymentGuaranteeRequestClaimsV1 {
        tab_id,
        user_address,
        recipient_address,
        asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        amount: U256::from(1u64),
        timestamp,
    }
}

#[tokio::test]
async fn accepts_timestamp_within_tab_window() {
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
    let claims = build_claims(tab_id, user_addr, recipient_addr, claims_ts);

    let req_id = core_service
        .verify_guarantee_request_claims_v1(&claims)
        .await
        .expect("claims should be valid");
    assert_eq!(req_id, U256::ZERO);

    let tab = repo::get_tab_by_id(&ctx, tab_id)
        .await
        .expect("tab fetch")
        .expect("tab exists");
    assert_eq!(tab.status, TabStatus::Open);
    assert_eq!(tab.start_ts.and_utc().timestamp(), claims_ts as i64);
}

#[tokio::test]
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

    let before_start = (start_ts - Duration::seconds(1)).and_utc().timestamp() as u64;
    let claims = build_claims(
        tab_id,
        user_addr.clone(),
        recipient_addr.clone(),
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
    let claims = build_claims(tab_id, user_addr, recipient_addr, after_expiry);
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
    assert_eq!(tab.status, TabStatus::Pending);
    assert_eq!(
        tab.start_ts.and_utc().timestamp(),
        start_ts.and_utc().timestamp()
    );
}
