use alloy::primitives::U256;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use chrono::{Duration, Utc};
use core_service::{
    config::{AppConfig, DEFAULT_ASSET_ADDRESS, DEFAULT_TTL_SECS},
    ethereum::CoreContractApi,
    persist::{PersistCtx, repo},
    service::{CoreService, CoreServiceDeps},
    util::u256_to_string,
};
use entities::sea_orm_active_enums::{SettlementStatus, TabStatus};
use entities::tabs;
use rand::random;
use rpc::CreatePaymentTabRequest;
use sea_orm::{EntityTrait, Set};
use std::{panic, sync::Arc};

const DEFAULT_TAB_EXPIRATION_TIME: u64 = DEFAULT_TTL_SECS + 60;

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
        ProviderBuilder::new().connect_anvil_with_wallet_and_config(|anvil| anvil.port(40106u16))
    });

    let provider = match provider_res {
        Ok(Ok(p)) => p,
        Ok(Err(err)) => return Err(anyhow::Error::from(err)),
        Err(_) => return Err(anyhow::anyhow!("failed to start anvil provider (panic)")),
    };

    Ok(provider.erased())
}

async fn build_core_service(
    persist_ctx: PersistCtx,
    tab_expiration_time: u64,
) -> anyhow::Result<CoreService> {
    dotenv::dotenv().ok();
    dotenv::from_filename("../.env").ok();
    let config = AppConfig::fetch()?;
    let read_provider = build_read_provider()?;
    let chain_id = read_provider.get_chain_id().await?;

    let contract_api: Arc<dyn CoreContractApi> = Arc::new(MockContractApi {
        chain_id,
        domain: [0u8; 32],
        tab_expiration_time,
    });

    let (_ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    CoreService::new_with_dependencies(
        config,
        CoreServiceDeps {
            persist_ctx,
            contract_api,
            chain_id,
            read_provider,
            guarantee_domain: [0u8; 32],
            tab_expiration_time,
            listener_ready_rx: ready_rx,
        },
    )
}

async fn seed_user(ctx: &PersistCtx, addr: &str) {
    use core_service::persist::repo::users::ensure_user_exists_on;

    ensure_user_exists_on(ctx.db.as_ref(), addr)
        .await
        .expect("seed user");
}

#[tokio::test]
#[serial_test::serial]
async fn returns_existing_pending_tab_when_active() {
    let ctx = match PersistCtx::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("skipping returns_existing_pending_tab_when_active: {err}");
            return;
        }
    };
    let core_service = match build_core_service(ctx.clone(), DEFAULT_TAB_EXPIRATION_TIME).await {
        Ok(cs) => cs,
        Err(err) => {
            eprintln!("skipping returns_existing_pending_tab_when_active: {err}");
            return;
        }
    };

    let user = format!("0x{:040x}", rand::random::<u128>());
    let recipient = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user).await;
    seed_user(&ctx, &recipient).await;

    let first = core_service
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user.clone(),
            recipient_address: recipient.clone(),
            erc20_token: None,
            ttl: Some(600),
        })
        .await
        .expect("first tab");

    // Second request with a different TTL should still reuse the active pending tab.
    let second = core_service
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user.clone(),
            recipient_address: recipient.clone(),
            erc20_token: None,
            ttl: Some(1200),
        })
        .await
        .expect("second tab");

    assert_eq!(first.id, second.id);

    // TTL should remain what the first tab was created with.
    let stored = repo::get_tab_by_id(&ctx, first.id)
        .await
        .expect("tab fetch")
        .expect("tab present");
    assert_eq!(stored.ttl, 600);
    assert_eq!(stored.status, TabStatus::Pending);
    assert_eq!(stored.settlement_status, SettlementStatus::Pending);
}

#[tokio::test]
#[serial_test::serial]
async fn reuses_pending_tab_even_when_expired() {
    let ctx = match PersistCtx::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("skipping creates_new_tab_when_existing_pending_is_expired: {err}");
            return;
        }
    };
    let core_service = match build_core_service(ctx.clone(), DEFAULT_TAB_EXPIRATION_TIME).await {
        Ok(cs) => cs,
        Err(err) => {
            eprintln!("skipping creates_new_tab_when_existing_pending_is_expired: {err}");
            return;
        }
    };

    let user = format!("0x{:040x}", rand::random::<u128>());
    let recipient = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user).await;
    seed_user(&ctx, &recipient).await;

    // Manually seed an expired pending tab.
    let expired_id = U256::from(random::<u128>());
    let expired_ttl = 60i64;
    let expired_start = (Utc::now() - Duration::seconds(expired_ttl + 5)).naive_utc();
    let expired_tab = tabs::ActiveModel {
        id: Set(u256_to_string(expired_id)),
        user_address: Set(user.clone()),
        server_address: Set(recipient.clone()),
        asset_address: Set(DEFAULT_ASSET_ADDRESS.to_string()),
        start_ts: Set(expired_start),
        ttl: Set(expired_ttl),
        status: Set(TabStatus::Pending),
        settlement_status: Set(SettlementStatus::Pending),
        total_amount: Set("0".to_string()),
        paid_amount: Set("0".to_string()),
        created_at: Set(expired_start),
        updated_at: Set(expired_start),
    };
    tabs::Entity::insert(expired_tab)
        .exec(ctx.db.as_ref())
        .await
        .expect("seed expired tab");

    let reused = core_service
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user,
            recipient_address: recipient,
            erc20_token: None,
            ttl: Some(300),
        })
        .await
        .expect("tab reused even if expired");

    assert_eq!(reused.id, expired_id);

    let fetched = repo::get_tab_by_id(&ctx, reused.id)
        .await
        .expect("tab fetch")
        .expect("tab present");
    assert_eq!(fetched.ttl, expired_ttl);
    assert_eq!(fetched.status, TabStatus::Pending);
}

#[tokio::test]
#[serial_test::serial]
async fn uses_default_ttl_when_not_provided() {
    let ctx = match PersistCtx::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("skipping uses_default_ttl_when_not_provided: {err}");
            return;
        }
    };
    let core_service = match build_core_service(ctx.clone(), DEFAULT_TAB_EXPIRATION_TIME).await {
        Ok(cs) => cs,
        Err(err) => {
            eprintln!("skipping uses_default_ttl_when_not_provided: {err}");
            return;
        }
    };

    let user = format!("0x{:040x}", rand::random::<u128>());
    let recipient = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user).await;
    seed_user(&ctx, &recipient).await;

    let tab = core_service
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user.clone(),
            recipient_address: recipient.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await
        .expect("tab with default ttl");

    let stored = repo::get_tab_by_id(&ctx, tab.id)
        .await
        .expect("tab fetch")
        .expect("tab present");
    assert_eq!(stored.ttl, DEFAULT_TTL_SECS as i64);
    assert_eq!(stored.user_address, user);
    assert_eq!(stored.server_address, recipient);
}

#[tokio::test]
#[serial_test::serial]
async fn rejects_ttl_exceeding_tab_expiration() {
    let ctx = match PersistCtx::new().await {
        Ok(ctx) => ctx,
        Err(err) => {
            eprintln!("skipping rejects_ttl_exceeding_tab_expiration: {err}");
            return;
        }
    };
    let core_service = match build_core_service(ctx.clone(), 300).await {
        Ok(cs) => cs,
        Err(err) => {
            eprintln!("skipping rejects_ttl_exceeding_tab_expiration: {err}");
            return;
        }
    };

    let user = format!("0x{:040x}", rand::random::<u128>());
    let recipient = format!("0x{:040x}", rand::random::<u128>());
    seed_user(&ctx, &user).await;
    seed_user(&ctx, &recipient).await;

    let err = core_service
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user,
            recipient_address: recipient,
            erc20_token: None,
            ttl: Some(600),
        })
        .await
        .expect_err("ttl should exceed tab expiration");

    assert!(matches!(
        err,
        core_service::error::ServiceError::InvalidParams(msg)
            if msg.contains("tab expiration time")
    ));
}
