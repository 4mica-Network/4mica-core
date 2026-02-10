use std::{
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

use alloy::providers::{DynProvider, Provider, ProviderBuilder, WalletProvider};
use alloy_primitives::{Address, FixedBytes};
use anyhow::{Context, bail};
use core_service::{
    config::{AppConfig, EthereumConfig},
    persist::PersistCtx,
    scheduler::TaskScheduler,
    service::{
        CoreService,
        payment::{ConfirmPaymentsTask, FinalizePaymentsTask, ScanPaymentsTask},
    },
};
use log::debug;

use crate::common::{
    contract::{
        AccessManager::{self, AccessManagerInstance},
        Core4Mica::{self, Core4MicaInstance},
        MockERC20::{self, MockERC20Instance},
    },
    fixtures::clear_all_tables,
};

pub struct E2eEnvironment {
    cfg: AppConfig,
    pub provider: DynProvider,
    pub access_manager: AccessManagerInstance<DynProvider>,
    pub contract: Core4MicaInstance<DynProvider>,
    pub usdc: MockERC20Instance<DynProvider>,
    pub usdt: MockERC20Instance<DynProvider>,
    pub core_service: CoreService,
    pub scheduler: TaskScheduler,
    pub signer_addr: Address,
}

pub fn dummy_verification_key() -> (
    FixedBytes<32>,
    FixedBytes<32>,
    FixedBytes<32>,
    FixedBytes<32>,
) {
    (
        FixedBytes::<32>::from([0u8; 32]),
        FixedBytes::<32>::from([0u8; 32]),
        FixedBytes::<32>::from([0u8; 32]),
        FixedBytes::<32>::from([0u8; 32]),
    )
}

/// Reserve an unused TCP port for Anvil to bind to.
fn allocate_anvil_port() -> anyhow::Result<u16> {
    // Keep a running counter so concurrent tests do not pick the same ephemeral port.
    static NEXT_PORT: AtomicU16 = AtomicU16::new(40101);

    for _ in 0..200 {
        let candidate = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let listener = match TcpListener::bind(("127.0.0.1", candidate)) {
            Ok(listener) => listener,
            Err(_) => continue, // try the next port
        };

        let port = listener
            .local_addr()
            .context("failed to read reserved anvil port")?
            .port();
        drop(listener); // free the port so Anvil can take it
        return Ok(port);
    }

    bail!("could not allocate a free port for Anvil")
}

fn init_config() -> AppConfig {
    dotenv::dotenv().ok();
    // also try parent folder when running from core/tests
    dotenv::from_filename("../.env").ok();
    AppConfig::fetch().expect("Failed to load test config")
}

async fn deploy_contracts(
    provider: DynProvider,
    admin_addr: Address,
) -> anyhow::Result<(
    Core4MicaInstance<DynProvider>,
    MockERC20Instance<DynProvider>,
    MockERC20Instance<DynProvider>,
    AccessManagerInstance<DynProvider>,
)> {
    let access_manager = AccessManager::deploy(provider.clone(), admin_addr).await?;

    let usdc =
        MockERC20::deploy(provider.clone(), "USD Coin".to_string(), "USDC".to_string()).await?;
    let usdt = MockERC20::deploy(
        provider.clone(),
        "Tether USD".to_string(),
        "USDT".to_string(),
    )
    .await?;

    let contract = Core4Mica::deploy(
        provider.clone(),
        *access_manager.address(),
        dummy_verification_key(),
        *usdc.address(),
        *usdt.address(),
    )
    .await?;

    debug!(
        "Contracts deployed: \n\tcore_4mica={:?}\n\tusdc={:?}\n\tusdt={:?}\n\taccess_manager={:?}",
        contract.address(),
        usdc.address(),
        usdt.address(),
        access_manager.address()
    );

    Ok((contract, usdc, usdt, access_manager))
}

pub async fn setup_e2e_environment() -> anyhow::Result<E2eEnvironment> {
    let mut cfg = init_config();
    let anvil_port = allocate_anvil_port()?;

    let provider = ProviderBuilder::new()
        .connect_anvil_with_wallet_and_config(|anvil| anvil.port(anvil_port))?;
    let signer_addr = provider.default_signer_address();
    let provider = provider.erased();

    let (contract, usdc, usdt, access_manager) =
        deploy_contracts(provider.clone(), signer_addr).await?;

    let operator_key =
        String::from("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    cfg.ethereum_config = EthereumConfig {
        chain_id: provider.get_chain_id().await?,
        contract_address: contract.address().to_string(),
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        cron_job_settings: "*/2 * * * * *".to_string(),
        number_of_blocks_to_confirm: 1, // faster confirmations for tests
        confirmation_mode: "depth".to_string(),
        number_of_pending_blocks: 1,
        ethereum_private_key: operator_key,
    };

    debug!(
        "cron job settings: {}",
        cfg.ethereum_config.cron_job_settings
    );

    // It's important to clear the tables before the core service starts,
    //   otherwise the listener may see a populated blockchain_event table.
    let persist_ctx = PersistCtx::new().await?;
    clear_all_tables(&persist_ctx).await?;
    let core_service = CoreService::new(cfg.clone()).await?;
    core_service.wait_for_listener_ready().await?;

    let mut scheduler = TaskScheduler::new().await?;
    scheduler
        .add_task(Arc::new(ScanPaymentsTask::new(core_service.clone())))
        .await?;
    scheduler
        .add_task(Arc::new(ConfirmPaymentsTask::new(core_service.clone())))
        .await?;
    scheduler
        .add_task(Arc::new(FinalizePaymentsTask::new(core_service.clone())))
        .await?;
    scheduler.start().await?;

    Ok(E2eEnvironment {
        cfg,
        provider,
        access_manager,
        contract,
        usdc,
        usdt,
        core_service,
        scheduler,
        signer_addr,
    })
}

pub async fn spawn_core_service_in_existing_environment(
    env: &mut E2eEnvironment,
) -> anyhow::Result<CoreService> {
    let core_service = CoreService::new(env.cfg.clone()).await?;
    core_service.wait_for_listener_ready().await?;

    env.core_service = core_service.clone();

    Ok(core_service)
}
