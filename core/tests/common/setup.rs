use std::sync::Arc;

use alloy::providers::{DynProvider, Provider, ProviderBuilder, WalletProvider};
use alloy_primitives::{Address, FixedBytes};
use core_service::{
    config::{AppConfig, EthereumConfig},
    scheduler::TaskScheduler,
    service::{CoreService, payment::ScanPaymentsTask},
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

fn init_config() -> AppConfig {
    dotenv::dotenv().ok();
    // also try parent folder when running from core/tests
    dotenv::from_filename("../.env").ok();
    AppConfig::fetch()
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
    let anvil_port = 40101u16;

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
        number_of_pending_blocks: 1,
        ethereum_private_key: operator_key,
        ..cfg.ethereum_config
    };

    debug!(
        "cron job settings: {}",
        cfg.ethereum_config.cron_job_settings
    );

    let core_service = CoreService::new(cfg).await?;
    clear_all_tables(core_service.persist_ctx()).await?;

    let mut scheduler = TaskScheduler::new().await?;
    scheduler
        .add_task(Arc::new(ScanPaymentsTask::new(core_service.clone())))
        .await?;
    scheduler.start().await?;

    Ok(E2eEnvironment {
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
