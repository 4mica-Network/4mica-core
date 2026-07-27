//! On-chain (anvil) test harness: deploys the full contract stack, runs the
//! event scanner, and provides chain interaction helpers shared by the
//! `chain_*.rs` test files.

use std::{net::TcpListener, str::FromStr, sync::Arc};

use alloy::network::EthereumWallet;
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::{FixedBytes, U256, keccak256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use alloy_primitives::Address;
use anyhow::Context;
use core_service::{
    config::{AppConfig, EthereumConfig},
    ethereum::EthereumEventScanner,
    persist::PersistCtx,
    scheduler::TaskScheduler,
    service::CoreService,
};
use log::debug;

use super::contract::{
    AccessManager::{self, AccessManagerInstance},
    ClearingHouse::{self, ClearingHouseInstance},
    Core4Mica::{self, Core4MicaInstance},
    MockAToken, MockAavePool, MockAaveProtocolDataProvider,
    MockERC20::{self, MockERC20Instance},
    MockPoolAddressesProvider,
};
use super::db::{clear_all_tables, ensure_migrations};

pub const OPERATOR_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Depth the test scanner subtracts from the latest block to reach its confirmed
/// head (`CONFIRMATION_MODE=depth`, `NUMBER_OF_BLOCKS_TO_CONFIRM`). Shared by the
/// scanner config and `mine_confirmations` so they never drift out of sync.
pub const TEST_CONFIRMATION_DEPTH: u64 = 1;

pub struct E2eEnvironment {
    pub cfg: AppConfig,
    pub provider: DynProvider,
    _anvil: AnvilInstance,
    pub access_manager: AccessManagerInstance<DynProvider>,
    pub contract: Core4MicaInstance<DynProvider>,
    pub clearing_house: ClearingHouseInstance<DynProvider>,
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

/// Build an HTTP provider that signs as `key`, returning its address too.
pub fn wallet_provider(http_url: &str, key: &str) -> anyhow::Result<(Address, DynProvider)> {
    let signer = PrivateKeySigner::from_str(key)?;
    let address = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(http_url.parse()?)
        .erased();
    Ok((address, provider))
}

/// Compute a 4-byte function selector from a signature string.
pub fn fn_selector(sig: &str) -> FixedBytes<4> {
    let h = keccak256(sig.as_bytes());
    FixedBytes::<4>::from([h[0], h[1], h[2], h[3]])
}

/// Mine `blocks` confirmations (plus the depth the scanner subtracts to reach its
/// confirmed head) so the event scanner observes confirmed state.
pub async fn mine_confirmations(provider: &DynProvider, blocks: u64) -> anyhow::Result<()> {
    let total = blocks.saturating_add(TEST_CONFIRMATION_DEPTH);
    if total > 0 {
        provider.anvil_mine(Some(total), None).await?;
    }
    Ok(())
}

/// Mint a MockERC20 balance to the signer, approve Core4Mica, and deposit it as
/// stablecoin collateral. Returns once the deposit tx is mined (not yet
/// confirmed — call `mine_confirmations` to surface it to the scanner).
pub async fn deposit_stablecoin(
    env: &E2eEnvironment,
    token: &MockERC20Instance<DynProvider>,
    amount: U256,
) -> anyhow::Result<()> {
    token
        .mint(env.signer_addr, amount)
        .send()
        .await?
        .watch()
        .await?;
    token
        .approve(*env.contract.address(), amount)
        .send()
        .await?
        .watch()
        .await?;
    env.contract
        .depositStablecoin(*token.address(), amount)
        .send()
        .await?
        .watch()
        .await?;
    Ok(())
}

/// Reserve an unused TCP port for Anvil to bind to.
fn allocate_anvil_port() -> anyhow::Result<u16> {
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).context("failed to reserve ephemeral anvil port")?;
    let port = listener
        .local_addr()
        .context("failed to read reserved anvil port")?
        .port();
    drop(listener); // free the port so Anvil can take it
    Ok(port)
}

fn init_config() -> AppConfig {
    let operator_key = String::from(OPERATOR_KEY);
    let eth_env_key = "ETHEREUM_PRIVATE_KEY";

    dotenv::dotenv().ok();
    // also try parent folder when running from core/tests
    dotenv::from_filename("../.env").ok();

    unsafe {
        std::env::set_var(eth_env_key, operator_key);
    }
    AppConfig::fetch().expect("Failed to load test config")
}

fn force_local_e2e_guarantee_defaults(cfg: &mut AppConfig) {
    // These tests deploy a fresh Core4Mica with no validators, so a developer's env must not
    // leak a whitelist the local chain cannot serve.
    cfg.guarantee.validators = "[]".to_string();
    // No shortfall grace window in tests: drive an under-funded cycle terminal immediately so
    // the Shortfall path is exercised deterministically without advancing wall-clock time.
    cfg.settlement_cycle.shortfall_grace_secs = 0;
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
    let mock_pool = MockAavePool::deploy(provider.clone()).await?;
    let mock_data_provider = MockAaveProtocolDataProvider::deploy(provider.clone()).await?;
    let mock_provider = MockPoolAddressesProvider::deploy(provider.clone()).await?;
    let mock_usdc_a_token = MockAToken::deploy(
        provider.clone(),
        *usdc.address(),
        *mock_pool.address(),
        "Aave USDC".to_string(),
        "aUSDC".to_string(),
    )
    .await?;
    let mock_usdt_a_token = MockAToken::deploy(
        provider.clone(),
        *usdt.address(),
        *mock_pool.address(),
        "Aave USDT".to_string(),
        "aUSDT".to_string(),
    )
    .await?;
    let initial_index = U256::from_str_radix("1000000000000000000000000000", 10)?;

    mock_pool
        .setReserve(*usdc.address(), *mock_usdc_a_token.address(), initial_index)
        .send()
        .await?
        .watch()
        .await?;
    mock_pool
        .setReserve(*usdt.address(), *mock_usdt_a_token.address(), initial_index)
        .send()
        .await?
        .watch()
        .await?;
    mock_data_provider
        .setReserveAToken(*usdc.address(), *mock_usdc_a_token.address())
        .send()
        .await?
        .watch()
        .await?;
    mock_data_provider
        .setReserveAToken(*usdt.address(), *mock_usdt_a_token.address())
        .send()
        .await?
        .watch()
        .await?;
    mock_provider
        .setPool(*mock_pool.address())
        .send()
        .await?
        .watch()
        .await?;
    mock_provider
        .setPoolDataProvider(*mock_data_provider.address())
        .send()
        .await?
        .watch()
        .await?;

    let stablecoins = vec![*usdc.address(), *usdt.address()];
    let contract = Core4Mica::deploy(
        provider.clone(),
        *access_manager.address(),
        dummy_verification_key(),
        stablecoins,
    )
    .await?;
    let a_tokens = vec![*mock_usdc_a_token.address(), *mock_usdt_a_token.address()];
    contract
        .configureAave(*mock_provider.address(), a_tokens)
        .send()
        .await?
        .watch()
        .await?;

    debug!(
        "Contracts deployed: \n\tcore_4mica={:?}\n\tusdc={:?}\n\tusdt={:?}\n\taccess_manager={:?}\n\tmock_pool={:?}\n\tmock_provider={:?}",
        contract.address(),
        usdc.address(),
        usdt.address(),
        access_manager.address(),
        mock_pool.address(),
        mock_provider.address()
    );

    Ok((contract, usdc, usdt, access_manager))
}

/// Deploy the ClearingHouse and grant the operator role to `operator` (the test
/// signer, which is also the core service's transaction wallet) so it can commit
/// cycles and settle defaults through the `restricted` entry points.
async fn deploy_clearing_house(
    provider: DynProvider,
    access_manager: &AccessManagerInstance<DynProvider>,
    core4mica: &Core4MicaInstance<DynProvider>,
    operator: Address,
) -> anyhow::Result<ClearingHouseInstance<DynProvider>> {
    const OPERATOR_ROLE: u64 = 9;
    const CLEARING_HOUSE_ROLE: u64 = 10;

    let clearing_house =
        ClearingHouse::deploy(provider, *access_manager.address(), *core4mica.address())
            .await
            .context("ClearingHouse::deploy")?;

    let selectors = vec![
        FixedBytes::<4>::from(ClearingHouse::commitCycleCall::SELECTOR),
        FixedBytes::<4>::from(ClearingHouse::settleDefaultsFromCollateralBatchCall::SELECTOR),
        FixedBytes::<4>::from(ClearingHouse::fundCreditorsFromPoolBatchCall::SELECTOR),
        FixedBytes::<4>::from(ClearingHouse::markCycleShortfallCall::SELECTOR),
    ];
    access_manager
        .setTargetFunctionRole(*clearing_house.address(), selectors, OPERATOR_ROLE)
        .send()
        .await
        .context("setTargetFunctionRole send")?
        .watch()
        .await
        .context("setTargetFunctionRole confirm")?;
    access_manager
        .grantRole(OPERATOR_ROLE, operator, 0)
        .send()
        .await
        .context("grantRole send")?
        .watch()
        .await
        .context("grantRole confirm")?;

    // Let the ClearingHouse move collateral inside Core4Mica during settlement.
    let collateral_selectors = vec![
        FixedBytes::<4>::from(Core4Mica::seizeCollateralCall::SELECTOR),
        FixedBytes::<4>::from(Core4Mica::seizeUpToCall::SELECTOR),
        FixedBytes::<4>::from(Core4Mica::creditCollateralCall::SELECTOR),
        FixedBytes::<4>::from(Core4Mica::depositToEscrowCall::SELECTOR),
        FixedBytes::<4>::from(Core4Mica::creditFromEscrowScaledCall::SELECTOR),
        FixedBytes::<4>::from(Core4Mica::withdrawFromEscrowCall::SELECTOR),
    ];
    access_manager
        .setTargetFunctionRole(
            *core4mica.address(),
            collateral_selectors,
            CLEARING_HOUSE_ROLE,
        )
        .send()
        .await
        .context("setTargetFunctionRole(core4mica) send")?
        .watch()
        .await
        .context("setTargetFunctionRole(core4mica) confirm")?;
    access_manager
        .grantRole(CLEARING_HOUSE_ROLE, *clearing_house.address(), 0)
        .send()
        .await
        .context("grantRole(clearing_house) send")?
        .watch()
        .await
        .context("grantRole(clearing_house) confirm")?;

    Ok(clearing_house)
}

pub async fn setup_e2e_environment() -> anyhow::Result<E2eEnvironment> {
    let mut cfg = init_config();
    force_local_e2e_guarantee_defaults(&mut cfg);
    let anvil_port = allocate_anvil_port()?;

    let anvil = Anvil::new().port(anvil_port).spawn();
    let (op_addr, op_provider) = wallet_provider(anvil.endpoint_url().as_str(), OPERATOR_KEY)?;

    let (contract, usdc, usdt, access_manager) =
        deploy_contracts(op_provider.clone(), op_addr).await?;
    let clearing_house =
        deploy_clearing_house(op_provider.clone(), &access_manager, &contract, op_addr).await?;

    cfg.ethereum_config = EthereumConfig {
        chain_id: op_provider.get_chain_id().await?,
        contract_address: contract.address().to_string(),
        clearing_house_address: clearing_house.address().to_string(),
        ws_rpc_url: format!("ws://localhost:{anvil_port}"),
        http_rpc_url: format!("http://localhost:{anvil_port}"),
        public_http_rpc_url: format!("http://localhost:{anvil_port}"),
        cron_job_settings: "* * * * * *".to_string(),
        event_scanner_cron: "* * * * * *".to_string(),
        // The anvil harness has no real finalized head, so it uses depth-based
        // confirmation (treating latest-N blocks as confirmed). That reorg-able
        // mode is acceptable in tests only; production requires `finalized`.
        confirmation_mode: "depth".to_string(),
        number_of_blocks_to_confirm: TEST_CONFIRMATION_DEPTH,
        payment_scan_lookback_blocks: 1,
        payment_legacy_scan_enabled: false,
        initial_event_scan_lookback_blocks: 10,
        max_log_block_range: 10_000,
        event_handler_max_retries: 5,
        event_handler_retry_base_delay_ms: 200,
    };

    debug!(
        "cron job settings: {}",
        cfg.ethereum_config.cron_job_settings
    );

    let persist_ctx = PersistCtx::new().await?;
    ensure_migrations(&persist_ctx).await?;
    clear_all_tables(&persist_ctx).await?;
    let core_service = CoreService::new(cfg.clone()).await?;

    let ethereum_scanner = Arc::new(EthereumEventScanner::new(
        cfg.ethereum_config.clone(),
        core_service.persist_ctx().clone(),
        core_service.read_provider().clone(),
        Arc::new(core_service.clone()),
    ));

    let mut scheduler = TaskScheduler::new().await?;
    scheduler.add_task(ethereum_scanner).await?;
    scheduler.start().await?;

    Ok(E2eEnvironment {
        cfg,
        provider: op_provider,
        _anvil: anvil,
        access_manager,
        contract,
        clearing_house,
        usdc,
        usdt,
        core_service,
        scheduler,
        signer_addr: op_addr,
    })
}

pub async fn spawn_core_service_in_existing_environment(
    env: &mut E2eEnvironment,
) -> anyhow::Result<CoreService> {
    let core_service = CoreService::new(env.cfg.clone()).await?;

    let ethereum_scanner = Arc::new(EthereumEventScanner::new(
        env.cfg.ethereum_config.clone(),
        core_service.persist_ctx().clone(),
        core_service.read_provider().clone(),
        Arc::new(core_service.clone()),
    ));

    env.scheduler.add_task(ethereum_scanner).await?;
    env.core_service = core_service.clone();

    Ok(core_service)
}
