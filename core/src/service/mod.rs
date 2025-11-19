use crate::persist::mapper;
use crate::{
    config::{AppConfig, DEFAULT_ASSET_ADDRESS, DEFAULT_TTL_SECS, EthereumConfig},
    error::{ServiceError, ServiceResult},
    ethereum::{CoreContractApi, CoreContractProxy, EthereumListener},
    persist::{IntoUserTxInfo, PersistCtx, repo},
};
use alloy::{
    primitives::U256,
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
};
use anyhow::anyhow;
use entities::sea_orm_active_enums::SettlementStatus;
use log::{error, info};
use parking_lot::Mutex;
use rpc::{
    AssetBalanceInfo, CollateralEventInfo, CorePublicParameters, CreatePaymentTabRequest,
    CreatePaymentTabResult, GuaranteeInfo, PendingRemunerationInfo, TabInfo, UserSuspensionStatus,
    UserTransactionInfo,
};
use std::sync::Arc;
use tokio::{
    task::JoinHandle,
    time::{Duration, sleep},
};

mod api_keys;
pub mod event_handler;
mod guarantee;
pub mod payment;
pub use api_keys::AdminApiKeyScope;

pub struct Inner {
    config: AppConfig,
    bls_private_key: [u8; 32],
    public_params: CorePublicParameters,
    guarantee_domain: [u8; 32],
    persist_ctx: PersistCtx,
    read_provider: DynProvider,
    contract_api: Arc<dyn CoreContractApi>,
    listener_handle: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(handle) = self.listener_handle.lock().take() {
            handle.abort();
        }
    }
}

#[derive(Clone)]
pub struct CoreService {
    inner: Arc<Inner>,
}

impl CoreService {
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        let persist_ctx = PersistCtx::new().await?;
        let eth_cfg = config.ethereum_config.clone();
        let listener_cfg = eth_cfg.clone();

        let contract_api = Arc::new(CoreContractProxy::new(eth_cfg.clone()).await?);

        let actual_chain_id = contract_api
            .get_chain_id()
            .await
            .map_err(|e| anyhow!("failed to get chain id: {e}"))?;
        if actual_chain_id != eth_cfg.chain_id {
            anyhow::bail!(
                "ETHEREUM_CHAIN_ID ({}) does not match node-reported chain id ({actual_chain_id}).",
                eth_cfg.chain_id
            );
        }

        let read_provider = Self::build_ws_provider(eth_cfg.clone()).await?;
        let on_chain_domain = contract_api.get_guarantee_domain_separator().await?;
        info!(
            "on-chain guarantee domain separator: 0x{}",
            crypto::hex::encode_hex(&on_chain_domain)
        );

        let core_service = Self::new_with_dependencies(
            config,
            persist_ctx.clone(),
            contract_api,
            actual_chain_id,
            read_provider.clone(),
            on_chain_domain,
        )?;

        let core_service_clone = core_service.clone();
        tokio::spawn(async move {
            let mut delay = Duration::from_secs(1);
            loop {
                match EthereumListener::new(
                    listener_cfg.clone(),
                    persist_ctx.clone(),
                    read_provider.clone(),
                    Arc::new(core_service_clone.clone()),
                )
                .run()
                .await
                {
                    Ok(handle) => {
                        info!("EthereumListener connected successfully.");
                        core_service_clone
                            .inner
                            .listener_handle
                            .lock()
                            .replace(handle);

                        break;
                    }
                    Err(e) => {
                        error!("EthereumListener error: {e}. Restarting in {delay:?}…");
                        sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(60));
                    }
                }
            }
        });

        Ok(core_service)
    }

    pub fn new_with_dependencies(
        config: AppConfig,
        persist_ctx: PersistCtx,
        contract_api: Arc<dyn CoreContractApi>,
        chain_id: u64,
        read_provider: DynProvider,
        guarantee_domain: [u8; 32],
    ) -> anyhow::Result<Self> {
        let bls_private_key: [u8; 32] = config
            .secrets
            .bls_private_key
            .bytes()
            .try_into()
            .map_err(|_| anyhow!("BLS private key must be 32 bytes"))?;

        let public_key = crypto::bls::pub_key_from_scalar(&bls_private_key)?;
        info!(
            "Operator started with BLS Public Key: {}",
            crypto::hex::encode_hex(&public_key)
        );

        let eip712_name = config.eip712.name.clone();
        let eip712_version = config.eip712.version.clone();
        let eth_config = config.ethereum_config.clone();

        let inner = Inner {
            config,
            bls_private_key,
            public_params: CorePublicParameters {
                public_key,
                contract_address: eth_config.contract_address.clone(),
                ethereum_http_rpc_url: eth_config.http_rpc_url.clone(),
                eip712_name,
                eip712_version,
                chain_id,
            },
            guarantee_domain,
            persist_ctx,
            read_provider,
            contract_api,
            listener_handle: Mutex::default(),
        };

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    fn bls_private_key(&self) -> [u8; 32] {
        self.inner.bls_private_key
    }

    pub fn persist_ctx(&self) -> &PersistCtx {
        &self.inner.persist_ctx
    }

    pub fn public_params(&self) -> CorePublicParameters {
        self.inner.public_params.clone()
    }

    pub fn kill_listener(&self) {
        if let Some(handle) = self.inner.listener_handle.lock().take() {
            handle.abort();
        }
    }

    pub async fn build_ws_provider(config: EthereumConfig) -> ServiceResult<DynProvider> {
        let ws = WsConnect::new(&config.ws_rpc_url);
        let provider = ProviderBuilder::new()
            .connect_ws(ws)
            .await
            .map_err(|err| {
                error!("Failed to connect to Ethereum provider: {err}");
                ServiceError::Other(anyhow!(err))
            })?
            .erased();

        Ok(provider)
    }

    pub async fn create_payment_tab(
        &self,
        req: CreatePaymentTabRequest,
    ) -> ServiceResult<CreatePaymentTabResult> {
        let ttl = req.ttl.unwrap_or(DEFAULT_TTL_SECS);
        let tab_id = crate::util::generate_tab_id(&req.user_address, &req.recipient_address, ttl);

        let now = crate::util::now_naive();
        if now.and_utc().timestamp() < 0 {
            return Err(ServiceError::Other(anyhow!("System time before epoch")));
        }

        let asset_address = req
            .erc20_token
            .clone()
            .unwrap_or(DEFAULT_ASSET_ADDRESS.to_string());

        repo::create_pending_tab(
            &self.inner.persist_ctx,
            tab_id,
            &req.user_address,
            &req.recipient_address,
            &asset_address,
            now,
            ttl as i64,
        )
        .await?;

        Ok(CreatePaymentTabResult {
            id: tab_id,
            user_address: req.user_address,
            recipient_address: req.recipient_address,
            erc20_token: req.erc20_token,
        })
    }

    pub async fn list_tabs_for_recipient(
        &self,
        recipient_address: String,
        settlement_statuses: Vec<SettlementStatus>,
    ) -> ServiceResult<Vec<TabInfo>> {
        let status_refs = if settlement_statuses.is_empty() {
            None
        } else {
            Some(settlement_statuses.as_slice())
        };

        let tabs =
            repo::get_tabs_for_recipient(&self.inner.persist_ctx, &recipient_address, status_refs)
                .await?;

        tabs.into_iter()
            .map(mapper::tab_model_to_info)
            .collect::<ServiceResult<Vec<_>>>()
    }

    pub async fn list_pending_remunerations(
        &self,
        recipient_address: String,
    ) -> ServiceResult<Vec<PendingRemunerationInfo>> {
        let tabs = repo::get_tabs_for_recipient(
            &self.inner.persist_ctx,
            &recipient_address,
            Some(&[SettlementStatus::Pending]),
        )
        .await?;

        let mut items = Vec::with_capacity(tabs.len());
        for tab in tabs {
            let tab_info = mapper::tab_model_to_info(tab)?;
            let latest_guarantee =
                repo::get_last_guarantee_for_tab(&self.inner.persist_ctx, tab_info.tab_id)
                    .await?
                    .map(mapper::guarantee_model_to_info)
                    .transpose()?;

            items.push(PendingRemunerationInfo {
                tab: tab_info,
                latest_guarantee,
            });
        }

        Ok(items)
    }

    pub async fn get_tab(&self, tab_id: U256) -> ServiceResult<Option<TabInfo>> {
        let maybe_tab = repo::get_tab_by_id(&self.inner.persist_ctx, tab_id).await?;
        maybe_tab.map(mapper::tab_model_to_info).transpose()
    }

    pub async fn get_tab_guarantees(&self, tab_id: U256) -> ServiceResult<Vec<GuaranteeInfo>> {
        let rows = repo::get_guarantees_for_tab(&self.inner.persist_ctx, tab_id).await?;
        rows.into_iter()
            .map(mapper::guarantee_model_to_info)
            .collect::<ServiceResult<Vec<_>>>()
    }

    pub async fn get_latest_guarantee(&self, tab_id: U256) -> ServiceResult<Option<GuaranteeInfo>> {
        let maybe = repo::get_last_guarantee_for_tab(&self.inner.persist_ctx, tab_id).await?;
        maybe.map(mapper::guarantee_model_to_info).transpose()
    }

    pub async fn get_guarantee(
        &self,
        tab_id: U256,
        req_id: U256,
    ) -> ServiceResult<Option<GuaranteeInfo>> {
        let maybe = repo::get_guarantee(&self.inner.persist_ctx, tab_id, req_id).await?;
        maybe.map(mapper::guarantee_model_to_info).transpose()
    }

    pub async fn list_recipient_payments(
        &self,
        recipient_address: String,
    ) -> ServiceResult<Vec<UserTransactionInfo>> {
        let rows =
            repo::get_recipient_transactions(&self.inner.persist_ctx, &recipient_address).await?;
        rows.into_iter()
            .map(|row| row.into_user_tx_info())
            .collect::<ServiceResult<Vec<_>>>()
    }

    pub async fn get_collateral_events_for_tab(
        &self,
        tab_id: U256,
    ) -> ServiceResult<Vec<CollateralEventInfo>> {
        let rows = repo::get_collateral_events_for_tab(&self.inner.persist_ctx, tab_id).await?;
        rows.into_iter()
            .map(mapper::collateral_event_model_to_info)
            .collect::<ServiceResult<Vec<_>>>()
    }

    pub async fn get_user_asset_balance(
        &self,
        user_address: String,
        asset_address: String,
    ) -> ServiceResult<Option<AssetBalanceInfo>> {
        let maybe =
            repo::get_user_asset_balance(&self.inner.persist_ctx, &user_address, &asset_address)
                .await?;
        maybe.map(mapper::asset_balance_model_to_info).transpose()
    }

    pub async fn set_user_suspension(
        &self,
        user_address: String,
        suspended: bool,
    ) -> ServiceResult<UserSuspensionStatus> {
        let updated =
            repo::update_user_suspension(&self.inner.persist_ctx, &user_address, suspended).await?;
        Ok(mapper::user_model_to_suspension_status(updated))
    }
}
