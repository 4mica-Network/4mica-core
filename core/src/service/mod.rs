use crate::{
    config::{AppConfig, DEFAULT_ASSET_ADDRESS, DEFAULT_TTL_SECS, EthereumConfig},
    error::{ServiceError, ServiceResult, service_error_to_rpc},
    ethereum::{CoreContractApi, CoreContractProxy, EthereumListener},
    persist::{IntoUserTxInfo, PersistCtx, repo},
};
use alloy::{
    primitives::U256,
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
};
use anyhow::anyhow;
use async_trait::async_trait;
use crypto::bls::BLSCert;
use entities::{
    sea_orm_active_enums::{CollateralEventType, SettlementStatus, TabStatus},
    tabs,
};
use log::{error, info};
use parking_lot::Mutex;
use rpc::{
    RpcResult,
    common::*,
    core::{CoreApiServer, CorePublicParameters},
};
use std::str::FromStr;
use std::sync::Arc;
use tokio::{
    task::JoinHandle,
    time::{Duration, sleep},
};

pub mod event_handler;
mod guarantee;
pub mod payment;

pub struct Inner {
    config: AppConfig,
    public_params: CorePublicParameters,
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
        if config.secrets.bls_private_key.bytes().len() != 32 {
            anyhow::bail!("BLS private key must be 32 bytes");
        }

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
        crypto::guarantee::set_guarantee_domain_separator(on_chain_domain)
            .map_err(|e| anyhow!("failed to set guarantee domain: {e}"))?;

        let core_service = Self::new_with_dependencies(
            config,
            persist_ctx.clone(),
            contract_api,
            actual_chain_id,
            read_provider.clone(),
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
    ) -> anyhow::Result<Self> {
        let bls_private_key = config.secrets.bls_private_key.bytes();
        if bls_private_key.len() != 32 {
            anyhow::bail!("BLS private key must be 32 bytes");
        }

        let public_key = crypto::bls::pub_key_from_scalar(bls_private_key.try_into()?)?;
        info!(
            "Operator started with BLS Public Key: {}",
            crypto::hex::encode_hex(&public_key)
        );

        let eip712_name = config.eip712.name.clone();
        let eip712_version = config.eip712.version.clone();
        let eth_config = config.ethereum_config.clone();

        let inner = Inner {
            config,
            public_params: CorePublicParameters {
                public_key,
                contract_address: eth_config.contract_address.clone(),
                ethereum_http_rpc_url: eth_config.http_rpc_url.clone(),
                eip712_name,
                eip712_version,
                chain_id,
            },
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
        self.inner
            .config
            .secrets
            .bls_private_key
            .bytes()
            .try_into()
            .expect("BLS private key must be 32 bytes")
    }

    pub fn persist_ctx(&self) -> &PersistCtx {
        &self.inner.persist_ctx
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

    async fn create_payment_tab(
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

    fn tab_model_to_info(tab: tabs::Model) -> ServiceResult<TabInfo> {
        let tab_id = U256::from_str(&tab.id)
            .map_err(|e| ServiceError::Other(anyhow!("invalid tab id {}: {e}", tab.id)))?;
        let status = match tab.status {
            TabStatus::Pending => "PENDING",
            TabStatus::Open => "OPEN",
            TabStatus::Closed => "CLOSED",
        }
        .to_string();
        let settlement_status = match tab.settlement_status {
            SettlementStatus::Pending => "PENDING",
            SettlementStatus::Settled => "SETTLED",
            SettlementStatus::Failed => "FAILED",
            SettlementStatus::Remunerated => "REMUNERATED",
        }
        .to_string();
        let start_timestamp = tab.start_ts.and_utc().timestamp();
        let created_at = tab.created_at.and_utc().timestamp();
        let updated_at = tab.updated_at.and_utc().timestamp();

        Ok(TabInfo {
            tab_id,
            user_address: tab.user_address,
            recipient_address: tab.server_address,
            asset_address: tab.asset_address,
            start_timestamp,
            ttl_seconds: tab.ttl,
            status,
            settlement_status,
            created_at,
            updated_at,
        })
    }

    fn guarantee_model_to_info(model: entities::guarantee::Model) -> ServiceResult<GuaranteeInfo> {
        let entities::guarantee::Model {
            tab_id: tab_id_str,
            req_id: req_id_str,
            from_address,
            to_address,
            asset_address,
            value,
            start_ts,
            cert,
            ..
        } = model;

        let tab_id = U256::from_str(&tab_id_str)
            .map_err(|e| ServiceError::Other(anyhow!("invalid tab id {}: {e}", tab_id_str)))?;
        let req_id = U256::from_str(&req_id_str)
            .map_err(|e| ServiceError::Other(anyhow!("invalid req id {}: {e}", req_id_str)))?;
        let amount = U256::from_str(&value)
            .map_err(|e| ServiceError::Other(anyhow!("invalid guarantee amount {}: {e}", value)))?;
        let start_timestamp = start_ts.and_utc().timestamp();
        let certificate = if cert.is_empty() { None } else { Some(cert) };

        Ok(GuaranteeInfo {
            tab_id,
            req_id,
            from_address,
            to_address,
            asset_address,
            amount,
            start_timestamp,
            certificate,
        })
    }

    fn collateral_event_type_to_str(t: CollateralEventType) -> &'static str {
        match t {
            CollateralEventType::Deposit => "DEPOSIT",
            CollateralEventType::Withdraw => "WITHDRAW",
            CollateralEventType::Reserve => "RESERVE",
            CollateralEventType::CancelReserve => "CANCEL_RESERVE",
            CollateralEventType::Unlock => "UNLOCK",
            CollateralEventType::Remunerate => "REMUNERATE",
        }
    }

    fn collateral_event_model_to_info(
        model: entities::collateral_event::Model,
    ) -> ServiceResult<CollateralEventInfo> {
        let amount = U256::from_str(&model.amount).map_err(|e| {
            ServiceError::Other(anyhow!(
                "invalid collateral event amount {}: {e}",
                model.amount
            ))
        })?;

        let tab_id = match model.tab_id {
            Some(ref id) => Some(U256::from_str(id).map_err(|e| {
                ServiceError::Other(anyhow!("invalid collateral event tab id {}: {e}", id))
            })?),
            None => None,
        };

        let req_id = match model.req_id {
            Some(ref id) => Some(U256::from_str(id).map_err(|e| {
                ServiceError::Other(anyhow!("invalid collateral event req id {}: {e}", id))
            })?),
            None => None,
        };

        Ok(CollateralEventInfo {
            id: model.id,
            user_address: model.user_address,
            asset_address: model.asset_address,
            amount,
            event_type: Self::collateral_event_type_to_str(model.event_type).to_string(),
            tab_id,
            req_id,
            tx_id: model.tx_id,
            created_at: model.created_at.and_utc().timestamp(),
        })
    }

    fn asset_balance_model_to_info(
        model: entities::user_asset_balance::Model,
    ) -> ServiceResult<AssetBalanceInfo> {
        let total = U256::from_str(&model.total).map_err(|e| {
            ServiceError::Other(anyhow!("invalid asset balance total {}: {e}", model.total))
        })?;
        let locked = U256::from_str(&model.locked).map_err(|e| {
            ServiceError::Other(anyhow!(
                "invalid asset balance locked {}: {e}",
                model.locked
            ))
        })?;

        Ok(AssetBalanceInfo {
            user_address: model.user_address,
            asset_address: model.asset_address,
            total,
            locked,
            version: model.version,
            updated_at: model.updated_at.and_utc().timestamp(),
        })
    }

    fn parse_settlement_statuses(
        statuses: Option<Vec<String>>,
    ) -> ServiceResult<Vec<SettlementStatus>> {
        fn parse_one(value: &str) -> Option<SettlementStatus> {
            match value.to_ascii_uppercase().as_str() {
                "PENDING" => Some(SettlementStatus::Pending),
                "SETTLED" => Some(SettlementStatus::Settled),
                "FAILED" => Some(SettlementStatus::Failed),
                "REMUNERATED" => Some(SettlementStatus::Remunerated),
                _ => None,
            }
        }

        match statuses {
            Some(values) => {
                let mut parsed = Vec::with_capacity(values.len());
                for value in values {
                    match parse_one(&value) {
                        Some(status) => parsed.push(status),
                        None => {
                            return Err(ServiceError::InvalidParams(format!(
                                "invalid settlement status: {}",
                                value
                            )));
                        }
                    }
                }
                Ok(parsed)
            }
            None => Ok(Vec::new()),
        }
    }

    async fn list_tabs_for_recipient(
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
            .map(Self::tab_model_to_info)
            .collect::<ServiceResult<Vec<_>>>()
    }

    async fn list_pending_remunerations_internal(
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
            let tab_info = Self::tab_model_to_info(tab)?;
            let latest_guarantee =
                repo::get_last_guarantee_for_tab(&self.inner.persist_ctx, tab_info.tab_id)
                    .await?
                    .map(Self::guarantee_model_to_info)
                    .transpose()?;

            items.push(PendingRemunerationInfo {
                tab: tab_info,
                latest_guarantee,
            });
        }

        Ok(items)
    }

    async fn get_tab_info(&self, tab_id: U256) -> ServiceResult<Option<TabInfo>> {
        let maybe_tab = repo::get_tab_by_id(&self.inner.persist_ctx, tab_id).await?;
        maybe_tab.map(Self::tab_model_to_info).transpose()
    }

    async fn get_tab_guarantees_internal(&self, tab_id: U256) -> ServiceResult<Vec<GuaranteeInfo>> {
        let rows = repo::get_guarantees_for_tab(&self.inner.persist_ctx, tab_id).await?;
        rows.into_iter()
            .map(Self::guarantee_model_to_info)
            .collect::<ServiceResult<Vec<_>>>()
    }

    async fn get_latest_guarantee_internal(
        &self,
        tab_id: U256,
    ) -> ServiceResult<Option<GuaranteeInfo>> {
        let maybe = repo::get_last_guarantee_for_tab(&self.inner.persist_ctx, tab_id).await?;
        maybe.map(Self::guarantee_model_to_info).transpose()
    }

    async fn get_specific_guarantee_internal(
        &self,
        tab_id: U256,
        req_id: U256,
    ) -> ServiceResult<Option<GuaranteeInfo>> {
        let maybe = repo::get_guarantee(&self.inner.persist_ctx, tab_id, req_id).await?;
        maybe.map(Self::guarantee_model_to_info).transpose()
    }

    async fn list_recipient_payments_internal(
        &self,
        recipient_address: String,
    ) -> ServiceResult<Vec<UserTransactionInfo>> {
        let rows =
            repo::get_recipient_transactions(&self.inner.persist_ctx, &recipient_address).await?;
        Ok(rows
            .into_iter()
            .map(|row| row.into_user_tx_info())
            .collect())
    }

    async fn get_collateral_events_for_tab_internal(
        &self,
        tab_id: U256,
    ) -> ServiceResult<Vec<CollateralEventInfo>> {
        let rows = repo::get_collateral_events_for_tab(&self.inner.persist_ctx, tab_id).await?;
        rows.into_iter()
            .map(Self::collateral_event_model_to_info)
            .collect::<ServiceResult<Vec<_>>>()
    }

    async fn get_user_asset_balance_internal(
        &self,
        user_address: String,
        asset_address: String,
    ) -> ServiceResult<Option<AssetBalanceInfo>> {
        let maybe =
            repo::get_user_asset_balance(&self.inner.persist_ctx, &user_address, &asset_address)
                .await?;
        maybe.map(Self::asset_balance_model_to_info).transpose()
    }
}

#[async_trait]
impl CoreApiServer for CoreService {
    async fn get_public_params(&self) -> RpcResult<CorePublicParameters> {
        Ok(self.inner.public_params.clone())
    }

    async fn issue_guarantee(&self, req: PaymentGuaranteeRequest) -> RpcResult<BLSCert> {
        self.handle_promise(req).await.map_err(service_error_to_rpc)
    }

    async fn create_payment_tab(
        &self,
        req: CreatePaymentTabRequest,
    ) -> RpcResult<CreatePaymentTabResult> {
        self.create_payment_tab(req)
            .await
            .map_err(service_error_to_rpc)
    }

    async fn list_settled_tabs(&self, recipient_address: String) -> RpcResult<Vec<TabInfo>> {
        self.list_tabs_for_recipient(recipient_address, vec![SettlementStatus::Settled])
            .await
            .map_err(service_error_to_rpc)
    }

    async fn list_pending_remunerations(
        &self,
        recipient_address: String,
    ) -> RpcResult<Vec<PendingRemunerationInfo>> {
        self.list_pending_remunerations_internal(recipient_address)
            .await
            .map_err(service_error_to_rpc)
    }

    async fn get_tab(&self, tab_id: U256) -> RpcResult<Option<TabInfo>> {
        self.get_tab_info(tab_id)
            .await
            .map_err(service_error_to_rpc)
    }

    async fn list_recipient_tabs(
        &self,
        recipient_address: String,
        settlement_statuses: Option<Vec<String>>,
    ) -> RpcResult<Vec<TabInfo>> {
        let parsed =
            Self::parse_settlement_statuses(settlement_statuses).map_err(service_error_to_rpc)?;
        self.list_tabs_for_recipient(recipient_address, parsed)
            .await
            .map_err(service_error_to_rpc)
    }

    async fn get_tab_guarantees(&self, tab_id: U256) -> RpcResult<Vec<GuaranteeInfo>> {
        self.get_tab_guarantees_internal(tab_id)
            .await
            .map_err(service_error_to_rpc)
    }

    async fn get_latest_guarantee(&self, tab_id: U256) -> RpcResult<Option<GuaranteeInfo>> {
        self.get_latest_guarantee_internal(tab_id)
            .await
            .map_err(service_error_to_rpc)
    }

    async fn get_guarantee(&self, tab_id: U256, req_id: U256) -> RpcResult<Option<GuaranteeInfo>> {
        self.get_specific_guarantee_internal(tab_id, req_id)
            .await
            .map_err(service_error_to_rpc)
    }

    async fn list_recipient_payments(
        &self,
        recipient_address: String,
    ) -> RpcResult<Vec<UserTransactionInfo>> {
        self.list_recipient_payments_internal(recipient_address)
            .await
            .map_err(service_error_to_rpc)
    }

    async fn get_collateral_events_for_tab(
        &self,
        tab_id: U256,
    ) -> RpcResult<Vec<CollateralEventInfo>> {
        self.get_collateral_events_for_tab_internal(tab_id)
            .await
            .map_err(service_error_to_rpc)
    }

    async fn get_user_asset_balance(
        &self,
        user_address: String,
        asset_address: String,
    ) -> RpcResult<Option<AssetBalanceInfo>> {
        self.get_user_asset_balance_internal(user_address, asset_address)
            .await
            .map_err(service_error_to_rpc)
    }
}
