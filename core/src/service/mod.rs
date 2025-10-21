use crate::{
    config::{AppConfig, DEFAULT_ASSET_ADDRESS, DEFAULT_TTL_SECS, EthereumConfig},
    error::{ServiceError, ServiceResult, service_error_to_rpc},
    ethereum::{CoreContractApi, CoreContractProxy, EthereumListener},
    persist::{PersistCtx, repo},
};
use alloy::providers::{DynProvider, Provider, ProviderBuilder, WsConnect};
use anyhow::anyhow;
use async_trait::async_trait;
use crypto::bls::BLSCert;
use log::{error, info};
use parking_lot::Mutex;
use rpc::{
    RpcResult,
    common::*,
    core::{CoreApiServer, CorePublicParameters},
};
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

        let erc20_tokens = contract_api.get_erc20_tokens().await?;

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
                    erc20_tokens.clone(),
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
}
