use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use crate::persist::mapper;
use crate::{
    config::{AppConfig, EthereumConfig},
    error::{ServiceError, ServiceResult},
    ethereum::{CoreContractApi, CoreContractProxy, EthereumListener},
    persist::{PersistCtx, repo},
};
use alloy::providers::{DynProvider, Provider, ProviderBuilder, WsConnect};
use anyhow::anyhow;
use log::{error, info};
use parking_lot::Mutex;
use rpc::{CorePublicParameters, UserSuspensionStatus};
use tokio::{
    sync::{Notify, oneshot},
    task::JoinHandle,
    time::{Duration, sleep},
};

pub mod auth;
pub mod event_handler;
mod guarantee;
pub mod payment;
mod query;
mod tab;

pub struct Inner {
    config: AppConfig,
    bls_private_key: [u8; 32],
    public_params: CorePublicParameters,
    guarantee_domain: [u8; 32],
    tab_expiration_time: AtomicU64,
    persist_ctx: PersistCtx,
    read_provider: DynProvider,
    contract_api: Arc<dyn CoreContractApi>,
    listener_handle: Mutex<Option<JoinHandle<()>>>,
    listener_ready_rx: Mutex<Option<oneshot::Receiver<()>>>,
    listener_ready: AtomicBool,
    listener_ready_notify: Notify,
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

pub struct CoreServiceDeps {
    pub persist_ctx: PersistCtx,
    pub contract_api: Arc<dyn CoreContractApi>,
    pub chain_id: u64,
    pub read_provider: DynProvider,
    pub guarantee_domain: [u8; 32],
    pub tab_expiration_time: u64,
    pub listener_ready_rx: oneshot::Receiver<()>,
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
        let tab_expiration_time = contract_api.get_tab_expiration_time().await?;
        info!(
            "on-chain guarantee domain separator: 0x{}",
            crypto::hex::encode_hex(&on_chain_domain)
        );
        info!("on-chain tab expiration time: {}s", tab_expiration_time);

        let (ready_tx, ready_rx) = oneshot::channel();
        let core_service = Self::new_with_dependencies(
            config,
            CoreServiceDeps {
                persist_ctx: persist_ctx.clone(),
                contract_api,
                chain_id: actual_chain_id,
                read_provider: read_provider.clone(),
                guarantee_domain: on_chain_domain,
                tab_expiration_time,
                listener_ready_rx: ready_rx,
            },
        )?;
        let core_service_clone = core_service.clone();
        tokio::spawn(async move {
            let mut delay = Duration::from_secs(1);
            let mut ready_tx = Some(ready_tx);
            loop {
                match EthereumListener::new(
                    listener_cfg.clone(),
                    persist_ctx.clone(),
                    read_provider.clone(),
                    Arc::new(core_service_clone.clone()),
                )
                .run(ready_tx.take())
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

    pub fn new_with_dependencies(config: AppConfig, deps: CoreServiceDeps) -> anyhow::Result<Self> {
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
                contract_address: eth_config.contract_address,
                ethereum_http_rpc_url: eth_config.http_rpc_url,
                eip712_name,
                eip712_version,
                chain_id: deps.chain_id,
            },
            guarantee_domain: deps.guarantee_domain,
            tab_expiration_time: AtomicU64::new(deps.tab_expiration_time),
            persist_ctx: deps.persist_ctx,
            read_provider: deps.read_provider,
            contract_api: deps.contract_api,
            listener_handle: Mutex::default(),
            listener_ready_rx: Mutex::new(Some(deps.listener_ready_rx)),
            listener_ready: AtomicBool::new(false),
            listener_ready_notify: Notify::new(),
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

    fn tab_expiration_time(&self) -> u64 {
        self.inner.tab_expiration_time.load(Ordering::Relaxed)
    }

    fn set_tab_expiration_time(&self, tab_expiration_time: u64) {
        self.inner
            .tab_expiration_time
            .store(tab_expiration_time, Ordering::Relaxed);
    }

    pub fn kill_listener(&self) {
        if let Some(handle) = self.inner.listener_handle.lock().take() {
            handle.abort();
        }
    }

    pub async fn wait_for_listener_ready(&self) -> Result<(), oneshot::error::RecvError> {
        if self.inner.listener_ready.load(Ordering::Acquire) {
            return Ok(());
        }

        let receiver = self.inner.listener_ready_rx.lock().take();
        if let Some(receiver) = receiver {
            receiver.await?;
            self.inner.listener_ready.store(true, Ordering::Release);
            self.inner.listener_ready_notify.notify_waiters();
            return Ok(());
        }

        self.inner.listener_ready_notify.notified().await;
        Ok(())
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
