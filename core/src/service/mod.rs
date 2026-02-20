use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use crate::persist::mapper;
use crate::{
    config::{AppConfig, EthereumConfig},
    error::{ServiceError, ServiceResult},
    ethereum::{CoreContractApi, CoreContractProxy},
    persist::{PersistCtx, repo},
};
use alloy::providers::{DynProvider, Provider, ProviderBuilder, WsConnect};
use anyhow::anyhow;
use crypto::bls::KeyMaterial;
use log::{error, info};
use rpc::{CorePublicParameters, UserSuspensionStatus};

pub mod auth;
pub mod event_handler;
mod guarantee;
pub mod health;
pub mod payment;
mod query;
mod tab;

pub struct Inner {
    config: AppConfig,
    public_params: CorePublicParameters,
    guarantee_domain: [u8; 32],
    tab_expiration_time: AtomicU64,
    persist_ctx: PersistCtx,
    read_provider: DynProvider,
    contract_api: Arc<dyn CoreContractApi>,
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
}

impl CoreService {
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        let persist_ctx = PersistCtx::new().await?;
        let eth_cfg = config.ethereum_config.clone();

        let contract_api = Arc::new(CoreContractProxy::new(&config).await?);

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

        Self::new_with_dependencies(
            config,
            CoreServiceDeps {
                persist_ctx,
                contract_api,
                chain_id: actual_chain_id,
                read_provider,
                guarantee_domain: on_chain_domain,
                tab_expiration_time,
            },
        )
    }

    pub fn new_with_dependencies(config: AppConfig, deps: CoreServiceDeps) -> anyhow::Result<Self> {
        let public_key = config.secrets.bls_secret_key.public_key();
        let public_key_bytes = public_key.to_vec();
        info!(
            "Operator started with BLS Public Key: {}",
            crypto::hex::encode_hex(&public_key_bytes)
        );

        let eip712_name = config.eip712.name.clone();
        let eip712_version = config.eip712.version.clone();
        let eth_config = config.ethereum_config.clone();

        let inner = Inner {
            config,
            public_params: CorePublicParameters {
                public_key: public_key_bytes,
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
        };

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    fn bls_secret_key(&self) -> &KeyMaterial {
        &self.inner.config.secrets.bls_secret_key
    }

    pub fn persist_ctx(&self) -> &PersistCtx {
        &self.inner.persist_ctx
    }

    pub fn read_provider(&self) -> &DynProvider {
        &self.inner.read_provider
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
