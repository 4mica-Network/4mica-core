use std::collections::{HashMap, HashSet};
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
use alloy::primitives::Address;
use alloy::providers::{DynProvider, Provider, ProviderBuilder, WsConnect};
use anyhow::{Context, anyhow};
use crypto::bls::KeyMaterial;
use log::{error, info};
use rpc::{CorePublicParameters, SupportedTokensResponse, UserSuspensionStatus};

pub mod auth;
pub mod clearing;
pub mod cycle;
pub mod event_handler;
mod guarantee;
pub mod health;
pub mod netting;
mod query;

pub struct Inner {
    config: AppConfig,
    public_params: CorePublicParameters,
    trusted_validation_registry_set: HashSet<Address>,
    accepted_guarantee_versions: HashSet<u64>,
    guarantee_domains: HashMap<u64, [u8; 32]>,
    /// On-chain `withdrawalGracePeriod` (seconds)
    withdrawal_grace_period: AtomicU64,
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
    pub guarantee_domains: HashMap<u64, [u8; 32]>,
    pub withdrawal_grace_period: u64,
}

impl CoreService {
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        let persist_ctx = PersistCtx::new().await?;
        let eth_cfg = config.ethereum_config.clone();
        let guarantee_config = config.guarantee.clone();
        guarantee_config.validate(config.server_config.environment)?;
        let accepted_guarantee_versions = guarantee_config.accepted_request_versions()?;

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
        let mut guarantee_domains = HashMap::new();
        for version in accepted_guarantee_versions {
            let version_config = contract_api.get_guarantee_version_config(version).await?;
            if !version_config.enabled {
                anyhow::bail!(
                    "accepted guarantee version {} is disabled on-chain",
                    version
                );
            }
            info!(
                "on-chain guarantee v{} domain separator: {} (decoder: {})",
                version_config.version,
                crypto::hex::encode_hex(&version_config.domain_separator),
                version_config.decoder
            );
            guarantee_domains.insert(version, version_config.domain_separator);
        }
        let withdrawal_grace_period = contract_api.get_withdrawal_grace_period().await?;
        info!(
            "on-chain withdrawal grace period: {}s",
            withdrawal_grace_period
        );

        // Fail fast if the settlement-cycle timeline does not leave the operator
        // enough margin to seize a defaulter's collateral before it can be withdrawn.
        config
            .settlement_cycle
            .validate_against_withdrawal_grace_period(withdrawal_grace_period)
            .context(
                "settlement cycle timing is incompatible with on-chain withdrawalGracePeriod",
            )?;

        Self::new_with_dependencies(
            config,
            CoreServiceDeps {
                persist_ctx,
                contract_api,
                chain_id: actual_chain_id,
                read_provider,
                guarantee_domains,
                withdrawal_grace_period,
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
        let guarantee_config = config.guarantee.clone();
        guarantee_config.validate(config.server_config.environment)?;
        let trusted_validation_registries =
            guarantee_config.trusted_validation_registry_allowlist()?;
        let trusted_validation_registry_set: HashSet<Address> = trusted_validation_registries
            .iter()
            .map(|registry| {
                registry.parse::<Address>().map_err(|_| {
                    anyhow!(
                        "invalid normalized trusted validation registry address: {}",
                        registry
                    )
                })
            })
            .collect::<anyhow::Result<HashSet<Address>>>()?;
        let max_accepted_version = guarantee_config.max_accepted_version;
        let accepted_guarantee_versions = guarantee_config
            .accepted_request_versions()?
            .into_iter()
            .collect::<HashSet<_>>();
        let validation_hash_canonicalization_version = guarantee_config
            .validation_hash_canonicalization_version
            .clone();
        let mut accepted_guarantee_versions_public = accepted_guarantee_versions
            .iter()
            .copied()
            .collect::<Vec<_>>();
        accepted_guarantee_versions_public.sort_unstable();
        let max_accepted_domain = deps
            .guarantee_domains
            .get(&max_accepted_version)
            .ok_or_else(|| {
                anyhow!(
                    "missing guarantee domain for max accepted guarantee version {}",
                    max_accepted_version
                )
            })?;
        let active_guarantee_domain_separator = crypto::hex::encode_hex(max_accepted_domain);

        let inner = Inner {
            config,
            public_params: CorePublicParameters {
                public_key: public_key_bytes,
                contract_address: eth_config.contract_address,
                ethereum_http_rpc_url: eth_config.public_http_rpc_url,
                eip712_name,
                eip712_version,
                chain_id: deps.chain_id,
                max_accepted_guarantee_version: max_accepted_version,
                accepted_guarantee_versions: accepted_guarantee_versions_public,
                active_guarantee_domain_separator,
                trusted_validation_registries,
                validation_hash_canonicalization_version,
            },
            trusted_validation_registry_set,
            accepted_guarantee_versions,
            guarantee_domains: deps.guarantee_domains,
            withdrawal_grace_period: AtomicU64::new(deps.withdrawal_grace_period),
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

    pub fn clearing_house_address(&self) -> String {
        self.inner
            .config
            .ethereum_config
            .clearing_house_address
            .clone()
    }

    pub(crate) fn set_withdrawal_grace_period(&self, withdrawal_grace_period: u64) {
        self.inner
            .withdrawal_grace_period
            .store(withdrawal_grace_period, Ordering::Relaxed);
    }

    pub(crate) fn withdrawal_grace_period(&self) -> u64 {
        self.inner.withdrawal_grace_period.load(Ordering::Relaxed)
    }

    /// Re-evaluate the settlement-cycle solvency invariant against the currently
    /// known on-chain `withdrawalGracePeriod`.
    pub(crate) fn check_settlement_timing_invariant(&self) -> anyhow::Result<()> {
        self.inner
            .config
            .settlement_cycle
            .validate_against_withdrawal_grace_period(self.withdrawal_grace_period())
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

    pub async fn get_supported_tokens(&self) -> ServiceResult<SupportedTokensResponse> {
        let tokens = self
            .inner
            .contract_api
            .get_supported_tokens()
            .await
            .map_err(|e| ServiceError::Other(anyhow!(e)))?;
        Ok(SupportedTokensResponse {
            chain_id: self.inner.public_params.chain_id,
            tokens,
        })
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
