use std::collections::HashMap;
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
use anyhow::{Context, anyhow, bail};
use chrono::Utc;
use crypto::bls::KeyMaterial;
use log::{error, info, warn};
use rpc::{
    CorePublicParameters, GUARANTEE_CLAIMS_VERSION, SUPPORTED_GUARANTEE_VERSIONS,
    SupportedTokensResponse, UserSuspensionStatus,
};
use validators::ValidatorRegistry;

pub mod auth;
pub mod clearing;
pub mod cycle;
pub mod event_handler;
mod guarantee;
pub mod health;
pub mod netting;
mod query;
pub mod validation;

/// Maximum tolerated event-scanner lag before the cached on-chain `withdrawalGracePeriod` is
/// treated as untrustworthy for the settlement-timing invariant. A healthy scanner advances every
/// few seconds; 30 minutes is well clear of transient RPC hiccups while still catching a genuinely
/// wedged scanner long before an unprocessed grace reduction could matter.
const MAX_SCANNER_LAG_SECS: u64 = 1_800;

/// Decide whether the cached on-chain `withdrawalGracePeriod` is fresh enough to trust.
/// `last_scan_unix == 0` means the scanner has not completed a tick yet (startup), where the grace
/// was validated directly against the chain, so freshness is not yet enforced. Once the scanner has
/// run, a lag beyond `max_lag_secs` returns `Err(lag)` so the caller can halt issuance.
fn scanner_grace_is_fresh(
    now_unix: u64,
    last_scan_unix: u64,
    max_lag_secs: u64,
) -> Result<(), u64> {
    if last_scan_unix == 0 {
        return Ok(());
    }
    let lag = now_unix.saturating_sub(last_scan_unix);
    if lag > max_lag_secs {
        return Err(lag);
    }
    Ok(())
}

pub struct Inner {
    config: AppConfig,
    public_params: CorePublicParameters,
    validators: ValidatorRegistry,
    guarantee_domains: HashMap<u64, [u8; 32]>,
    /// On-chain `withdrawalGracePeriod` (seconds)
    withdrawal_grace_period: AtomicU64,
    /// Unix timestamp of the last confirmed-head advance reported by the event scanner.
    /// `0` until the scanner completes its first tick. Used to detect a wedged/lagging scanner,
    /// after which the cached `withdrawal_grace_period` may be stale (an unprocessed grace
    /// reduction) and must not be trusted to gate guarantee issuance.
    last_scan_unix: AtomicU64,
    persist_ctx: PersistCtx,
    read_provider: DynProvider,
    contract_api: Arc<dyn CoreContractApi>,
    /// Serializes settlement ticks so an overlong `settle_due_cycles` run can't overlap the next
    /// scheduled fire and re-submit the same on-chain settlement work concurrently.
    settlement_tick: tokio::sync::Mutex<()>,
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
    pub validators: ValidatorRegistry,
    pub withdrawal_grace_period: u64,
    pub core_domain_separator: Option<[u8; 32]>,
}

impl CoreService {
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        let persist_ctx = PersistCtx::new().await?;
        let eth_cfg = config.ethereum_config.clone();
        let guarantee_config = config.guarantee.clone();
        guarantee_config.validate()?;

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
        for &version in SUPPORTED_GUARANTEE_VERSIONS {
            let version_config = contract_api.get_guarantee_version_config(version).await?;
            if !version_config.enabled {
                anyhow::bail!(
                    "supported guarantee version {} is disabled on-chain",
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

        // A deployment old enough to lack `DOMAIN_SEPARATOR()` also lacks the gasless-withdrawal
        // entrypoints, so leaving the separator unpublished disables a feature that contract could
        // not serve anyway. Everything else core does is unaffected, so this must not be fatal.
        let core_domain_separator = match contract_api.get_core_domain_separator().await {
            Ok(separator) => {
                info!(
                    "on-chain core domain separator: {}",
                    crypto::hex::encode_hex(&separator)
                );
                Some(separator)
            }
            Err(e) => {
                warn!(
                    "contract does not expose DOMAIN_SEPARATOR() ({e}); gasless withdrawals are \
                     unavailable until it is redeployed"
                );
                None
            }
        };

        // Fail fast if the settlement-cycle timeline does not leave the operator
        // enough margin to seize a defaulter's collateral before it can be withdrawn.
        config
            .settlement_cycle
            .validate_against_withdrawal_grace_period(withdrawal_grace_period)
            .context(
                "settlement cycle timing is incompatible with on-chain withdrawalGracePeriod",
            )?;

        let validators =
            ValidatorRegistry::build(&guarantee_config.validators()?, Some(read_provider.clone()))
                .await?;

        Self::new_with_dependencies(
            config,
            CoreServiceDeps {
                persist_ctx,
                contract_api,
                chain_id: actual_chain_id,
                read_provider,
                guarantee_domains,
                validators,
                withdrawal_grace_period,
                core_domain_separator,
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
        guarantee_config.validate()?;
        let current_domain = deps
            .guarantee_domains
            .get(&GUARANTEE_CLAIMS_VERSION)
            .ok_or_else(|| {
                anyhow!("missing guarantee domain for version {GUARANTEE_CLAIMS_VERSION}")
            })?;
        let guarantee_domain_separator = crypto::hex::encode_hex(current_domain);
        let core_domain_separator = deps
            .core_domain_separator
            .map(|separator| crypto::hex::encode_hex(&separator))
            .unwrap_or_default();

        let inner = Inner {
            config,
            public_params: CorePublicParameters {
                public_key: public_key_bytes,
                contract_address: eth_config.contract_address,
                ethereum_http_rpc_url: eth_config.public_http_rpc_url,
                eip712_name,
                eip712_version,
                chain_id: deps.chain_id,
                supported_guarantee_versions: SUPPORTED_GUARANTEE_VERSIONS.to_vec(),
                guarantee_domain_separator,
                core_domain_separator,
                validators: deps.validators.validators(),
            },
            validators: deps.validators,
            guarantee_domains: deps.guarantee_domains,
            withdrawal_grace_period: AtomicU64::new(deps.withdrawal_grace_period),
            last_scan_unix: AtomicU64::new(0),
            persist_ctx: deps.persist_ctx,
            read_provider: deps.read_provider,
            contract_api: deps.contract_api,
            settlement_tick: tokio::sync::Mutex::new(()),
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

    /// Record that the event scanner advanced its confirmed head, i.e. the cached
    /// `withdrawal_grace_period` reflects chain state up to "now". Called once per successful
    /// scan tick; a cheap atomic store, safe to call from the scanner's hot loop.
    pub(crate) fn record_scan_progress(&self) {
        let now = Utc::now().timestamp().max(0) as u64;
        self.inner.last_scan_unix.store(now, Ordering::Relaxed);
    }
    pub(crate) fn check_settlement_timing_invariant(&self) -> anyhow::Result<()> {
        let now = Utc::now().timestamp().max(0) as u64;
        let last_scan = self.inner.last_scan_unix.load(Ordering::Relaxed);
        if let Err(lag) = scanner_grace_is_fresh(now, last_scan, MAX_SCANNER_LAG_SECS) {
            bail!(
                "event scanner is {lag}s behind (> {MAX_SCANNER_LAG_SECS}s); the cached on-chain \
                 withdrawalGracePeriod may be stale, so guarantee issuance is halted until the \
                 scanner catches up"
            );
        }
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

#[cfg(test)]
mod tests {
    use super::{MAX_SCANNER_LAG_SECS, scanner_grace_is_fresh};

    #[test]
    fn freshness_skipped_before_first_scan() {
        // last_scan_unix == 0: scanner has not run yet; startup validated grace directly.
        assert!(scanner_grace_is_fresh(1_000_000, 0, MAX_SCANNER_LAG_SECS).is_ok());
    }

    #[test]
    fn freshness_ok_within_lag_window() {
        let now = 1_000_000;
        let last = now - MAX_SCANNER_LAG_SECS; // exactly at the bound is still fresh
        assert!(scanner_grace_is_fresh(now, last, MAX_SCANNER_LAG_SECS).is_ok());
    }

    #[test]
    fn freshness_fails_when_scanner_stale() {
        let now = 1_000_000;
        let last = now - MAX_SCANNER_LAG_SECS - 1; // one second past the bound
        let lag = scanner_grace_is_fresh(now, last, MAX_SCANNER_LAG_SECS)
            .expect_err("a stale scanner must fail the freshness check");
        assert_eq!(lag, MAX_SCANNER_LAG_SECS + 1);
    }

    #[test]
    fn freshness_handles_clock_skew_without_underflow() {
        // last_scan in the future (clock skew) must not underflow; treat as zero lag.
        assert!(scanner_grace_is_fresh(1_000, 2_000, MAX_SCANNER_LAG_SECS).is_ok());
    }
}
