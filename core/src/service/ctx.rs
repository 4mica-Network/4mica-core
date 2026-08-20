//! Shared context handed to every service.
//!
//! Holds what the whole application needs regardless of layer: configuration, the database
//! handle, the chain seam, and the small amount of mutable state mirrored from the chain.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, bail};
use chrono::Utc;
use crypto::bls::KeyMaterial;
use log::info;
use rpc::{
    CorePublicParameters, GUARANTEE_CLAIMS_VERSION, GuaranteeVersionDomain,
    SUPPORTED_GUARANTEE_VERSIONS,
};
use validators::ValidatorRegistry;

use crate::config::AppConfig;
use crate::ethereum::ChainService;
use crate::persist::PersistCtx;

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

pub struct Ctx {
    pub config: AppConfig,
    pub public_params: CorePublicParameters,
    pub persist: PersistCtx,
    pub chain: Arc<ChainService>,
    pub validators: ValidatorRegistry,
    pub guarantee_domains: HashMap<u64, [u8; 32]>,
    /// On-chain `withdrawalGracePeriod` (seconds)
    withdrawal_grace_period: AtomicU64,
    /// Unix timestamp of the last confirmed-head advance reported by the event scanner.
    /// `0` until the scanner completes its first tick. Used to detect a wedged/lagging scanner,
    /// after which the cached `withdrawal_grace_period` may be stale (an unprocessed grace
    /// reduction) and must not be trusted to gate guarantee issuance.
    last_scan_unix: AtomicU64,
    /// Serializes settlement ticks so an overlong `settle_due_cycles` run can't overlap the next
    /// scheduled fire and re-submit the same on-chain settlement work concurrently.
    pub settlement_tick: tokio::sync::Mutex<()>,
}

impl Ctx {
    pub fn new(
        config: AppConfig,
        public_params: CorePublicParameters,
        persist: PersistCtx,
        chain: Arc<ChainService>,
        validators: ValidatorRegistry,
        guarantee_domains: HashMap<u64, [u8; 32]>,
        withdrawal_grace_period: u64,
    ) -> Self {
        Self {
            config,
            public_params,
            persist,
            chain,
            validators,
            guarantee_domains,
            withdrawal_grace_period: AtomicU64::new(withdrawal_grace_period),
            last_scan_unix: AtomicU64::new(0),
            settlement_tick: tokio::sync::Mutex::new(()),
        }
    }

    /// The database handle, for the many `*_on(conn, ..)` repo calls.
    pub fn db(&self) -> &sea_orm::DatabaseConnection {
        self.persist.db.as_ref()
    }

    pub fn bls_secret_key(&self) -> &KeyMaterial {
        &self.config.secrets.bls_secret_key
    }

    pub fn set_withdrawal_grace_period(&self, withdrawal_grace_period: u64) {
        self.withdrawal_grace_period
            .store(withdrawal_grace_period, Ordering::Relaxed);
    }

    pub fn withdrawal_grace_period(&self) -> u64 {
        self.withdrawal_grace_period.load(Ordering::Relaxed)
    }

    /// Record that the event scanner advanced its confirmed head, i.e. the cached
    /// `withdrawal_grace_period` reflects chain state up to "now". Called once per successful
    /// scan tick; a cheap atomic store, safe to call from the scanner's hot loop.
    pub fn record_scan_progress(&self) {
        let now = Utc::now().timestamp().max(0) as u64;
        self.last_scan_unix.store(now, Ordering::Relaxed);
    }

    pub fn check_settlement_timing_invariant(&self) -> anyhow::Result<()> {
        let now = Utc::now().timestamp().max(0) as u64;
        let last_scan = self.last_scan_unix.load(Ordering::Relaxed);
        if let Err(lag) = scanner_grace_is_fresh(now, last_scan, MAX_SCANNER_LAG_SECS) {
            bail!(
                "event scanner is {lag}s behind (> {MAX_SCANNER_LAG_SECS}s); the cached on-chain \
                 withdrawalGracePeriod may be stale, so guarantee issuance is halted until the \
                 scanner catches up"
            );
        }
        self.config
            .settlement_cycle
            .validate_against_withdrawal_grace_period(self.withdrawal_grace_period())
    }
}

/// Assemble the parameters core publishes to clients, from its configuration and what the chain
/// reported at startup.
pub fn public_parameters(
    config: &AppConfig,
    chain_id: u64,
    guarantee_domains: &HashMap<u64, [u8; 32]>,
    core_domain_separator: Option<[u8; 32]>,
    validators: &ValidatorRegistry,
) -> anyhow::Result<CorePublicParameters> {
    let public_key = config.secrets.bls_secret_key.public_key().to_vec();
    info!(
        "Operator started with BLS Public Key: {}",
        crypto::hex::encode_hex(&public_key)
    );

    let current_domain = guarantee_domains
        .get(&GUARANTEE_CLAIMS_VERSION)
        .ok_or_else(|| {
            anyhow!("missing guarantee domain for version {GUARANTEE_CLAIMS_VERSION}")
        })?;
    let mut published_guarantee_domains = guarantee_domains
        .iter()
        .map(|(&version, domain)| GuaranteeVersionDomain {
            version,
            domain_separator: crypto::hex::encode_hex(domain),
        })
        .collect::<Vec<_>>();
    published_guarantee_domains.sort_by_key(|entry| entry.version);

    let eth_config = &config.ethereum_config;
    Ok(CorePublicParameters {
        public_key,
        contract_address: eth_config.contract_address.clone(),
        ethereum_http_rpc_url: eth_config.public_http_rpc_url.clone(),
        eip712_name: config.eip712.name.clone(),
        eip712_version: config.eip712.version.clone(),
        chain_id,
        supported_guarantee_versions: SUPPORTED_GUARANTEE_VERSIONS.to_vec(),
        guarantee_domain_separator: crypto::hex::encode_hex(current_domain),
        guarantee_domains: published_guarantee_domains,
        core_domain_separator: core_domain_separator
            .map(|separator| crypto::hex::encode_hex(&separator))
            .unwrap_or_default(),
        validators: validators.validators(),
    })
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
