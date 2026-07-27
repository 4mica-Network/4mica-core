use std::collections::HashSet;
use std::{str::FromStr, sync::Arc};

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, bail};
use crypto::bls::KeyMaterial;
use envconfig::Envconfig;
use jsonwebtoken::{DecodingKey, EncodingKey};
use log::warn;
use secrecy::zeroize::Zeroize;
use validators::ValidatorEntry;

pub const DEFAULT_TTL_SECS: u64 = 3600 * 24;

pub const DEFAULT_ASSET_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
const DEFAULT_AUTH_JWT_SECRET: &str = "dev-insecure-change-me";
const PLACEHOLDER_AUTH_JWT_SECRET: &str = "replace-with-32+bytes-random";

#[derive(Debug, Clone, Envconfig)]
pub struct ServerConfig {
    #[envconfig(from = "SERVER_HOST", default = "127.0.0.1")]
    pub host: String,

    #[envconfig(from = "SERVER_PORT", default = "3000")]
    pub port: String,

    #[envconfig(from = "LOG_LEVEL", default = "info")]
    pub log_level: log::Level,

    /// Deployment environment. Gates production-only safety requirements (e.g.
    /// requiring reorg-safe `finalized` confirmation). Defaults to `production`
    /// so a deployment that forgets to set it gets the strict, safe behavior;
    /// local dev/test must explicitly opt into the relaxed paths with
    /// `SERVER_ENVIRONMENT=development`.
    #[envconfig(from = "SERVER_ENVIRONMENT", default = "production")]
    pub environment: Environment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Production,
    Development,
}

impl Environment {
    pub fn is_production(self) -> bool {
        matches!(self, Environment::Production)
    }
}

impl FromStr for Environment {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.trim().to_lowercase().as_str() {
            "production" | "prod" => Ok(Environment::Production),
            "development" | "dev" | "test" => Ok(Environment::Development),
            other => bail!(
                "Invalid SERVER_ENVIRONMENT '{}'. Use one of: production, development",
                other
            ),
        }
    }
}

#[derive(Debug, Clone, Envconfig)]
pub struct EthereumConfig {
    #[envconfig(from = "ETHEREUM_CHAIN_ID", default = "1")]
    pub chain_id: u64,
    #[envconfig(from = "ETHEREUM_WS_RPC_URL")]
    pub ws_rpc_url: String,
    #[envconfig(from = "ETHEREUM_HTTP_RPC_URL")]
    pub http_rpc_url: String,
    #[envconfig(from = "PUBLIC_ETHEREUM_HTTP_RPC_URL", default = "")]
    pub public_http_rpc_url: String,
    #[envconfig(from = "ETHEREUM_CONTRACT_ADDRESS")]
    pub contract_address: String,
    #[envconfig(
        from = "ETHEREUM_CLEARING_HOUSE_ADDRESS",
        default = "0x0000000000000000000000000000000000000000"
    )]
    pub clearing_house_address: String,
    #[envconfig(from = "CRON_JOB_SETTINGS", default = "0 */1 * * * *")]
    pub cron_job_settings: String,
    #[envconfig(from = "ETHEREUM_EVENT_SCANNER_CRON", default = "*/5 * * * * *")]
    pub event_scanner_cron: String,
    /// Confirmation policy for on-chain data:
    /// `depth` = confirm after N blocks (NUMBER_OF_BLOCKS_TO_CONFIRM),
    /// `safe` = confirm at the chain's "safe" head,
    /// `finalized` = confirm at the chain's finalized head (safest).
    #[envconfig(from = "CONFIRMATION_MODE", default = "finalized")]
    pub confirmation_mode: String,
    /// Only used when CONFIRMATION_MODE=depth.
    #[envconfig(from = "NUMBER_OF_BLOCKS_TO_CONFIRM", default = "20")]
    pub number_of_blocks_to_confirm: u64,
    #[envconfig(from = "PAYMENT_SCAN_LOOKBACK_BLOCKS", default = "5")]
    pub payment_scan_lookback_blocks: u64,
    /// Legacy payment scanner that inspects full transaction bodies in recent blocks.
    /// Contract events are the primary payment discovery path; keep this off unless
    /// explicitly needed because some RPCs return transaction shapes older clients
    /// cannot deserialize inside full blocks.
    #[envconfig(from = "PAYMENT_LEGACY_SCAN_ENABLED", default = "false")]
    pub payment_legacy_scan_enabled: bool,
    /// When scanning for events and cursor is not found in the database, scan back this many blocks.
    #[envconfig(from = "INITIAL_EVENT_SCAN_LOOKBACK_BLOCKS", default = "25")]
    pub initial_event_scan_lookback_blocks: u64,
    /// Maximum block span for a single eth_getLogs request.
    #[envconfig(from = "ETHEREUM_MAX_LOG_BLOCK_RANGE", default = "10000")]
    pub max_log_block_range: u64,
    /// Max in-loop retries for a *retryable* event-handler failure (transient DB/RPC) before the
    /// scan aborts and retries the range next tick. Deterministic failures are never retried; they
    /// are dead-lettered. `0` disables retries (a retryable error aborts immediately).
    #[envconfig(from = "ETHEREUM_EVENT_HANDLER_MAX_RETRIES", default = "5")]
    pub event_handler_max_retries: usize,
    /// Base backoff between event-handler retries; the delay scales linearly with the attempt count.
    #[envconfig(from = "ETHEREUM_EVENT_HANDLER_RETRY_BASE_DELAY_MS", default = "200")]
    pub event_handler_retry_base_delay_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationMode {
    Depth,
    Safe,
    Finalized,
}

impl ConfirmationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfirmationMode::Depth => "depth",
            ConfirmationMode::Safe => "safe",
            ConfirmationMode::Finalized => "finalized",
        }
    }
}

impl EthereumConfig {
    pub fn confirmation_mode(&self) -> anyhow::Result<ConfirmationMode> {
        match self.confirmation_mode.trim().to_lowercase().as_str() {
            "depth" => Ok(ConfirmationMode::Depth),
            "safe" => Ok(ConfirmationMode::Safe),
            "finalized" => Ok(ConfirmationMode::Finalized),
            other => bail!(
                "Invalid CONFIRMATION_MODE '{}'. Use one of: depth, safe, finalized",
                other
            ),
        }
    }

    pub fn validate(&self, environment: Environment) -> anyhow::Result<()> {
        Address::from_str(&self.contract_address).map_err(|_| {
            anyhow::anyhow!(
                "ETHEREUM_CONTRACT_ADDRESS is not a valid address: {:?}",
                self.contract_address
            )
        })?;

        let mode = self.confirmation_mode()?;
        if mode != ConfirmationMode::Finalized {
            if environment.is_production() {
                bail!(
                    "CONFIRMATION_MODE must be `finalized` in production, but is `{}`. Non-finalized \
                     modes treat reorg-able blocks as confirmed, which can double-credit ETH deposits \
                     and mint unbacked guarantees. Set SERVER_ENVIRONMENT=development \
                     for local/test use of `{}`.",
                    mode.as_str(),
                    mode.as_str()
                );
            }
            warn!(
                "CONFIRMATION_MODE={} treats recent (reorg-able) blocks as confirmed; permitted only \
                 because SERVER_ENVIRONMENT=development. Never use this in production.",
                mode.as_str()
            );
        }
        if mode == ConfirmationMode::Depth && self.number_of_blocks_to_confirm == 0 {
            bail!("NUMBER_OF_BLOCKS_TO_CONFIRM must be > 0 when CONFIRMATION_MODE=depth");
        }
        if self.payment_scan_lookback_blocks == 0 {
            bail!("PAYMENT_SCAN_LOOKBACK_BLOCKS must be > 0");
        }
        if self.max_log_block_range == 0 {
            bail!("ETHEREUM_MAX_LOG_BLOCK_RANGE must be > 0");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Envconfig)]
pub struct Eip712Config {
    #[envconfig(from = "EIP712_NAME", default = "4mica")]
    pub name: String,

    #[envconfig(from = "EIP712_VERSION", default = "1")]
    pub version: String,
}

#[derive(Debug, Clone, Envconfig)]
pub struct GuaranteeConfig {
    /// JSON array of whitelisted validators — see [`ValidatorEntry`]. Empty disables
    /// validation-gated guarantees entirely.
    #[envconfig(from = "GUARANTEE_VALIDATORS", default = "[]")]
    pub validators: String,
    #[envconfig(from = "VALIDATION_POLL_CRON", default = "0 */1 * * * *")]
    pub validation_poll_cron: String,
    /// Shortest validation window, in seconds, core will issue against.
    #[envconfig(from = "MIN_VALIDATION_WINDOW_SECS")]
    pub min_validation_window_secs: Option<u64>,
}

impl GuaranteeConfig {
    pub fn validators(&self) -> anyhow::Result<Vec<ValidatorEntry>> {
        let raw = self.validators.trim();
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str(raw).context("GUARANTEE_VALIDATORS must be a JSON array of validators")
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let validators = self.validators()?;
        let mut seen = HashSet::new();
        for entry in &validators {
            if entry.uri.trim().is_empty() {
                bail!("GUARANTEE_VALIDATORS contains an entry with an empty uri");
            }
            if !seen.insert(entry.uri.clone()) {
                bail!(
                    "GUARANTEE_VALIDATORS contains duplicate validator '{}'",
                    entry.uri
                );
            }
        }

        // The scheduler rejects a malformed pattern when the task is registered, but an empty
        // value is a common misconfiguration worth catching here with a clear message.
        if self.validation_poll_cron.trim().is_empty() {
            bail!("VALIDATION_POLL_CRON must not be empty");
        }
        Ok(())
    }
}

/// Configuration for the off-chain clearing/settlement cycle.
///
/// # Relationship to the on-chain delayed-withdrawal invariant
///
/// `Core4Mica` lets a user finalize a collateral withdrawal only after
/// `withdrawalGracePeriod` has elapsed since the request. That window is the
/// operator's only opportunity to seize a defaulting user's collateral before it
/// can leave. The contract cannot observe the settlement-cycle timeline, so it
/// only enforces that the grace period is non-zero — core-service owns the safety
/// relationship, because it is the only component that knows the cycle timing.
///
/// The worst case for an obligation accrued at the start of a cycle is that it
/// cannot be enforced as an on-chain default until that cycle reaches payment
/// finality, i.e. after [`cycle_to_finality_secs`](Self::cycle_to_finality_secs).
/// The operator then needs `seizure_margin_secs` of slack to actually land the
/// seizure transaction. Hence the invariant
/// (`validate_against_withdrawal_grace_period`):
///
/// ```text
/// cycle_to_finality_secs + seizure_margin_secs < withdrawalGracePeriod
/// ```
#[derive(Debug, Clone, Envconfig)]
pub struct SettlementCycleConfig {
    #[envconfig(from = "SETTLEMENT_CYCLE_SECS", default = "86400")]
    pub cycle_secs: u64,
    #[envconfig(from = "SETTLEMENT_RESOLUTION_CUTOFF_SECS", default = "21600")]
    pub resolution_cutoff_secs: u64,
    #[envconfig(from = "SETTLEMENT_CLEARING_COMMIT_DELAY_SECS", default = "900")]
    pub clearing_commit_delay_secs: u64,
    #[envconfig(from = "SETTLEMENT_PAYMENT_SUBMISSION_WINDOW_SECS", default = "7200")]
    pub payment_submission_window_secs: u64,
    #[envconfig(from = "SETTLEMENT_PAYMENT_FINALITY_WINDOW_SECS", default = "14400")]
    pub payment_finality_window_secs: u64,
    #[envconfig(from = "SETTLEMENT_SEIZURE_MARGIN_SECS", default = "21600")]
    pub seizure_margin_secs: u64,
    /// Maximum number of participants settled per on-chain batch transaction.
    #[envconfig(from = "SETTLEMENT_DEFAULT_BATCH_SIZE", default = "50")]
    pub default_batch_size: u64,
    /// Grace period, past the payment-finality deadline, during which seizures are retried
    /// before an under-funded cycle is driven to the terminal Shortfall state.
    /// Gives transient seize failures time to clear before losses are socialized.
    #[envconfig(from = "SETTLEMENT_SHORTFALL_GRACE_SECS", default = "21600")]
    pub shortfall_grace_secs: u64,
    /// How long an optimistic chain-driven cycle transition may stay unconfirmed by
    /// its chain event before the settlement driver re-drives it. Kept well above
    /// Ethereum finality so a re-drive only fires on a genuine reorg. Default 30 min.
    #[envconfig(from = "SETTLEMENT_RETRY_DELAY_SECS", default = "1800")]
    pub settlement_retry_delay_secs: u64,
    /// Retry windows past its expected-confirmation deadline after which an unconfirmed
    /// cycle is counted as hanging by the operator gauge.
    #[envconfig(from = "SETTLEMENT_HANGING_RETRY_WINDOWS", default = "3")]
    pub hanging_retry_windows: u64,
}

impl SettlementCycleConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.cycle_secs == 0 {
            bail!("SETTLEMENT_CYCLE_SECS must be > 0");
        }
        if self.resolution_cutoff_secs == 0 {
            bail!("SETTLEMENT_RESOLUTION_CUTOFF_SECS must be > 0");
        }
        if self.clearing_commit_delay_secs == 0 {
            bail!("SETTLEMENT_CLEARING_COMMIT_DELAY_SECS must be > 0");
        }
        if self.payment_submission_window_secs == 0 {
            bail!("SETTLEMENT_PAYMENT_SUBMISSION_WINDOW_SECS must be > 0");
        }
        if self.seizure_margin_secs == 0 {
            bail!("SETTLEMENT_SEIZURE_MARGIN_SECS must be > 0");
        }
        if self.payment_finality_window_secs < self.payment_submission_window_secs {
            bail!(
                "SETTLEMENT_PAYMENT_FINALITY_WINDOW_SECS must be >= SETTLEMENT_PAYMENT_SUBMISSION_WINDOW_SECS"
            );
        }
        if self.shortfall_grace_secs == 0 {
            // A zero grace collapses the seize-retry window, so the first tick past finality would
            // socialize creditor losses into the terminal Shortfall state with no retry buffer.
            bail!("SETTLEMENT_SHORTFALL_GRACE_SECS must be > 0");
        }
        if self.shortfall_grace_secs > self.seizure_margin_secs {
            // Seizures are retried until payment_finality_deadline + shortfall_grace_secs. Keeping
            // that window within seizure_margin_secs ensures the delayed-withdrawal solvency
            // invariant (validate_against_withdrawal_grace_period, which budgets seizure_margin_secs)
            // still covers the whole period during which a debtor's collateral may be seized.
            bail!(
                "SETTLEMENT_SHORTFALL_GRACE_SECS ({}) must be <= SETTLEMENT_SEIZURE_MARGIN_SECS ({}) \
                 so the shortfall retry window stays within the seizure margin the withdrawal-grace \
                 solvency invariant budgets for",
                self.shortfall_grace_secs,
                self.seizure_margin_secs
            );
        }
        Ok(())
    }

    /// Mirrors the deadline chain built in `SettlementCycleWindow::for_instant`.
    pub fn cycle_to_finality_secs(&self) -> u64 {
        self.cycle_secs
            .saturating_add(self.resolution_cutoff_secs)
            .saturating_add(self.clearing_commit_delay_secs)
            .saturating_add(self.payment_finality_window_secs)
    }

    /// cycle_to_finality_secs + seizure_margin_secs < withdrawal_grace_period
    pub fn validate_against_withdrawal_grace_period(
        &self,
        withdrawal_grace_period: u64,
    ) -> anyhow::Result<()> {
        let cycle_to_finality = self.cycle_to_finality_secs();
        let required = cycle_to_finality.saturating_add(self.seizure_margin_secs);
        if required >= withdrawal_grace_period {
            bail!(
                "settlement cycle time-to-finality ({cycle_to_finality}s) + seizure margin \
                 ({}s) = {required}s must be < on-chain withdrawalGracePeriod \
                 ({withdrawal_grace_period}s) to preserve the delayed-withdrawal solvency \
                 invariant; increase withdrawalGracePeriod or shorten the settlement cycle windows",
                self.seizure_margin_secs
            );
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Secrets {
    pub bls_secret_key: KeyMaterial,
    // PrivateKeySigner handles the zeroization internally
    pub ethereum_private_key_signer: PrivateKeySigner,
    pub jwt_enc_key: EncodingKey,
    pub jwt_dec_key: DecodingKey,
}

impl Secrets {
    pub fn init_from_env(environment: Environment) -> anyhow::Result<Self> {
        let mut bls_secret_key_raw = Self::load_env_var("BLS_PRIVATE_KEY")?;
        let bls_secret_key = KeyMaterial::from_str(&bls_secret_key_raw)?;
        bls_secret_key_raw.zeroize();

        let mut ethereum_private_key = Self::load_env_var("ETHEREUM_PRIVATE_KEY")?;
        let ethereum_private_key_signer: PrivateKeySigner = ethereum_private_key.parse()?;
        ethereum_private_key.zeroize();

        let mut jwt_hmac_secret = Self::load_env_var("AUTH_JWT_SECRET")?;
        let secret = jwt_hmac_secret.trim();
        if secret.is_empty() {
            bail!("AUTH_JWT_SECRET must be set");
        }
        if secret == DEFAULT_AUTH_JWT_SECRET {
            bail!("AUTH_JWT_SECRET is set to the insecure default; override it");
        }
        // A placeholder or short signing key can be brute-forced, letting anyone forge
        // access tokens. Hard-fail in production; keep it a warning in development so
        // local/test setups can use throwaway secrets.
        let weak_secret = if secret == PLACEHOLDER_AUTH_JWT_SECRET {
            Some(
                "AUTH_JWT_SECRET uses the placeholder value; set a 32+ byte random secret"
                    .to_string(),
            )
        } else if secret.len() < 32 {
            Some(format!(
                "AUTH_JWT_SECRET is {} bytes; use a 32+ byte random secret",
                secret.len()
            ))
        } else {
            None
        };
        if let Some(reason) = weak_secret {
            if environment.is_production() {
                bail!("{reason} (required in production; SERVER_ENVIRONMENT=production)");
            }
            warn!("{reason}; permitted only because SERVER_ENVIRONMENT=development");
        }

        let secret_bytes = secret.as_bytes();

        let jwt_enc_key = EncodingKey::from_secret(secret_bytes);
        let jwt_dec_key = DecodingKey::from_secret(secret_bytes);

        jwt_hmac_secret.zeroize();

        Ok(Self {
            bls_secret_key,
            ethereum_private_key_signer,
            jwt_enc_key,
            jwt_dec_key,
        })
    }

    fn load_env_var(name: &str) -> anyhow::Result<String> {
        let value = std::env::var(name)
            .map_err(|e| anyhow::anyhow!("Failed to load environment variable {name}: {e}"))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Envconfig)]
pub struct AuthConfig {
    #[envconfig(from = "AUTH_NONCE_TTL_SECS", default = "300")]
    pub nonce_ttl_secs: i64,

    #[envconfig(from = "AUTH_REFRESH_TTL_SECS", default = "2592000")]
    pub refresh_ttl_secs: i64,

    #[envconfig(from = "AUTH_ACCESS_TTL_SECS", default = "900")]
    pub access_ttl_secs: u64,

    #[envconfig(from = "AUTH_JWT_ISSUER", default = "4mica-core")]
    pub jwt_issuer: String,

    #[envconfig(from = "AUTH_JWT_AUDIENCE", default = "4mica")]
    pub jwt_audience: String,

    #[envconfig(from = "AUTH_SIWE_STATEMENT", default = "Sign in to 4mica.")]
    pub siwe_statement: String,

    #[envconfig(from = "AUTH_SIWE_DOMAIN")]
    pub siwe_domain: Option<String>,

    #[envconfig(from = "AUTH_SIWE_URI")]
    pub siwe_uri: Option<String>,
}

impl AuthConfig {
    pub fn validate(&self, environment: Environment) -> anyhow::Result<()> {
        // The SIWE domain and URI are bound into the sign-in message the wallet
        // signs, anchoring the login to this origin. In production we refuse the
        // silent fallbacks in `build_siwe_context` (bind host for the domain,
        // `http://` for the URI): a wrong or insecure origin enables cross-domain
        // replay/phishing of sign-in messages. Development keeps the fallbacks so
        // local setups work without extra config.
        if !environment.is_production() {
            return Ok(());
        }
        let domain = self.siwe_domain.as_deref().map(str::trim).unwrap_or("");
        if domain.is_empty() {
            bail!(
                "AUTH_SIWE_DOMAIN must be set in production (SERVER_ENVIRONMENT=production); \
                 otherwise the SIWE domain silently falls back to the server bind host"
            );
        }
        let uri = self.siwe_uri.as_deref().map(str::trim).unwrap_or("");
        if uri.is_empty() {
            bail!(
                "AUTH_SIWE_URI must be set in production (SERVER_ENVIRONMENT=production); \
                 otherwise the SIWE URI silently falls back to an insecure http:// URL"
            );
        }
        if !uri.starts_with("https://") {
            bail!("AUTH_SIWE_URI must use https in production, but is '{uri}'");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Envconfig)]
pub struct DatabaseConfig {
    #[envconfig(from = "DATABASE_CONFLICT_RETRIES", default = "5")]
    pub conflict_retries: usize,
}

#[derive(Debug, Clone, Envconfig)]
pub struct MonitoringConfig {
    #[envconfig(from = "METRICS_UPKEEP_CRON", default = "*/5 * * * * *")]
    pub metrics_upkeep_cron: String,
    #[envconfig(from = "HEALTH_CHECK_CRON", default = "*/30 * * * * *")]
    pub health_check_cron: String,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server_config: ServerConfig,
    pub ethereum_config: EthereumConfig,
    pub database_config: DatabaseConfig,
    pub eip712: Eip712Config,
    pub guarantee: GuaranteeConfig,
    pub settlement_cycle: SettlementCycleConfig,
    pub auth: AuthConfig,
    pub monitoring: MonitoringConfig,
    /// Secrets are loaded into an Arc to avoid multiple allocations of the same secret.
    pub secrets: Arc<Secrets>,
}

impl AppConfig {
    pub fn fetch() -> anyhow::Result<Self> {
        let server_config =
            ServerConfig::init_from_env().context("Failed to load server config")?;
        let ethereum_config =
            EthereumConfig::init_from_env().context("Failed to load ethereum config")?;
        ethereum_config
            .validate(server_config.environment)
            .context("Invalid ethereum config")?;
        let database_config =
            DatabaseConfig::init_from_env().context("Failed to load database config")?;
        let eip712 = Eip712Config::init_from_env().context("Failed to load EIP712 config")?;
        let guarantee =
            GuaranteeConfig::init_from_env().context("Failed to load guarantee config")?;
        guarantee.validate().context("Invalid guarantee config")?;
        let settlement_cycle = SettlementCycleConfig::init_from_env()
            .context("Failed to load settlement cycle config")?;
        settlement_cycle
            .validate()
            .context("Invalid settlement cycle config")?;
        let auth = AuthConfig::init_from_env().context("Failed to load auth config")?;
        auth.validate(server_config.environment)
            .context("Invalid auth config")?;
        let monitoring =
            MonitoringConfig::init_from_env().context("Failed to load monitoring config")?;
        let secrets = Arc::new(
            Secrets::init_from_env(server_config.environment).context("Failed to load secrets")?,
        );

        Ok(Self {
            server_config,
            ethereum_config,
            database_config,
            eip712,
            guarantee,
            settlement_cycle,
            auth,
            monitoring,
            secrets,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthConfig, Environment, EthereumConfig, GuaranteeConfig, SettlementCycleConfig};

    fn base_ethereum_config() -> EthereumConfig {
        EthereumConfig {
            chain_id: 1,
            ws_rpc_url: "ws://localhost:8545".to_string(),
            http_rpc_url: "http://localhost:8545".to_string(),
            public_http_rpc_url: String::new(),
            contract_address: "0x0000000000000000000000000000000000000001".to_string(),
            clearing_house_address: "0x0000000000000000000000000000000000000000".to_string(),
            cron_job_settings: "0 */1 * * * *".to_string(),
            event_scanner_cron: "*/5 * * * * *".to_string(),
            confirmation_mode: "finalized".to_string(),
            number_of_blocks_to_confirm: 20,
            payment_scan_lookback_blocks: 5,
            payment_legacy_scan_enabled: false,
            initial_event_scan_lookback_blocks: 25,
            max_log_block_range: 10000,
            event_handler_max_retries: 5,
            event_handler_retry_base_delay_ms: 200,
        }
    }

    #[test]
    fn ethereum_config_accepts_finalized_in_production() {
        let cfg = base_ethereum_config();
        cfg.validate(Environment::Production)
            .expect("finalized config must be valid in production");
    }

    #[test]
    fn ethereum_config_rejects_reorgable_mode_in_production() {
        let mut cfg = base_ethereum_config();
        cfg.confirmation_mode = "depth".to_string();
        let err = cfg
            .validate(Environment::Production)
            .expect_err("depth mode in production should fail");
        assert!(
            err.to_string()
                .contains("CONFIRMATION_MODE must be `finalized`")
        );
        assert!(err.to_string().contains("SERVER_ENVIRONMENT=development"));
    }

    #[test]
    fn ethereum_config_allows_reorgable_mode_in_development() {
        let mut cfg = base_ethereum_config();
        cfg.confirmation_mode = "depth".to_string();
        cfg.validate(Environment::Development)
            .expect("depth mode should be allowed in development");
    }

    #[test]
    fn ethereum_config_accepts_finalized_in_development() {
        let cfg = base_ethereum_config();
        cfg.validate(Environment::Development)
            .expect("finalized config must be valid in development");
    }

    #[test]
    fn environment_parses_case_insensitively() {
        use std::str::FromStr;
        assert_eq!(
            Environment::from_str("PRODUCTION").unwrap(),
            Environment::Production
        );
        assert_eq!(
            Environment::from_str(" development ").unwrap(),
            Environment::Development
        );
        assert!(Environment::from_str("staging").is_err());
    }

    fn auth_config(siwe_domain: Option<&str>, siwe_uri: Option<&str>) -> AuthConfig {
        AuthConfig {
            nonce_ttl_secs: 300,
            refresh_ttl_secs: 2_592_000,
            access_ttl_secs: 900,
            jwt_issuer: "4mica-core".to_string(),
            jwt_audience: "4mica".to_string(),
            siwe_statement: "Sign in to 4mica.".to_string(),
            siwe_domain: siwe_domain.map(str::to_string),
            siwe_uri: siwe_uri.map(str::to_string),
        }
    }

    #[test]
    fn auth_config_development_allows_siwe_fallbacks() {
        auth_config(None, None)
            .validate(Environment::Development)
            .expect("development must permit SIWE fallbacks");
    }

    #[test]
    fn auth_config_production_requires_siwe_domain() {
        let err = auth_config(None, Some("https://app.4mica.io"))
            .validate(Environment::Production)
            .expect_err("missing SIWE domain must fail in production");
        assert!(err.to_string().contains("AUTH_SIWE_DOMAIN"));
    }

    #[test]
    fn auth_config_production_requires_siwe_uri() {
        let err = auth_config(Some("app.4mica.io"), None)
            .validate(Environment::Production)
            .expect_err("missing SIWE uri must fail in production");
        assert!(err.to_string().contains("AUTH_SIWE_URI"));
    }

    #[test]
    fn auth_config_production_rejects_insecure_siwe_uri() {
        let err = auth_config(Some("app.4mica.io"), Some("http://app.4mica.io"))
            .validate(Environment::Production)
            .expect_err("http SIWE uri must fail in production");
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn auth_config_production_accepts_explicit_https_siwe() {
        auth_config(Some("app.4mica.io"), Some("https://app.4mica.io"))
            .validate(Environment::Production)
            .expect("explicit https SIWE config must be valid in production");
    }

    fn guarantee_config(validators: &str) -> GuaranteeConfig {
        GuaranteeConfig {
            validators: validators.to_string(),
            validation_poll_cron: "0 */1 * * * *".to_string(),
            min_validation_window_secs: None,
        }
    }

    #[test]
    fn guarantee_config_accepts_an_empty_validator_whitelist() {
        let cfg = guarantee_config("[]");
        cfg.validate().expect("no validators is a valid config");
        assert!(cfg.validators().expect("parse").is_empty());
    }

    #[test]
    fn guarantee_config_parses_validators() {
        let cfg = guarantee_config(
            r#"[
                {"uri": "eip155:8453:0x1111111111111111111111111111111111111111",
                 "kind": "erc8004"},
                {"uri": "https://validator.acme.io/checks",
                 "kind": "http-json-v1",
                 "config": {"timeout_ms": 1000}}
            ]"#,
        );
        cfg.validate().expect("valid validators");

        let validators = cfg.validators().expect("parse");
        assert_eq!(validators.len(), 2);
        assert_eq!(validators[0].kind, "erc8004");
        assert_eq!(validators[1].kind, "http-json-v1");
    }

    #[test]
    fn guarantee_config_rejects_malformed_validators() {
        let err = guarantee_config("not json")
            .validate()
            .expect_err("malformed GUARANTEE_VALIDATORS must fail");
        assert!(err.to_string().contains("GUARANTEE_VALIDATORS"));
    }

    #[test]
    fn guarantee_config_rejects_duplicate_validators() {
        let err = guarantee_config(
            r#"[
                {"uri": "https://validator.acme.io/checks", "kind": "http-json-v1"},
                {"uri": "https://validator.acme.io/checks", "kind": "http-json-v1"}
            ]"#,
        )
        .validate()
        .expect_err("duplicate validator uris must fail");
        assert!(err.to_string().contains("duplicate validator"));
    }

    #[test]
    fn guarantee_config_rejects_empty_validator_uri() {
        let err = guarantee_config(r#"[{"uri": "  ", "kind": "http-json-v1"}]"#)
            .validate()
            .expect_err("empty uri must fail");
        assert!(err.to_string().contains("empty uri"));
    }

    #[test]
    fn guarantee_config_rejects_empty_poll_cron() {
        let mut cfg = guarantee_config("[]");
        cfg.validation_poll_cron = "   ".to_string();
        let err = cfg.validate().expect_err("empty cron must fail");
        assert!(err.to_string().contains("VALIDATION_POLL_CRON"));
    }

    fn default_settlement_cycle_config() -> SettlementCycleConfig {
        SettlementCycleConfig {
            cycle_secs: 86_400,
            resolution_cutoff_secs: 21_600,
            clearing_commit_delay_secs: 900,
            payment_submission_window_secs: 7_200,
            payment_finality_window_secs: 14_400,
            seizure_margin_secs: 21_600,
            default_batch_size: 50,
            shortfall_grace_secs: 21_600,
            settlement_retry_delay_secs: 1_800,
            hanging_retry_windows: 3,
        }
    }

    #[test]
    fn settlement_cycle_config_accepts_defaults() {
        default_settlement_cycle_config()
            .validate()
            .expect("default settlement cycle config must be valid");
    }

    #[test]
    fn settlement_cycle_config_rejects_zero_cycle_length() {
        let cfg = SettlementCycleConfig {
            cycle_secs: 0,
            ..default_settlement_cycle_config()
        };

        let err = cfg
            .validate()
            .expect_err("zero cycle length must be rejected");
        assert!(err.to_string().contains("SETTLEMENT_CYCLE_SECS"));
    }

    #[test]
    fn settlement_cycle_config_rejects_zero_seizure_margin() {
        let cfg = SettlementCycleConfig {
            seizure_margin_secs: 0,
            ..default_settlement_cycle_config()
        };

        let err = cfg
            .validate()
            .expect_err("zero seizure margin must be rejected");
        assert!(err.to_string().contains("SETTLEMENT_SEIZURE_MARGIN_SECS"));
    }

    #[test]
    fn settlement_cycle_config_rejects_zero_shortfall_grace() {
        let cfg = SettlementCycleConfig {
            shortfall_grace_secs: 0,
            ..default_settlement_cycle_config()
        };

        let err = cfg
            .validate()
            .expect_err("zero shortfall grace must be rejected");
        assert!(err.to_string().contains("SETTLEMENT_SHORTFALL_GRACE_SECS"));
    }

    #[test]
    fn settlement_cycle_config_rejects_shortfall_grace_above_seizure_margin() {
        let cfg = SettlementCycleConfig {
            shortfall_grace_secs: 21_601,
            seizure_margin_secs: 21_600,
            ..default_settlement_cycle_config()
        };

        let err = cfg
            .validate()
            .expect_err("shortfall grace above seizure margin must be rejected");
        assert!(err.to_string().contains("SETTLEMENT_SHORTFALL_GRACE_SECS"));
        assert!(err.to_string().contains("SETTLEMENT_SEIZURE_MARGIN_SECS"));
    }

    #[test]
    fn settlement_cycle_config_rejects_finality_before_submission() {
        let cfg = SettlementCycleConfig {
            payment_finality_window_secs: 3_600,
            ..default_settlement_cycle_config()
        };

        let err = cfg
            .validate()
            .expect_err("finality before submission must be rejected");
        assert!(
            err.to_string()
                .contains("SETTLEMENT_PAYMENT_FINALITY_WINDOW_SECS")
        );
    }

    #[test]
    fn cycle_to_finality_sums_the_deadline_chain() {
        let cfg = default_settlement_cycle_config();
        // 86_400 + 21_600 + 900 + 14_400
        assert_eq!(cfg.cycle_to_finality_secs(), 123_300);
    }

    #[test]
    fn grace_period_invariant_accepts_onchain_defaults() {
        // On-chain default withdrawalGracePeriod is 22 days.
        let cfg = default_settlement_cycle_config();
        cfg.validate_against_withdrawal_grace_period(22 * 24 * 60 * 60)
            .expect("default cycle config must satisfy the 22-day grace period");
    }

    #[test]
    fn grace_period_invariant_rejects_too_short_grace() {
        let cfg = default_settlement_cycle_config();
        // required = cycle_to_finality (123_300) + seizure_margin (21_600) = 144_900.
        let required = cfg.cycle_to_finality_secs() + cfg.seizure_margin_secs;

        // Exactly equal must be rejected (strict inequality).
        let err = cfg
            .validate_against_withdrawal_grace_period(required)
            .expect_err("grace period equal to required margin must be rejected");
        assert!(err.to_string().contains("withdrawalGracePeriod"));

        // One second above the requirement is accepted.
        cfg.validate_against_withdrawal_grace_period(required + 1)
            .expect("grace period one second above the requirement must be accepted");
    }
}
