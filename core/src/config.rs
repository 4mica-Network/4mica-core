use std::{str::FromStr, sync::Arc};

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, bail};
use crypto::bls::KeyMaterial;
use envconfig::Envconfig;
use jsonwebtoken::{DecodingKey, EncodingKey};
use log::warn;
use rpc::{
    GUARANTEE_CLAIMS_VERSION, SUPPORTED_GUARANTEE_VERSIONS, is_supported_guarantee_version,
    version_requires_validation_registry,
};
use secrecy::zeroize::Zeroize;

pub const DEFAULT_TTL_SECS: u64 = 3600 * 24;

pub const DEFAULT_ASSET_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
pub const VALIDATION_HASH_CANONICALIZATION_VERSION_V1: &str =
    rpc::VALIDATION_REQUEST_BINDING_DOMAIN_V1;
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
}

#[derive(Debug, Clone, Envconfig)]
pub struct EthereumConfig {
    #[envconfig(from = "ETHEREUM_CHAIN_ID", default = "1")]
    pub chain_id: u64,
    #[envconfig(from = "ETHEREUM_WS_RPC_URL")]
    pub ws_rpc_url: String,
    #[envconfig(from = "ETHEREUM_HTTP_RPC_URL")]
    pub http_rpc_url: String,
    #[envconfig(from = "ETHEREUM_CONTRACT_ADDRESS")]
    pub contract_address: String,
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
    /// When scanning for events and cursor is not found in the database, scan back this many blocks.
    #[envconfig(from = "INITIAL_EVENT_SCAN_LOOKBACK_BLOCKS", default = "25")]
    pub initial_event_scan_lookback_blocks: u64,
    /// Maximum block span for a single eth_getLogs request.
    #[envconfig(from = "ETHEREUM_MAX_LOG_BLOCK_RANGE", default = "10000")]
    pub max_log_block_range: u64,
    /// When CONFIRMATION_MODE=finalized and the provider doesn't advance finalized head,
    /// treat blocks as finalized after this depth (useful for local dev/test only).
    #[envconfig(from = "FINALIZED_HEAD_DEPTH", default = "0")]
    pub finalized_head_depth: u64,
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

    pub fn validate(&self) -> anyhow::Result<()> {
        let mode = self.confirmation_mode()?;
        if mode != ConfirmationMode::Finalized {
            bail!(
                "CONFIRMATION_MODE must be finalized when processing on-chain data without rollback"
            );
        }
        if mode == ConfirmationMode::Finalized && self.finalized_head_depth > 0 {
            warn!(
                "FINALIZED_HEAD_DEPTH={} is set; finalized mode will treat latest-N blocks as finalized. This is not safe for production.",
                self.finalized_head_depth
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
    /// Ceiling for the default accepted-version range. The output guarantee version is always
    /// determined by the incoming claim payload — this value only controls which versions core
    /// will accept and which on-chain domain separators are loaded at startup.
    #[envconfig(from = "GUARANTEE_REQUEST_VERSION", default = "1")]
    pub max_accepted_version: u64,
    #[envconfig(from = "GUARANTEE_ACCEPTED_REQUEST_VERSIONS", default = "")]
    pub accepted_request_versions: String,
    #[envconfig(from = "TRUSTED_VALIDATION_REGISTRIES", default = "")]
    pub trusted_validation_registries: String,
    #[envconfig(
        from = "VALIDATION_HASH_CANONICALIZATION_VERSION",
        default = "4MICA_VALIDATION_REQUEST_V1"
    )]
    pub validation_hash_canonicalization_version: String,
}

impl GuaranteeConfig {
    pub fn accepted_request_versions(&self) -> anyhow::Result<Vec<u64>> {
        let mut versions = if self.accepted_request_versions.trim().is_empty() {
            // Default: accept every version from 1 up to max_accepted_version so that
            // upgrading to V3 (or higher) automatically accepts all prior versions too.
            (GUARANTEE_CLAIMS_VERSION..=self.max_accepted_version).collect()
        } else {
            self.accepted_request_versions
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    value.parse::<u64>().map_err(|_| {
                        anyhow::anyhow!(
                            "invalid guarantee request version in GUARANTEE_ACCEPTED_REQUEST_VERSIONS: {value}"
                        )
                    })
                })
                .collect::<anyhow::Result<Vec<u64>>>()?
        };

        versions.sort_unstable();
        versions.dedup();
        Ok(versions)
    }

    pub fn trusted_validation_registry_allowlist(&self) -> anyhow::Result<Vec<String>> {
        self.trusted_validation_registries
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                Address::from_str(value)
                    .map(|addr| addr.to_string())
                    .map_err(|_| anyhow::anyhow!("invalid validation registry address: {value}"))
            })
            .collect()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        validate_guarantee_version(self.max_accepted_version, "GUARANTEE_REQUEST_VERSION")?;
        let accepted_versions = self.accepted_request_versions()?;
        for version in &accepted_versions {
            validate_guarantee_version(*version, "GUARANTEE_ACCEPTED_REQUEST_VERSIONS")?;
        }
        let canonicalization_version = self.validation_hash_canonicalization_version.trim();
        if canonicalization_version.is_empty() {
            bail!("VALIDATION_HASH_CANONICALIZATION_VERSION must not be empty");
        }
        if canonicalization_version != VALIDATION_HASH_CANONICALIZATION_VERSION_V1 {
            bail!(
                "unsupported VALIDATION_HASH_CANONICALIZATION_VERSION '{}'; supported: {}",
                canonicalization_version,
                VALIDATION_HASH_CANONICALIZATION_VERSION_V1
            );
        }

        // Ensures all configured addresses are valid and normalized.
        let allowlist = self.trusted_validation_registry_allowlist()?;
        // Any validation-gated version (V2+) requires on-chain validation; ensure the allowlist is set.
        if accepted_versions
            .iter()
            .any(|&v| version_requires_validation_registry(v))
            && allowlist.is_empty()
        {
            bail!(
                "TRUSTED_VALIDATION_REGISTRIES must include at least one registry when validation-gated guarantee versions are accepted"
            );
        }
        Ok(())
    }
}

fn validate_guarantee_version(version: u64, field: &str) -> anyhow::Result<()> {
    if !is_supported_guarantee_version(version) {
        let supported = SUPPORTED_GUARANTEE_VERSIONS
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        bail!("unsupported {field} '{version}'; supported: {supported}");
    }
    Ok(())
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
    pub fn init_from_env() -> anyhow::Result<Self> {
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
        if secret == PLACEHOLDER_AUTH_JWT_SECRET {
            warn!("AUTH_JWT_SECRET uses the placeholder value; replace with a 32+ byte secret");
        } else if secret.len() < 32 {
            warn!("AUTH_JWT_SECRET is shorter than 32 bytes; use a 32+ byte secret in production");
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
            .validate()
            .context("Invalid ethereum config")?;
        let database_config =
            DatabaseConfig::init_from_env().context("Failed to load database config")?;
        let eip712 = Eip712Config::init_from_env().context("Failed to load EIP712 config")?;
        let guarantee =
            GuaranteeConfig::init_from_env().context("Failed to load guarantee config")?;
        guarantee.validate().context("Invalid guarantee config")?;
        let auth = AuthConfig::init_from_env().context("Failed to load auth config")?;
        let monitoring =
            MonitoringConfig::init_from_env().context("Failed to load monitoring config")?;
        let secrets = Arc::new(Secrets::init_from_env().context("Failed to load secrets")?);

        Ok(Self {
            server_config,
            ethereum_config,
            database_config,
            eip712,
            guarantee,
            auth,
            monitoring,
            secrets,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::GuaranteeConfig;

    #[test]
    fn guarantee_config_accepts_valid_v1_and_v2() {
        let v1 = GuaranteeConfig {
            max_accepted_version: 1,
            accepted_request_versions: String::new(),
            trusted_validation_registries: String::new(),
            validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V1".to_string(),
        };
        v1.validate().expect("v1 config must be valid");

        let v2 = GuaranteeConfig {
            max_accepted_version: 2,
            accepted_request_versions: String::new(),
            trusted_validation_registries:
                "0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222"
                    .to_string(),
            validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V1".to_string(),
        };
        v2.validate().expect("v2 config must be valid");
        let allowlist = v2
            .trusted_validation_registry_allowlist()
            .expect("allowlist should parse");
        assert_eq!(allowlist.len(), 2);
    }

    #[test]
    fn guarantee_config_rejects_invalid_registry_allowlist() {
        let cfg = GuaranteeConfig {
            max_accepted_version: 2,
            accepted_request_versions: String::new(),
            trusted_validation_registries:
                "0x1111111111111111111111111111111111111111,not-an-address".to_string(),
            validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V1".to_string(),
        };
        let err = cfg
            .validate()
            .expect_err("invalid allowlist should be rejected");
        assert!(
            err.to_string()
                .contains("invalid validation registry address")
        );
    }

    #[test]
    fn guarantee_config_rejects_invalid_hash_canonicalization_version() {
        let cfg = GuaranteeConfig {
            max_accepted_version: 2,
            accepted_request_versions: String::new(),
            trusted_validation_registries: "0x1111111111111111111111111111111111111111".to_string(),
            validation_hash_canonicalization_version: "   ".to_string(),
        };
        let err = cfg
            .validate()
            .expect_err("empty canonicalization version should fail");
        assert!(
            err.to_string()
                .contains("VALIDATION_HASH_CANONICALIZATION_VERSION")
        );
    }

    #[test]
    fn guarantee_config_rejects_unsupported_hash_canonicalization_version() {
        let cfg = GuaranteeConfig {
            max_accepted_version: 2,
            accepted_request_versions: String::new(),
            trusted_validation_registries: "0x1111111111111111111111111111111111111111".to_string(),
            validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
        };
        let err = cfg
            .validate()
            .expect_err("unsupported canonicalization version should fail");
        assert!(
            err.to_string()
                .contains("unsupported VALIDATION_HASH_CANONICALIZATION_VERSION")
        );
    }

    #[test]
    fn guarantee_config_rejects_v2_without_trusted_validation_registries() {
        let cfg = GuaranteeConfig {
            max_accepted_version: 2,
            accepted_request_versions: String::new(),
            trusted_validation_registries: String::new(),
            validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V1".to_string(),
        };
        let err = cfg
            .validate()
            .expect_err("v2 config without allowlist should fail");
        assert!(err.to_string().contains("TRUSTED_VALIDATION_REGISTRIES"));
    }

    #[test]
    fn guarantee_config_rejects_unsupported_request_version() {
        let cfg = GuaranteeConfig {
            max_accepted_version: 3,
            accepted_request_versions: String::new(),
            trusted_validation_registries: String::new(),
            validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V1".to_string(),
        };
        let err = cfg
            .validate()
            .expect_err("unsupported guarantee request version should fail");
        assert!(
            err.to_string()
                .contains("unsupported GUARANTEE_REQUEST_VERSION")
        );
    }

    #[test]
    fn guarantee_config_defaults_to_accepting_v1_and_v2_when_active_is_v2() {
        let cfg = GuaranteeConfig {
            max_accepted_version: 2,
            accepted_request_versions: String::new(),
            trusted_validation_registries: "0x1111111111111111111111111111111111111111".to_string(),
            validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V1".to_string(),
        };

        let versions = cfg
            .accepted_request_versions()
            .expect("accepted versions should resolve");
        assert_eq!(versions, vec![1, 2]);
    }

    #[test]
    fn guarantee_config_accepts_explicit_accepted_versions() {
        let cfg = GuaranteeConfig {
            max_accepted_version: 2,
            accepted_request_versions: "2".to_string(),
            trusted_validation_registries: "0x1111111111111111111111111111111111111111".to_string(),
            validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V1".to_string(),
        };

        let versions = cfg
            .accepted_request_versions()
            .expect("accepted versions should resolve");
        assert_eq!(versions, vec![2]);
    }
}
