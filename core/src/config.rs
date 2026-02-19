use std::{str::FromStr, sync::Arc};

use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, bail};
use crypto::bls::KeyMaterial;
use envconfig::Envconfig;
use jsonwebtoken::{DecodingKey, EncodingKey};
use log::warn;
use secrecy::zeroize::Zeroize;

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

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server_config: ServerConfig,
    pub ethereum_config: EthereumConfig,
    pub database_config: DatabaseConfig,
    pub eip712: Eip712Config,
    pub auth: AuthConfig,
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
        let auth = AuthConfig::init_from_env().context("Failed to load auth config")?;
        let secrets = Arc::new(Secrets::init_from_env().context("Failed to load secrets")?);

        Ok(Self {
            server_config,
            ethereum_config,
            database_config,
            eip712,
            auth,
            secrets,
        })
    }
}
