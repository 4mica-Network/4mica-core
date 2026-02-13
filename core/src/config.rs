use anyhow::{Context, bail};
use crypto::hex::HexBytes;
use envconfig::Envconfig;
use log::warn;

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
    #[envconfig(from = "NUMBER_OF_BLOCKS_TO_CONFIRM", default = "20")]
    pub number_of_blocks_to_confirm: u64,
    /// Confirmation policy for on-chain data:
    /// `depth` = confirm after N blocks (NUMBER_OF_BLOCKS_TO_CONFIRM),
    /// `safe` = confirm at the chain's "safe" head,
    /// `finalized` = confirm at the chain's finalized head (safest).
    #[envconfig(from = "CONFIRMATION_MODE", default = "finalized")]
    pub confirmation_mode: String,
    #[envconfig(from = "NUMBER_OF_PENDING_BLOCKS", default = "5")]
    pub number_of_pending_blocks: u64,
    /// When CONFIRMATION_MODE=finalized and the provider doesn't advance finalized head,
    /// treat blocks as finalized after this depth (useful for local dev/test only).
    #[envconfig(from = "FINALIZED_HEAD_DEPTH", default = "0")]
    pub finalized_head_depth: u64,
    #[envconfig(from = "ETHEREUM_PRIVATE_KEY")]
    pub ethereum_private_key: String,
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
        if mode == ConfirmationMode::Depth && self.number_of_blocks_to_confirm == 0 {
            bail!("NUMBER_OF_BLOCKS_TO_CONFIRM must be > 0 when CONFIRMATION_MODE=depth");
        }
        if self.number_of_pending_blocks == 0 {
            bail!("NUMBER_OF_PENDING_BLOCKS must be > 0");
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
pub struct Secrets {
    #[envconfig(from = "BLS_PRIVATE_KEY")]
    pub bls_private_key: HexBytes,
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

    #[envconfig(from = "AUTH_JWT_SECRET", default = "dev-insecure-change-me")]
    pub jwt_hmac_secret: String,

    #[envconfig(from = "AUTH_SIWE_STATEMENT", default = "Sign in to 4mica.")]
    pub siwe_statement: String,

    #[envconfig(from = "AUTH_SIWE_DOMAIN")]
    pub siwe_domain: Option<String>,

    #[envconfig(from = "AUTH_SIWE_URI")]
    pub siwe_uri: Option<String>,
}

impl AuthConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        let secret = self.jwt_hmac_secret.trim();
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
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server_config: ServerConfig,
    pub ethereum_config: EthereumConfig,
    pub secrets: Secrets,
    pub eip712: Eip712Config,
    pub auth: AuthConfig,
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
        let secrets = Secrets::init_from_env().context("Failed to load secrets")?;
        let eip712 = Eip712Config::init_from_env().context("Failed to load EIP712 config")?;
        let auth = AuthConfig::init_from_env().context("Failed to load auth config")?;
        auth.validate().context("Invalid auth config")?;

        Ok(Self {
            server_config,
            ethereum_config,
            secrets,
            eip712,
            auth,
        })
    }
}
