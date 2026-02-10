use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use url::Url;

use crate::{
    error::ConfigError,
    validators::{validate_address, validate_url, validate_wallet_private_key},
};

const DEFAULT_AUTH_REFRESH_MARGIN_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub auth_url: Url,
    pub refresh_margin_secs: u64,
}

#[derive(Debug, Clone)]
pub struct Config<S> {
    pub rpc_url: Url,
    pub signer: S,
    pub ethereum_http_rpc_url: Option<Url>,
    pub contract_address: Option<Address>,
    pub bearer_token: Option<String>,
    pub auth: Option<AuthConfig>,
}

pub struct ConfigBuilder<S = PrivateKeySigner> {
    rpc_url: Option<String>,
    signer: Option<S>,
    ethereum_http_rpc_url: Option<String>,
    contract_address: Option<String>,
    bearer_token: Option<String>,
    auth_url: Option<String>,
    auth_refresh_margin_secs: Option<u64>,
    auth_refresh_margin_parse_error: Option<String>,
    auth_enabled: bool,
}

impl ConfigBuilder<PrivateKeySigner> {
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut builder = Self::empty();

        if let Ok(v) = std::env::var("4MICA_RPC_URL") {
            builder = builder.rpc_url(v);
        }
        if let Ok(v) = std::env::var("4MICA_WALLET_PRIVATE_KEY") {
            builder = builder.signer(
                validate_wallet_private_key(&v)
                    .map_err(|e| ConfigError::InvalidValue(e.to_string()))?,
            );
        }
        if let Ok(v) = std::env::var("4MICA_ETHEREUM_HTTP_RPC_URL") {
            builder = builder.ethereum_http_rpc_url(v);
        }
        if let Ok(v) = std::env::var("4MICA_CONTRACT_ADDRESS") {
            builder = builder.contract_address(v);
        }
        if let Ok(v) = std::env::var("4MICA_BEARER_TOKEN") {
            builder = builder.bearer_token(v);
        }
        if let Ok(v) = std::env::var("4MICA_AUTH_URL") {
            builder = builder.auth_url(v);
        }
        if let Ok(v) = std::env::var("4MICA_AUTH_REFRESH_MARGIN_SECS") {
            match v.parse::<u64>() {
                Ok(secs) => {
                    builder = builder.auth_refresh_margin_secs(secs);
                }
                Err(_) => {
                    builder.auth_refresh_margin_parse_error = Some(v);
                    builder.auth_enabled = true;
                }
            }
        }

        Ok(builder)
    }
}

impl<S> ConfigBuilder<S> {
    fn empty() -> Self {
        Self {
            rpc_url: None,
            signer: None,
            ethereum_http_rpc_url: None,
            contract_address: None,
            bearer_token: None,
            auth_url: None,
            auth_refresh_margin_secs: None,
            auth_refresh_margin_parse_error: None,
            auth_enabled: false,
        }
    }

    pub fn rpc_url(mut self, rpc_url: String) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }

    pub fn signer(mut self, signer: S) -> Self {
        self.signer = Some(signer);
        self
    }

    /// If not provided, the default config will be fetched from the server.
    /// You normally don't need to provide this!
    pub fn ethereum_http_rpc_url(mut self, ethereum_http_rpc_url: String) -> Self {
        self.ethereum_http_rpc_url = Some(ethereum_http_rpc_url);
        self
    }

    /// If not provided, the default config will be fetched from the server.
    /// You normally don't need to provide this!
    pub fn contract_address(mut self, contract_address: String) -> Self {
        self.contract_address = Some(contract_address);
        self
    }

    /// Optional bearer token for authenticated core HTTP calls.
    pub fn bearer_token(mut self, bearer_token: String) -> Self {
        self.bearer_token = Some(bearer_token);
        self
    }

    /// Enable SIWE authentication using the core auth endpoints.
    pub fn enable_auth(mut self) -> Self {
        self.auth_enabled = true;
        self
    }

    /// Optional auth base URL. Defaults to the RPC URL when auth is enabled.
    pub fn auth_url(mut self, auth_url: String) -> Self {
        self.auth_url = Some(auth_url);
        self.auth_enabled = true;
        self
    }

    /// Refresh access tokens when the remaining TTL is below this threshold (in seconds).
    pub fn auth_refresh_margin_secs(mut self, secs: u64) -> Self {
        self.auth_refresh_margin_secs = Some(secs);
        self.auth_enabled = true;
        self
    }

    pub fn build(self) -> Result<Config<S>, ConfigError> {
        let rpc_url = Self::required(self.rpc_url, "rpc_url")?;

        let signer = Self::required(self.signer, "signer")?;

        let rpc_url =
            validate_url(&rpc_url).map_err(|e| ConfigError::InvalidValue(e.to_string()))?;

        let ethereum_http_rpc_url = Self::optional(
            self.ethereum_http_rpc_url,
            validate_url,
            "ethereum_http_rpc_url",
        )?;
        let contract_address =
            Self::optional(self.contract_address, validate_address, "contract_address")?;
        let bearer_token = self.bearer_token.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });

        if let Some(raw) = self.auth_refresh_margin_parse_error {
            return Err(ConfigError::InvalidValue(format!(
                "invalid auth_refresh_margin_secs: {raw}"
            )));
        }

        let auth = if self.auth_enabled {
            let auth_url = match self.auth_url {
                Some(raw) => {
                    validate_url(&raw).map_err(|e| ConfigError::InvalidValue(e.to_string()))?
                }
                None => rpc_url.clone(),
            };
            let refresh_margin_secs = self
                .auth_refresh_margin_secs
                .unwrap_or(DEFAULT_AUTH_REFRESH_MARGIN_SECS);
            Some(AuthConfig {
                auth_url,
                refresh_margin_secs,
            })
        } else {
            None
        };

        Ok(Config {
            rpc_url,
            signer,
            ethereum_http_rpc_url,
            contract_address,
            bearer_token,
            auth,
        })
    }

    fn required<T>(value: Option<T>, field: &str) -> Result<T, ConfigError> {
        value.ok_or_else(|| ConfigError::Missing(field.to_string()))
    }

    fn optional<T>(
        value: Option<String>,
        parser: impl FnOnce(&str) -> anyhow::Result<T>,
        _field: &str,
    ) -> Result<Option<T>, ConfigError> {
        match value {
            Some(raw) => parser(&raw)
                .map(Some)
                .map_err(|e| ConfigError::InvalidValue(e.to_string())),
            None => Ok(None),
        }
    }
}

impl<S> Default for ConfigBuilder<S> {
    fn default() -> Self {
        Self::empty().rpc_url("https://api.4mica.xyz/".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use serial_test::serial;

    const VALID_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const VALID_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
    const VALID_RPC_URL: &str = "http://api.4mica.xyz/";
    const VALID_ETH_RPC_URL: &str = "http://localhost:8545/";

    #[test]
    fn test_default_builder() {
        let builder = ConfigBuilder::<PrivateKeySigner>::default();

        assert_eq!(builder.rpc_url, Some("https://api.4mica.xyz/".to_string()));
        assert!(builder.signer.is_none());
        assert!(builder.ethereum_http_rpc_url.is_none());
        assert!(builder.contract_address.is_none());
        assert!(builder.bearer_token.is_none());
        assert!(builder.auth_url.is_none());
        assert!(builder.auth_refresh_margin_secs.is_none());
        assert!(!builder.auth_enabled);
    }

    #[test]
    fn test_build_with_required_fields_only() {
        let local_signer =
            PrivateKeySigner::from_str(VALID_PRIVATE_KEY).expect("Invalid private key");

        let config = ConfigBuilder::default()
            .signer(local_signer.clone())
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.rpc_url.as_str(), "https://api.4mica.xyz/");
        assert_eq!(config.signer.address(), local_signer.address());
        assert!(config.ethereum_http_rpc_url.is_none());
        assert!(config.contract_address.is_none());
        assert!(config.bearer_token.is_none());
        assert!(config.auth.is_none());
    }

    #[test]
    fn test_build_with_all_fields() {
        let local_signer =
            PrivateKeySigner::from_str(VALID_PRIVATE_KEY).expect("Invalid private key");

        let config = ConfigBuilder::default()
            .rpc_url(VALID_RPC_URL.to_string())
            .signer(local_signer.clone())
            .ethereum_http_rpc_url(VALID_ETH_RPC_URL.to_string())
            .contract_address(VALID_ADDRESS.to_string())
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.rpc_url.as_str(), VALID_RPC_URL);
        assert_eq!(config.signer.address(), local_signer.address());
        assert_eq!(
            config.ethereum_http_rpc_url.unwrap().as_str(),
            VALID_ETH_RPC_URL
        );
        assert_eq!(config.contract_address.unwrap().to_string(), VALID_ADDRESS);
        assert!(config.bearer_token.is_none());
        assert!(config.auth.is_none());
    }

    #[test]
    fn test_build_missing_signer() {
        let config = ConfigBuilder::<PrivateKeySigner>::default().build();

        assert!(config.is_err());
        match config.unwrap_err() {
            ConfigError::Missing(field) => assert_eq!(field, "signer"),
            _ => panic!("Expected Missing error"),
        }
    }

    #[test]
    fn test_build_invalid_rpc_url() {
        let config = ConfigBuilder::default()
            .rpc_url("not-a-valid-url".to_string())
            .signer(PrivateKeySigner::from_str(VALID_PRIVATE_KEY).expect("Invalid private key"))
            .build();

        assert!(config.is_err());
        match config.unwrap_err() {
            ConfigError::InvalidValue(msg) => assert!(msg.contains("invalid URL")),
            _ => panic!("Expected InvalidValue error"),
        }
    }

    #[test]
    fn test_build_invalid_ethereum_http_rpc_url() {
        let config = ConfigBuilder::default()
            .signer(PrivateKeySigner::from_str(VALID_PRIVATE_KEY).expect("Invalid private key"))
            .ethereum_http_rpc_url("not-a-valid-url".to_string())
            .build();

        assert!(config.is_err());
        match config.unwrap_err() {
            ConfigError::InvalidValue(msg) => assert!(msg.contains("invalid URL")),
            _ => panic!("Expected InvalidValue error"),
        }
    }

    #[test]
    fn test_build_invalid_contract_address() {
        let config = ConfigBuilder::default()
            .signer(PrivateKeySigner::from_str(VALID_PRIVATE_KEY).expect("Invalid private key"))
            .contract_address("not-a-valid-address".to_string())
            .build();

        assert!(config.is_err());
        match config.unwrap_err() {
            ConfigError::InvalidValue(msg) => assert!(msg.contains("invalid address")),
            _ => panic!("Expected InvalidValue error"),
        }
    }

    #[test]
    #[serial]
    fn test_from_env_with_all_vars() {
        let local_signer =
            PrivateKeySigner::from_str(VALID_PRIVATE_KEY).expect("Invalid private key");

        unsafe {
            std::env::set_var("4MICA_RPC_URL", VALID_RPC_URL);
            std::env::set_var("4MICA_WALLET_PRIVATE_KEY", VALID_PRIVATE_KEY);
            std::env::set_var("4MICA_ETHEREUM_HTTP_RPC_URL", VALID_ETH_RPC_URL);
            std::env::set_var("4MICA_CONTRACT_ADDRESS", VALID_ADDRESS);
            std::env::set_var("4MICA_BEARER_TOKEN", "test-token");
        }

        let config = ConfigBuilder::from_env()
            .expect("Invalid environment variables")
            .build();

        // Clean up
        unsafe {
            std::env::remove_var("4MICA_RPC_URL");
            std::env::remove_var("4MICA_WALLET_PRIVATE_KEY");
            std::env::remove_var("4MICA_ETHEREUM_HTTP_RPC_URL");
            std::env::remove_var("4MICA_CONTRACT_ADDRESS");
            std::env::remove_var("4MICA_BEARER_TOKEN");
        }

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.rpc_url.as_str(), VALID_RPC_URL);
        assert_eq!(config.signer.address(), local_signer.address());
        assert_eq!(
            config.ethereum_http_rpc_url.unwrap().as_str(),
            VALID_ETH_RPC_URL
        );
        assert_eq!(config.contract_address.unwrap().to_string(), VALID_ADDRESS);
        assert_eq!(config.bearer_token.as_deref(), Some("test-token"));
        assert!(config.auth.is_none());
    }

    #[test]
    #[serial]
    fn test_from_env_with_partial_vars() {
        unsafe {
            std::env::set_var("4MICA_RPC_URL", VALID_RPC_URL);
        }

        let local_signer =
            validate_wallet_private_key(VALID_PRIVATE_KEY).expect("Invalid private key");

        let config = ConfigBuilder::from_env()
            .expect("Invalid environment variables")
            .signer(local_signer.clone())
            .build();

        // Clean up
        unsafe {
            std::env::remove_var("4MICA_RPC_URL");
        }

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.rpc_url.as_str(), VALID_RPC_URL);
        assert_eq!(config.signer.address(), local_signer.address());
    }
}
