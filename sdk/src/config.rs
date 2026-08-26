use std::str::FromStr;

use alloy::{primitives::Address, signers::Signer, signers::local::PrivateKeySigner};
use url::Url;
use zeroize::Zeroize;

use crate::{
    client::Client,
    error::{ConfigError, Error},
    validators::{validate_address, validate_url, validate_wallet_private_key},
};

const DEFAULT_AUTH_REFRESH_MARGIN_SECS: u64 = 60;
const DEFAULT_RPC_URL: &str = "https://ethereum.sepolia.api.4mica.xyz/";

/// A network this SDK has a default core endpoint for. Parses from the shorthand (`"base"`) or
/// the CAIP-2 id (`"eip155:8453"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Base,
    BaseSepolia,
    EthereumSepolia,
}

impl Network {
    pub fn caip2(&self) -> &'static str {
        match self {
            Self::Base => "eip155:8453",
            Self::BaseSepolia => "eip155:84532",
            Self::EthereumSepolia => "eip155:11155111",
        }
    }

    pub fn rpc_url(&self) -> &'static str {
        match self {
            Self::Base => "https://base.api.4mica.xyz/",
            Self::BaseSepolia => "https://base.sepolia.api.4mica.xyz/",
            Self::EthereumSepolia => "https://ethereum.sepolia.api.4mica.xyz/",
        }
    }
}

impl FromStr for Network {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "base" | "eip155:8453" => Ok(Self::Base),
            "base-sepolia" | "eip155:84532" => Ok(Self::BaseSepolia),
            "ethereum-sepolia" | "eip155:11155111" => Ok(Self::EthereumSepolia),
            _ => Err(ConfigError::InvalidValue(format!(
                "unknown network \"{value}\". Use a known shorthand (e.g. \"base\") or CAIP-2 id, \
                 or call rpc_url() directly."
            ))),
        }
    }
}

/// How API calls authenticate. The default is [`Credentials::Siwe`]: sign in with the configured
/// signer.
#[derive(Debug, Clone)]
pub enum Credentials {
    /// Sign in with the configured signer (SIWE), refreshing tokens as needed.
    Siwe,
    /// A pre-issued bearer token, in place of signing in.
    Bearer(String),
    /// Unauthenticated: only public endpoints work.
    None,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub auth_url: Url,
    pub refresh_margin_secs: u64,
}

/// [`Credentials`] with everything resolved, as [`Client::connect`] consumes it.
#[derive(Debug, Clone)]
pub enum CredentialsConfig {
    Siwe(AuthConfig),
    Bearer(String),
    None,
}

#[derive(Debug, Clone)]
pub struct Config<S> {
    pub rpc_url: Url,
    pub signer: S,
    pub ethereum_http_rpc_url: Option<Url>,
    pub contract_address: Option<Address>,
    pub credentials: CredentialsConfig,
    /// Facilitator that sponsors gas. Without one, every operation is self-funded.
    pub facilitator_url: Option<Url>,
}

/// Builds a [`Client`] (via [`connect()`](Self::connect)) or a [`Config`] (via
/// [`build()`](Self::build)). No setter has side effects: what authenticates is decided by
/// [`credentials()`](Self::credentials) alone, and the auth tuning knobs apply only when the
/// credentials are SIWE.
#[derive(Debug)]
pub struct ClientBuilder<S = PrivateKeySigner> {
    rpc_url: Option<String>,
    signer: Option<S>,
    ethereum_http_rpc_url: Option<String>,
    contract_address: Option<String>,
    credentials: Credentials,
    auth_url: Option<String>,
    auth_refresh_margin_secs: Option<u64>,
    facilitator_url: Option<String>,
}

impl ClientBuilder<PrivateKeySigner> {
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut builder = Self::default();

        if let Ok(v) = std::env::var("4MICA_NETWORK") {
            builder = builder.network(v.parse()?);
        } else if let Ok(v) = std::env::var("4MICA_RPC_URL") {
            builder = builder.rpc_url(v);
        }
        if let Ok(mut v) = std::env::var("4MICA_WALLET_PRIVATE_KEY") {
            builder = builder.signer(
                validate_wallet_private_key(&v)
                    .map_err(|e| ConfigError::InvalidValue(e.to_string()))?,
            );
            v.zeroize();
        }
        if let Ok(v) = std::env::var("4MICA_ETHEREUM_HTTP_RPC_URL") {
            builder = builder.ethereum_http_rpc_url(v);
        }
        if let Ok(v) = std::env::var("4MICA_CONTRACT_ADDRESS") {
            builder = builder.contract_address(v);
        }
        if let Ok(v) = std::env::var("4MICA_FACILITATOR_URL") {
            builder = builder.facilitator_url(v);
        }
        if let Ok(v) = std::env::var("4MICA_BEARER_TOKEN") {
            builder = builder.bearer_token(v);
        }
        if let Ok(v) = std::env::var("4MICA_AUTH_URL") {
            builder = builder.auth_url(v);
        }
        if let Ok(v) = std::env::var("4MICA_AUTH_REFRESH_MARGIN_SECS") {
            let secs = v.parse::<u64>().map_err(|_| {
                ConfigError::InvalidValue(format!("invalid 4MICA_AUTH_REFRESH_MARGIN_SECS: {v}"))
            })?;
            builder = builder.auth_refresh_margin_secs(secs);
        }

        Ok(builder)
    }
}

impl<S> ClientBuilder<S> {
    pub fn rpc_url(mut self, rpc_url: impl Into<String>) -> Self {
        self.rpc_url = Some(rpc_url.into());
        self
    }

    /// Points the client at a known network's default core endpoint.
    pub fn network(mut self, network: Network) -> Self {
        self.rpc_url = Some(network.rpc_url().to_string());
        self
    }

    pub fn signer(mut self, signer: S) -> Self {
        self.signer = Some(signer);
        self
    }

    /// If not provided, the default config will be fetched from the server.
    /// You normally don't need to provide this!
    pub fn ethereum_http_rpc_url(mut self, ethereum_http_rpc_url: impl Into<String>) -> Self {
        self.ethereum_http_rpc_url = Some(ethereum_http_rpc_url.into());
        self
    }

    /// Facilitator that sponsors gas. Without one, every operation is self-funded.
    pub fn facilitator_url(mut self, facilitator_url: impl Into<String>) -> Self {
        self.facilitator_url = Some(facilitator_url.into());
        self
    }

    /// If not provided, the default config will be fetched from the server.
    /// You normally don't need to provide this!
    pub fn contract_address(mut self, contract_address: impl Into<String>) -> Self {
        self.contract_address = Some(contract_address.into());
        self
    }

    /// How API calls authenticate. Defaults to [`Credentials::Siwe`].
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = credentials;
        self
    }

    /// Shorthand for [`credentials(Credentials::Bearer(…))`](Self::credentials). A blank token is
    /// ignored, keeping whatever credentials were already chosen.
    pub fn bearer_token(self, bearer_token: impl Into<String>) -> Self {
        let token = bearer_token.into();
        let trimmed = token.trim();
        if trimmed.is_empty() {
            return self;
        }
        self.credentials(Credentials::Bearer(trimmed.to_string()))
    }

    /// Auth base URL for SIWE credentials. Defaults to the RPC URL.
    pub fn auth_url(mut self, auth_url: impl Into<String>) -> Self {
        self.auth_url = Some(auth_url.into());
        self
    }

    /// Refresh access tokens when the remaining TTL is below this threshold (in seconds). Applies
    /// to SIWE credentials only.
    pub fn auth_refresh_margin_secs(mut self, secs: u64) -> Self {
        self.auth_refresh_margin_secs = Some(secs);
        self
    }

    /// Builds the [`Client`] and connects it: reaches core for its public parameters, which is why
    /// this is fallible and async. Most callers want this rather than [`build()`](Self::build).
    pub async fn connect(self) -> Result<Client<S>, Error>
    where
        S: Signer + Sync + Clone,
    {
        let config = self.build()?;
        Ok(Client::connect(config).await?)
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

        let credentials = match self.credentials {
            Credentials::Siwe => {
                let auth_url = match self.auth_url {
                    Some(raw) => {
                        validate_url(&raw).map_err(|e| ConfigError::InvalidValue(e.to_string()))?
                    }
                    None => rpc_url.clone(),
                };
                CredentialsConfig::Siwe(AuthConfig {
                    auth_url,
                    refresh_margin_secs: self
                        .auth_refresh_margin_secs
                        .unwrap_or(DEFAULT_AUTH_REFRESH_MARGIN_SECS),
                })
            }
            Credentials::Bearer(token) => CredentialsConfig::Bearer(token),
            Credentials::None => CredentialsConfig::None,
        };

        let facilitator_url = self
            .facilitator_url
            .as_deref()
            .map(validate_url)
            .transpose()
            .map_err(|e| ConfigError::InvalidValue(format!("facilitator_url: {e}")))?;

        Ok(Config {
            rpc_url,
            signer,
            ethereum_http_rpc_url,
            contract_address,
            credentials,
            facilitator_url,
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

impl<S> Default for ClientBuilder<S> {
    fn default() -> Self {
        Self {
            rpc_url: Some(DEFAULT_RPC_URL.to_string()),
            signer: None,
            ethereum_http_rpc_url: None,
            contract_address: None,
            credentials: Credentials::Siwe,
            auth_url: None,
            auth_refresh_margin_secs: None,
            facilitator_url: None,
        }
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

    fn valid_signer() -> PrivateKeySigner {
        PrivateKeySigner::from_str(VALID_PRIVATE_KEY).expect("Invalid private key")
    }

    #[test]
    fn test_default_builder() {
        let builder = ClientBuilder::<PrivateKeySigner>::default();

        assert_eq!(builder.rpc_url, Some(DEFAULT_RPC_URL.to_string()));
        assert!(builder.signer.is_none());
        assert!(builder.ethereum_http_rpc_url.is_none());
        assert!(builder.contract_address.is_none());
        assert!(matches!(builder.credentials, Credentials::Siwe));
        assert!(builder.auth_url.is_none());
        assert!(builder.auth_refresh_margin_secs.is_none());
    }

    #[test]
    fn test_build_with_required_fields_only() {
        let signer = valid_signer();
        let config = ClientBuilder::default()
            .signer(signer.clone())
            .build()
            .expect("config should build");

        assert_eq!(config.rpc_url.as_str(), DEFAULT_RPC_URL);
        assert_eq!(config.signer.address(), signer.address());
        assert!(config.ethereum_http_rpc_url.is_none());
        assert!(config.contract_address.is_none());
        let CredentialsConfig::Siwe(auth) = config.credentials else {
            panic!("default credentials should be SIWE");
        };
        assert_eq!(auth.auth_url.as_str(), DEFAULT_RPC_URL);
        assert_eq!(auth.refresh_margin_secs, DEFAULT_AUTH_REFRESH_MARGIN_SECS);
    }

    #[test]
    fn test_build_with_bearer_token_replaces_siwe() {
        let config = ClientBuilder::default()
            .signer(valid_signer())
            .bearer_token("test-token")
            .build()
            .expect("config should build");

        let CredentialsConfig::Bearer(token) = config.credentials else {
            panic!("bearer_token should select bearer credentials");
        };
        assert_eq!(token, "test-token");
    }

    #[test]
    fn test_a_blank_bearer_token_is_ignored() {
        let config = ClientBuilder::default()
            .signer(valid_signer())
            .bearer_token("   ")
            .build()
            .expect("config should build");

        assert!(matches!(config.credentials, CredentialsConfig::Siwe(_)));
    }

    #[test]
    fn test_build_with_all_fields() {
        let signer = valid_signer();
        let config = ClientBuilder::default()
            .rpc_url(VALID_RPC_URL)
            .signer(signer.clone())
            .ethereum_http_rpc_url(VALID_ETH_RPC_URL)
            .contract_address(VALID_ADDRESS)
            .build()
            .expect("config should build");

        assert_eq!(config.rpc_url.as_str(), VALID_RPC_URL);
        assert_eq!(config.signer.address(), signer.address());
        assert_eq!(
            config.ethereum_http_rpc_url.unwrap().as_str(),
            VALID_ETH_RPC_URL
        );
        assert_eq!(config.contract_address.unwrap().to_string(), VALID_ADDRESS);
        assert!(matches!(config.credentials, CredentialsConfig::Siwe(_)));
    }

    #[test]
    fn test_network_resolves_base() {
        let builder = ClientBuilder::<PrivateKeySigner>::default().network(Network::Base);

        assert_eq!(
            builder.rpc_url,
            Some("https://base.api.4mica.xyz/".to_string())
        );
        assert_eq!("eip155:8453".parse::<Network>().unwrap(), Network::Base);
        assert_eq!("base".parse::<Network>().unwrap(), Network::Base);
        assert!("solana".parse::<Network>().is_err());
    }

    #[test]
    fn test_build_missing_signer() {
        let config = ClientBuilder::<PrivateKeySigner>::default().build();

        match config.unwrap_err() {
            ConfigError::Missing(field) => assert_eq!(field, "signer"),
            _ => panic!("Expected Missing error"),
        }
    }

    #[test]
    fn test_build_invalid_rpc_url() {
        let config = ClientBuilder::default()
            .rpc_url("not-a-valid-url")
            .signer(valid_signer())
            .build();

        match config.unwrap_err() {
            ConfigError::InvalidValue(msg) => assert!(msg.contains("invalid URL")),
            _ => panic!("Expected InvalidValue error"),
        }
    }

    #[test]
    fn test_build_invalid_ethereum_http_rpc_url() {
        let config = ClientBuilder::default()
            .signer(valid_signer())
            .ethereum_http_rpc_url("not-a-valid-url")
            .build();

        match config.unwrap_err() {
            ConfigError::InvalidValue(msg) => assert!(msg.contains("invalid URL")),
            _ => panic!("Expected InvalidValue error"),
        }
    }

    #[test]
    fn test_build_invalid_contract_address() {
        let config = ClientBuilder::default()
            .signer(valid_signer())
            .contract_address("not-a-valid-address")
            .build();

        match config.unwrap_err() {
            ConfigError::InvalidValue(msg) => assert!(msg.contains("invalid address")),
            _ => panic!("Expected InvalidValue error"),
        }
    }

    #[test]
    #[serial]
    fn test_from_env_with_all_vars() {
        let signer = valid_signer();

        unsafe {
            std::env::set_var("4MICA_RPC_URL", VALID_RPC_URL);
            std::env::set_var("4MICA_WALLET_PRIVATE_KEY", VALID_PRIVATE_KEY);
            std::env::set_var("4MICA_ETHEREUM_HTTP_RPC_URL", VALID_ETH_RPC_URL);
            std::env::set_var("4MICA_CONTRACT_ADDRESS", VALID_ADDRESS);
            std::env::set_var("4MICA_BEARER_TOKEN", "test-token");
        }

        let config = ClientBuilder::from_env()
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

        let config = config.expect("config should build");
        assert_eq!(config.rpc_url.as_str(), VALID_RPC_URL);
        assert_eq!(config.signer.address(), signer.address());
        assert_eq!(
            config.ethereum_http_rpc_url.unwrap().as_str(),
            VALID_ETH_RPC_URL
        );
        assert_eq!(config.contract_address.unwrap().to_string(), VALID_ADDRESS);
        assert!(matches!(
            config.credentials,
            CredentialsConfig::Bearer(ref token) if token == "test-token"
        ));
    }

    #[test]
    #[serial]
    fn test_from_env_with_partial_vars() {
        unsafe {
            std::env::set_var("4MICA_RPC_URL", VALID_RPC_URL);
        }

        let signer = validate_wallet_private_key(VALID_PRIVATE_KEY).expect("Invalid private key");

        let config = ClientBuilder::from_env()
            .expect("Invalid environment variables")
            .signer(signer.clone())
            .build();

        // Clean up
        unsafe {
            std::env::remove_var("4MICA_RPC_URL");
        }

        let config = config.expect("config should build");
        assert_eq!(config.rpc_url.as_str(), VALID_RPC_URL);
        assert_eq!(config.signer.address(), signer.address());
    }

    #[test]
    #[serial]
    fn test_from_env_uses_default_rpc_url_and_auth_when_unset() {
        unsafe {
            std::env::remove_var("4MICA_NETWORK");
            std::env::remove_var("4MICA_RPC_URL");
            std::env::remove_var("4MICA_BEARER_TOKEN");
            std::env::remove_var("4MICA_AUTH_URL");
            std::env::remove_var("4MICA_AUTH_REFRESH_MARGIN_SECS");
        }

        let signer = validate_wallet_private_key(VALID_PRIVATE_KEY).expect("Invalid private key");

        let config = ClientBuilder::from_env()
            .expect("Invalid environment variables")
            .signer(signer)
            .build()
            .expect("config should build");

        assert_eq!(config.rpc_url.as_str(), DEFAULT_RPC_URL);
        let CredentialsConfig::Siwe(auth) = config.credentials else {
            panic!("from_env should default to SIWE credentials");
        };
        assert_eq!(auth.auth_url.as_str(), DEFAULT_RPC_URL);
    }

    #[test]
    #[serial]
    fn test_from_env_rejects_a_bad_refresh_margin() {
        unsafe {
            std::env::set_var("4MICA_AUTH_REFRESH_MARGIN_SECS", "not-a-number");
        }

        let result = ClientBuilder::from_env();

        unsafe {
            std::env::remove_var("4MICA_AUTH_REFRESH_MARGIN_SECS");
        }

        match result.unwrap_err() {
            ConfigError::InvalidValue(msg) => assert!(msg.contains("not-a-number")),
            _ => panic!("Expected InvalidValue error"),
        }
    }

    #[test]
    #[serial]
    fn test_from_env_network_takes_precedence_over_rpc_url() {
        unsafe {
            std::env::set_var("4MICA_NETWORK", "base");
            std::env::set_var("4MICA_RPC_URL", VALID_RPC_URL);
        }

        let signer = validate_wallet_private_key(VALID_PRIVATE_KEY).expect("Invalid private key");

        let config = ClientBuilder::from_env()
            .expect("Invalid environment variables")
            .signer(signer)
            .build()
            .expect("config should build");

        unsafe {
            std::env::remove_var("4MICA_NETWORK");
            std::env::remove_var("4MICA_RPC_URL");
        }

        assert_eq!(config.rpc_url.as_str(), "https://base.api.4mica.xyz/");
    }
}
