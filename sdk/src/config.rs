use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use url::Url;

use crate::{
    error::ConfigError,
    validators::{validate_address, validate_url, validate_wallet_private_key},
};

#[derive(Debug, Clone)]
pub struct Config {
    pub rpc_url: Url,
    pub wallet_private_key: PrivateKeySigner,
    pub ethereum_http_rpc_url: Option<Url>,
    pub contract_address: Option<Address>,
    pub chain_id: u64,
}

pub struct ConfigBuilder {
    rpc_url: Option<String>,
    wallet_private_key: Option<String>,
    ethereum_http_rpc_url: Option<String>,
    contract_address: Option<String>,
    chain_id: Option<u64>,
}

impl ConfigBuilder {
    fn empty() -> Self {
        Self {
            rpc_url: None,
            wallet_private_key: None,
            ethereum_http_rpc_url: None,
            contract_address: None,
            chain_id: None,
        }
    }

    pub fn rpc_url(mut self, rpc_url: String) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }

    pub fn wallet_private_key(mut self, wallet_private_key: String) -> Self {
        self.wallet_private_key = Some(wallet_private_key);
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

    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    pub fn from_env(mut self) -> Self {
        if let Ok(v) = std::env::var("4MICA_RPC_URL") {
            self = self.rpc_url(v);
        }
        if let Ok(v) = std::env::var("4MICA_WALLET_PRIVATE_KEY") {
            self = self.wallet_private_key(v);
        }
        if let Ok(v) = std::env::var("4MICA_ETHEREUM_HTTP_RPC_URL") {
            self = self.ethereum_http_rpc_url(v);
        }
        if let Ok(v) = std::env::var("4MICA_CONTRACT_ADDRESS") {
            self = self.contract_address(v);
        }
        if let Ok(v) = std::env::var("4MICA_CHAIN_ID") {
            if let Ok(parsed) = v.parse::<u64>() {
                self = self.chain_id(parsed);
            }
        }
        self
    }

    pub fn build(self) -> Result<Config, ConfigError> {
        let Some(rpc_url) = self.rpc_url else {
            return Err(ConfigError::Missing("rpc_url".to_string()));
        };
        let Some(wallet_private_key) = self.wallet_private_key else {
            return Err(ConfigError::Missing("wallet_private_key".to_string()));
        };

        let rpc_url =
            validate_url(&rpc_url).map_err(|e| ConfigError::InvalidValue(e.to_string()))?;
        let wallet_private_key = validate_wallet_private_key(&wallet_private_key)
            .map_err(|e| ConfigError::InvalidValue(e.to_string()))?;

        let ethereum_http_rpc_url = self
            .ethereum_http_rpc_url
            .map(|url| validate_url(&url).map_err(|e| ConfigError::InvalidValue(e.to_string())));
        if let Some(Err(e)) = ethereum_http_rpc_url {
            return Err(e);
        }
        let ethereum_http_rpc_url = ethereum_http_rpc_url.map(|url| url.unwrap());

        let contract_address = self.contract_address.map(|address| {
            validate_address(&address).map_err(|e| ConfigError::InvalidValue(e.to_string()))
        });
        if let Some(Err(e)) = contract_address {
            return Err(e);
        }
        let contract_address = contract_address.map(|address| address.unwrap());

        let chain_id = self.chain_id.unwrap_or(1);
        if chain_id == 0 {
            return Err(ConfigError::InvalidValue(
                "chain_id must be greater than zero".into(),
            ));
        }

        Ok(Config {
            rpc_url,
            wallet_private_key,
            ethereum_http_rpc_url,
            contract_address,
            chain_id,
        })
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::empty()
            .rpc_url("https://api.4mica.xyz/".to_string())
            .chain_id(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    const VALID_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const VALID_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
    const VALID_RPC_URL: &str = "http://api.4mica.xyz/";
    const VALID_ETH_RPC_URL: &str = "http://localhost:8545/";

    #[test]
    fn test_default_builder() {
        let builder = ConfigBuilder::default();
        assert_eq!(builder.rpc_url, Some("https://api.4mica.xyz/".to_string()));
        assert!(builder.wallet_private_key.is_none());
        assert!(builder.ethereum_http_rpc_url.is_none());
        assert!(builder.contract_address.is_none());
        assert_eq!(builder.chain_id, Some(1));
    }

    #[test]
    fn test_build_with_required_fields_only() {
        let config = ConfigBuilder::default()
            .wallet_private_key(VALID_PRIVATE_KEY.to_string())
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.rpc_url.as_str(), "https://api.4mica.xyz/");
        assert_eq!(
            config.wallet_private_key,
            validate_wallet_private_key(VALID_PRIVATE_KEY).expect("Invalid private key")
        );
        assert!(config.ethereum_http_rpc_url.is_none());
        assert!(config.contract_address.is_none());
        assert_eq!(config.chain_id, 1);
    }

    #[test]
    fn test_build_with_all_fields() {
        let config = ConfigBuilder::default()
            .rpc_url(VALID_RPC_URL.to_string())
            .wallet_private_key(VALID_PRIVATE_KEY.to_string())
            .ethereum_http_rpc_url(VALID_ETH_RPC_URL.to_string())
            .contract_address(VALID_ADDRESS.to_string())
            .chain_id(31337)
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.rpc_url.as_str(), VALID_RPC_URL);
        assert_eq!(
            config.wallet_private_key,
            validate_wallet_private_key(VALID_PRIVATE_KEY).expect("Invalid private key")
        );
        assert_eq!(
            config.ethereum_http_rpc_url.unwrap().as_str(),
            VALID_ETH_RPC_URL
        );
        assert_eq!(config.contract_address.unwrap().to_string(), VALID_ADDRESS);
        assert_eq!(config.chain_id, 31337);
    }

    #[test]
    fn test_build_missing_wallet_private_key() {
        let config = ConfigBuilder::default().build();

        assert!(config.is_err());
        match config.unwrap_err() {
            ConfigError::Missing(field) => assert_eq!(field, "wallet_private_key"),
            _ => panic!("Expected Missing error"),
        }
    }

    #[test]
    fn test_build_invalid_rpc_url() {
        let config = ConfigBuilder::default()
            .rpc_url("not-a-valid-url".to_string())
            .wallet_private_key(VALID_PRIVATE_KEY.to_string())
            .build();

        assert!(config.is_err());
        match config.unwrap_err() {
            ConfigError::InvalidValue(msg) => assert!(msg.contains("invalid URL")),
            _ => panic!("Expected InvalidValue error"),
        }
    }

    #[test]
    fn test_build_invalid_wallet_private_key() {
        let config = ConfigBuilder::default()
            .wallet_private_key("not-a-valid-key".to_string())
            .build();

        assert!(config.is_err());
        match config.unwrap_err() {
            ConfigError::InvalidValue(msg) => assert!(msg.contains("invalid private key")),
            _ => panic!("Expected InvalidValue error"),
        }
    }

    #[test]
    fn test_build_invalid_ethereum_http_rpc_url() {
        let config = ConfigBuilder::default()
            .wallet_private_key(VALID_PRIVATE_KEY.to_string())
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
            .wallet_private_key(VALID_PRIVATE_KEY.to_string())
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
        unsafe {
            std::env::set_var("4MICA_RPC_URL", VALID_RPC_URL);
            std::env::set_var("4MICA_WALLET_PRIVATE_KEY", VALID_PRIVATE_KEY);
            std::env::set_var("4MICA_ETHEREUM_HTTP_RPC_URL", VALID_ETH_RPC_URL);
            std::env::set_var("4MICA_CONTRACT_ADDRESS", VALID_ADDRESS);
        }

        let config = ConfigBuilder::default().from_env().build();

        // Clean up
        unsafe {
            std::env::remove_var("4MICA_RPC_URL");
            std::env::remove_var("4MICA_WALLET_PRIVATE_KEY");
            std::env::remove_var("4MICA_ETHEREUM_HTTP_RPC_URL");
            std::env::remove_var("4MICA_CONTRACT_ADDRESS");
        }

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.rpc_url.as_str(), VALID_RPC_URL);
        assert_eq!(
            config.wallet_private_key,
            validate_wallet_private_key(VALID_PRIVATE_KEY).expect("Invalid private key")
        );
        assert_eq!(config.chain_id, 1);
        assert_eq!(
            config.ethereum_http_rpc_url.unwrap().as_str(),
            VALID_ETH_RPC_URL
        );
        assert_eq!(config.contract_address.unwrap().to_string(), VALID_ADDRESS);
        assert_eq!(config.chain_id, 1);
    }

    #[test]
    #[serial]
    fn test_from_env_with_partial_vars() {
        unsafe {
            std::env::set_var("4MICA_RPC_URL", VALID_RPC_URL);
        }

        let config = ConfigBuilder::default()
            .from_env()
            .wallet_private_key(VALID_PRIVATE_KEY.to_string())
            .build();

        // Clean up
        unsafe {
            std::env::remove_var("4MICA_RPC_URL");
        }

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.rpc_url.as_str(), VALID_RPC_URL);
        assert_eq!(
            config.wallet_private_key,
            validate_wallet_private_key(VALID_PRIVATE_KEY).expect("Invalid private key")
        );
        assert_eq!(config.chain_id, 1);
    }

    #[test]
    #[serial]
    fn test_from_env_override() {
        unsafe {
            std::env::set_var("4MICA_RPC_URL", "http://env-url:3000/");
        }

        let config = ConfigBuilder::default()
            .rpc_url(VALID_RPC_URL.to_string())
            .from_env()
            .wallet_private_key(VALID_PRIVATE_KEY.to_string())
            .build();

        // Clean up
        unsafe {
            std::env::remove_var("4MICA_RPC_URL");
        }

        assert!(config.is_ok());
        let config = config.unwrap();
        // from_env should override the earlier value
        assert_eq!(config.rpc_url.as_str(), "http://env-url:3000/");
        assert_eq!(config.chain_id, 1);
    }
}
