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
}

pub struct ConfigBuilder {
    rpc_url: Option<String>,
    wallet_private_key: Option<String>,
    ethereum_http_rpc_url: Option<String>,
    contract_address: Option<String>,
}

impl ConfigBuilder {
    fn empty() -> Self {
        Self {
            rpc_url: None,
            wallet_private_key: None,
            ethereum_http_rpc_url: None,
            contract_address: None,
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

        Ok(Config {
            rpc_url,
            wallet_private_key,
            ethereum_http_rpc_url,
            contract_address,
        })
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::empty().rpc_url("http://localhost:3000".to_string())
    }
}
