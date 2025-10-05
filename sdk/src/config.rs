use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use url::Url;

use crate::{
    error::Error4Mica,
    validators::{validate_address, validate_url, validate_wallet_private_key},
};

#[derive(Debug, Clone)]
pub struct Config {
    pub rpc_url: Url,
    pub ethereum_http_rpc_url: Url,
    pub contract_address: Address,
    pub wallet_private_key: PrivateKeySigner,
}

pub struct ConfigBuilder {
    rpc_url: Option<String>,
    ethereum_http_rpc_url: Option<String>,
    contract_address: Option<String>,
    wallet_private_key: Option<String>,
}

impl ConfigBuilder {
    fn empty() -> Self {
        Self {
            rpc_url: None,
            ethereum_http_rpc_url: None,
            contract_address: None,
            wallet_private_key: None,
        }
    }

    pub fn rpc_url(mut self, rpc_url: String) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }

    pub fn ethereum_http_rpc_url(mut self, ethereum_http_rpc_url: String) -> Self {
        self.ethereum_http_rpc_url = Some(ethereum_http_rpc_url);
        self
    }

    pub fn contract_address(mut self, contract_address: String) -> Self {
        self.contract_address = Some(contract_address);
        self
    }

    pub fn wallet_private_key(mut self, wallet_private_key: String) -> Self {
        self.wallet_private_key = Some(wallet_private_key);
        self
    }

    pub fn from_env(mut self) -> Self {
        if let Ok(v) = std::env::var("4MICA_RPC_URL") {
            self = self.rpc_url(v);
        }
        if let Ok(v) = std::env::var("4MICA_ETHEREUM_HTTP_RPC_URL") {
            self = self.ethereum_http_rpc_url(v);
        }
        if let Ok(v) = std::env::var("4MICA_CONTRACT_ADDRESS") {
            self = self.contract_address(v);
        }
        if let Ok(v) = std::env::var("4MICA_WALLET_PRIVATE_KEY") {
            self = self.wallet_private_key(v);
        }
        self
    }

    pub fn build(self) -> Result<Config, Error4Mica> {
        let Some(rpc_url) = self.rpc_url else {
            return Err(Error4Mica::ConfigMissing("rpc_url".to_string()));
        };
        let Some(ethereum_http_rpc_url) = self.ethereum_http_rpc_url else {
            return Err(Error4Mica::ConfigMissing(
                "ethereum_http_rpc_url".to_string(),
            ));
        };
        let Some(contract_address) = self.contract_address else {
            return Err(Error4Mica::ConfigMissing("contract_address".to_string()));
        };
        let Some(wallet_private_key) = self.wallet_private_key else {
            return Err(Error4Mica::ConfigMissing("wallet_private_key".to_string()));
        };

        let rpc_url = validate_url(&rpc_url)?;
        let ethereum_http_rpc_url = validate_url(&ethereum_http_rpc_url)?;
        let contract_address = validate_address(&contract_address)?;
        let wallet_private_key = validate_wallet_private_key(&wallet_private_key)?;

        Ok(Config {
            rpc_url,
            ethereum_http_rpc_url,
            contract_address,
            wallet_private_key,
        })
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::empty()
            .rpc_url("http://localhost:3000".to_string())
            .ethereum_http_rpc_url("http://localhost:8545".to_string())
            .contract_address("0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0".to_string())
    }
}
