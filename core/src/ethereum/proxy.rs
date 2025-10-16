use crate::{config::EthereumConfig, error::CoreContractApiError, ethereum::contract_abi::*};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::anyhow;
use async_trait::async_trait;
use log::info;

pub struct CoreContractProxy {
    provider: DynProvider,
    contract_address: Address,
}

#[async_trait]
pub trait CoreContractApi: Send + Sync {
    async fn get_chain_id(&self) -> Result<u64, CoreContractApiError>;

    async fn get_guarantee_domain_separator(&self) -> Result<[u8; 32], CoreContractApiError>;

    async fn record_payment(&self, tab_id: U256, amount: U256) -> Result<(), CoreContractApiError>;
}

impl CoreContractProxy {
    pub async fn new(config: EthereumConfig) -> Result<Self, CoreContractApiError> {
        let signer: PrivateKeySigner = config.ethereum_private_key.parse()?;
        let wallet = EthereumWallet::new(signer);

        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(&config.http_rpc_url)
            .await
            .map_err(CoreContractApiError::TransportFailure)?
            .erased();

        let contract_address: Address = config.contract_address.parse().map_err(|_| {
            CoreContractApiError::Other(anyhow!(
                "invalid contract address {}",
                config.contract_address
            ))
        })?;

        Ok(Self {
            provider,
            contract_address,
        })
    }

    fn build_contract(&self) -> Core4Mica::Core4MicaInstance<DynProvider> {
        Core4Mica::Core4MicaInstance::new(self.contract_address, self.provider.clone())
    }
}

#[async_trait]
impl CoreContractApi for CoreContractProxy {
    async fn get_chain_id(&self) -> Result<u64, CoreContractApiError> {
        let chain_id = self.provider.get_chain_id().await?;
        Ok(chain_id)
    }

    async fn get_guarantee_domain_separator(&self) -> Result<[u8; 32], CoreContractApiError> {
        let contract = self.build_contract();
        let domain_separator = contract.guaranteeDomainSeparator().call().await?;
        Ok(domain_separator.into())
    }

    async fn record_payment(&self, tab_id: U256, amount: U256) -> Result<(), CoreContractApiError> {
        let contract = self.build_contract();
        let tx = contract.recordPayment(tab_id, amount);

        let receipt = tx.send().await?.get_receipt().await?;

        info!(
            "recordPayment confirmed in tx {:?}",
            receipt.transaction_hash
        );
        Ok(())
    }
}
