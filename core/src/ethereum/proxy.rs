use crate::{config::AppConfig, error::CoreContractApiError, ethereum::contract_abi::*};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
};
use anyhow::anyhow;
use async_trait::async_trait;
use log::info;

pub struct CoreContractProxy {
    provider: DynProvider,
    contract_address: Address,
}

#[derive(Debug, Clone)]
pub struct RecordPaymentTx {
    pub tx_hash: B256,
    pub block_number: Option<u64>,
    pub block_hash: Option<B256>,
}

#[async_trait]
pub trait CoreContractApi: Send + Sync {
    async fn get_chain_id(&self) -> Result<u64, CoreContractApiError>;

    async fn get_guarantee_domain_separator(&self) -> Result<[u8; 32], CoreContractApiError>;

    async fn get_tab_expiration_time(&self) -> Result<u64, CoreContractApiError>;

    async fn record_payment(
        &self,
        tab_id: U256,
        asset: Address,
        amount: U256,
    ) -> Result<RecordPaymentTx, CoreContractApiError>;
}

impl CoreContractProxy {
    pub async fn new(config: &AppConfig) -> Result<Self, CoreContractApiError> {
        let wallet = EthereumWallet::new(config.secrets.ethereum_private_key_signer.clone());

        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(&config.ethereum_config.http_rpc_url)
            .await
            .map_err(CoreContractApiError::TransportFailure)?
            .erased();

        let contract_address: Address =
            config
                .ethereum_config
                .contract_address
                .parse()
                .map_err(|_| {
                    CoreContractApiError::Other(anyhow!(
                        "invalid contract address {}",
                        config.ethereum_config.contract_address
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
        let version_config = contract
            .getGuaranteeVersionConfig(rpc::GUARANTEE_CLAIMS_VERSION)
            .call()
            .await?;

        if !version_config.enabled {
            return Err(CoreContractApiError::GuaranteeVersionDisabled(
                rpc::GUARANTEE_CLAIMS_VERSION,
            ));
        }

        Ok(version_config.domainSeparator.into())
    }

    async fn get_tab_expiration_time(&self) -> Result<u64, CoreContractApiError> {
        let contract = self.build_contract();
        let expiration = contract.tabExpirationTime().call().await?;
        Ok(expiration.to())
    }

    async fn record_payment(
        &self,
        tab_id: U256,
        asset: Address,
        amount: U256,
    ) -> Result<RecordPaymentTx, CoreContractApiError> {
        let contract = self.build_contract();
        let tx = contract.recordPayment(tab_id, asset, amount);

        let receipt = tx.send().await?.get_receipt().await?;

        info!(
            "recordPayment confirmed in tx {:?}",
            receipt.transaction_hash
        );
        Ok(RecordPaymentTx {
            tx_hash: receipt.transaction_hash,
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
        })
    }
}
