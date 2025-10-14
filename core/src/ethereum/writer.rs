use crate::{config::EthereumConfig, error::BlockchainWriterError, ethereum::contract_abi::*};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
};
use anyhow::anyhow;
use async_trait::async_trait;
use log::info;

pub struct EthereumWriter {
    provider: DynProvider,
    contract_address: Address,
}

#[async_trait]
pub trait PaymentWriter: Send + Sync {
    async fn record_payment(&self, tab_id: U256, amount: U256)
        -> Result<(), BlockchainWriterError>;
}

impl EthereumWriter {
    pub async fn new(config: EthereumConfig) -> Result<Self, BlockchainWriterError> {
        let signer: PrivateKeySigner = config.ethereum_private_key.parse()?;
        let wallet = EthereumWallet::new(signer);

        let ws = WsConnect::new(&config.ws_rpc_url);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_ws(ws)
            .await
            .map_err(BlockchainWriterError::TransportFailure)?
            .erased();

        let contract_address: Address = config.contract_address.parse().map_err(|_| {
            BlockchainWriterError::Other(anyhow!(
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
impl PaymentWriter for EthereumWriter {
    async fn record_payment(
        &self,
        tab_id: U256,
        amount: U256,
    ) -> Result<(), BlockchainWriterError> {
        let contract = self.build_contract();
        let tx = contract.recordPayment(tab_id, Address::ZERO, amount);

        let receipt = tx.send().await?.get_receipt().await?;

        info!(
            "recordPayment confirmed in tx {:?}",
            receipt.transaction_hash
        );
        Ok(())
    }
}
