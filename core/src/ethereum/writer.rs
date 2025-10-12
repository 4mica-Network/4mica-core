use crate::{config::EthereumConfig, error::BlockchainWriterError, ethereum::contract_abi::*};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder, WsConnect},
    signers::local::PrivateKeySigner,
};
use anyhow::anyhow;
use log::info;

pub struct EthereumWriter {
    config: EthereumConfig,
}

impl EthereumWriter {
    pub fn new(config: EthereumConfig) -> Self {
        Self { config }
    }

    async fn build_contract(
        &self,
    ) -> Result<Core4Mica::Core4MicaInstance<impl Provider + 'static>, BlockchainWriterError> {
        let signer: PrivateKeySigner = self.config.ethereum_private_key.parse()?;
        let wallet = EthereumWallet::new(signer);

        let ws = WsConnect::new(&self.config.ws_rpc_url);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_ws(ws)
            .await
            .map_err(BlockchainWriterError::TransportFailure)?;

        let address: Address = self.config.contract_address.parse().map_err(|_| {
            BlockchainWriterError::Other(anyhow!(
                "invalid contract address {}",
                self.config.contract_address
            ))
        })?;

        Ok(Core4Mica::Core4MicaInstance::new(address, provider))
    }

    pub async fn record_payment(
        &self,
        tab_id: U256,
        amount: U256,
    ) -> Result<(), BlockchainWriterError> {
        let contract = self.build_contract().await?;
        let tx = contract.recordPayment(tab_id, amount);

        let receipt = tx.send().await?.get_receipt().await?;

        info!(
            "recordPayment confirmed in tx {:?}",
            receipt.transaction_hash
        );
        Ok(())
    }
}
