use crate::{config::AppConfig, error::CoreContractApiError, ethereum::contract_abi::*};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
};
use anyhow::anyhow;
use async_trait::async_trait;
use log::info;
use rpc::SupportedTokenInfo;
use tokio::sync::Mutex;

pub struct CoreContractProxy {
    provider: DynProvider,
    contract_address: Address,
    tx_write_lock: Mutex<()>,
}

#[derive(Debug, Clone, Copy)]
pub struct GuaranteeVersionConfig {
    pub version: u64,
    pub domain_separator: [u8; 32],
    pub decoder: Address,
    pub enabled: bool,
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

    async fn get_guarantee_version_config(
        &self,
        version: u64,
    ) -> Result<GuaranteeVersionConfig, CoreContractApiError>;

    async fn get_guarantee_domain_separator(&self) -> Result<[u8; 32], CoreContractApiError> {
        let cfg = self
            .get_guarantee_version_config(rpc::GUARANTEE_CLAIMS_VERSION)
            .await?;

        if !cfg.enabled {
            return Err(CoreContractApiError::GuaranteeVersionDisabled(
                rpc::GUARANTEE_CLAIMS_VERSION,
            ));
        }

        Ok(cfg.domain_separator)
    }

    async fn get_tab_expiration_time(&self) -> Result<u64, CoreContractApiError>;

    async fn get_supported_tokens(&self) -> Result<Vec<SupportedTokenInfo>, CoreContractApiError>;

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
            tx_write_lock: Mutex::new(()),
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

    async fn get_guarantee_version_config(
        &self,
        version: u64,
    ) -> Result<GuaranteeVersionConfig, CoreContractApiError> {
        let contract = self.build_contract();
        let version_config = contract.getGuaranteeVersionConfig(version).call().await?;

        Ok(GuaranteeVersionConfig {
            version,
            domain_separator: version_config.domainSeparator.into(),
            decoder: version_config.decoder,
            enabled: version_config.enabled,
        })
    }

    async fn get_tab_expiration_time(&self) -> Result<u64, CoreContractApiError> {
        let contract = self.build_contract();
        let expiration = contract.tabExpirationTime().call().await?;
        Ok(expiration.to())
    }

    async fn get_supported_tokens(&self) -> Result<Vec<SupportedTokenInfo>, CoreContractApiError> {
        let contract = self.build_contract();
        let addresses = contract.getERC20Tokens().call().await?;
        let mut tokens = Vec::with_capacity(addresses.len());
        for addr in addresses {
            let erc20 = ERC20Metadata::new(addr, self.provider.clone());
            let symbol = erc20.symbol().call().await?;
            let decimals = erc20.decimals().call().await?;
            tokens.push(SupportedTokenInfo {
                symbol,
                address: addr.to_string(),
                decimals,
            });
        }
        Ok(tokens)
    }

    async fn record_payment(
        &self,
        tab_id: U256,
        asset: Address,
        amount: U256,
    ) -> Result<RecordPaymentTx, CoreContractApiError> {
        // Serialize contract writes for the shared signer to avoid nonce races between
        // overlapping payment-confirmation tasks.
        let _guard = self.tx_write_lock.lock().await;
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
