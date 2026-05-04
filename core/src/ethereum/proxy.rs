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
    clearing_house_address: Address,
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
pub struct ClearingCommitInput {
    pub cycle_id: B256,
    pub asset: Address,
    pub merkle_root: B256,
    pub total_net_debit: U256,
    pub total_net_credit: U256,
    pub payment_submission_deadline: u64,
    pub payment_finality_deadline: u64,
}

#[derive(Debug, Clone)]
pub struct ClearingCommitTx {
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

    async fn commit_clearing_cycle(
        &self,
        input: ClearingCommitInput,
    ) -> Result<ClearingCommitTx, CoreContractApiError>;
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
        let clearing_house_address: Address = config
            .ethereum_config
            .clearing_house_address
            .parse()
            .map_err(|_| {
                CoreContractApiError::InvalidAddress(
                    config.ethereum_config.clearing_house_address.clone(),
                )
            })?;

        Ok(Self {
            provider,
            contract_address,
            clearing_house_address,
            tx_write_lock: Mutex::new(()),
        })
    }

    fn build_contract(&self) -> Core4Mica::Core4MicaInstance<DynProvider> {
        Core4Mica::Core4MicaInstance::new(self.contract_address, self.provider.clone())
    }

    fn build_clearing_house(&self) -> ClearingHouse::ClearingHouseInstance<DynProvider> {
        ClearingHouse::ClearingHouseInstance::new(
            self.clearing_house_address,
            self.provider.clone(),
        )
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

    async fn commit_clearing_cycle(
        &self,
        input: ClearingCommitInput,
    ) -> Result<ClearingCommitTx, CoreContractApiError> {
        let _guard = self.tx_write_lock.lock().await;
        let contract = self.build_clearing_house();
        let tx = contract.commitCycle(
            input.cycle_id,
            input.asset,
            input.merkle_root,
            input.total_net_debit,
            input.total_net_credit,
            input.payment_submission_deadline,
            input.payment_finality_deadline,
        );

        let receipt = tx.send().await?.get_receipt().await?;

        info!(
            "ClearingHouse.commitCycle confirmed in tx {:?}",
            receipt.transaction_hash
        );
        Ok(ClearingCommitTx {
            tx_hash: receipt.transaction_hash,
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
        })
    }
}
