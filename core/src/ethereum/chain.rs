//! The single seam between core and the chain.
//!
//! Everything that talks to Ethereum goes through here: contract writes via [`CoreContractApi`],
//! read-only contract calls, and provider-level queries. No other module should hold a
//! `DynProvider` or build its own contract instance.

use std::sync::Arc;

use alloy::eips::BlockId;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder, WsConnect};
use anyhow::anyhow;
use log::error;

use crate::config::EthereumConfig;
use crate::error::{BlockchainListenerError, CoreContractApiError, ServiceError, ServiceResult};
use crate::ethereum::contract::contract_abi::Core4Mica;
use crate::ethereum::{
    ClearingCommitInput, ClearingTxResult, CoreContractApi, CreditorSettlement, DebtorSettlement,
    GuaranteeVersionConfig,
};
use rpc::SupportedTokenInfo;

pub struct ChainService {
    contract_api: Arc<dyn CoreContractApi>,
    read_provider: DynProvider,
    contract_address: String,
}

impl ChainService {
    pub fn new(
        contract_api: Arc<dyn CoreContractApi>,
        read_provider: DynProvider,
        config: &EthereumConfig,
    ) -> Self {
        Self {
            contract_api,
            read_provider,
            contract_address: config.contract_address.clone(),
        }
    }

    /// The raw read provider. Only the event scanner, which drives its own subscription, needs
    /// this; everything else should use a method on this service.
    pub fn provider(&self) -> &DynProvider {
        &self.read_provider
    }

    pub async fn build_ws_provider(config: EthereumConfig) -> ServiceResult<DynProvider> {
        let ws = WsConnect::new(&config.ws_rpc_url);
        let provider = ProviderBuilder::new()
            .connect_ws(ws)
            .await
            .map_err(|err| {
                error!("Failed to connect to Ethereum provider: {err}");
                ServiceError::Other(anyhow!(err))
            })?
            .erased();

        Ok(provider)
    }

    pub async fn block_number(&self) -> Result<u64, anyhow::Error> {
        self.read_provider
            .get_block_number()
            .await
            .map_err(|err| anyhow!(err))
    }

    /// Verify a SIWE signature, including the EIP-1271 contract-wallet path that needs a provider.
    pub async fn verify_siwe_message(
        &self,
        expected_address: &str,
        raw_message: &str,
        signature_hex: &str,
    ) -> ServiceResult<crate::evm::siwe::SiweMessage> {
        crate::evm::siwe::verify_siwe_message(
            &self.read_provider,
            expected_address,
            raw_message,
            signature_hex,
        )
        .await
    }

    // --- contract writes / reads delegated to the proxy ------------------------------------

    pub async fn get_chain_id(&self) -> Result<u64, CoreContractApiError> {
        self.contract_api.get_chain_id().await
    }

    pub async fn get_guarantee_version_config(
        &self,
        version: u64,
    ) -> Result<GuaranteeVersionConfig, CoreContractApiError> {
        self.contract_api
            .get_guarantee_version_config(version)
            .await
    }

    pub async fn get_withdrawal_grace_period(&self) -> Result<u64, CoreContractApiError> {
        self.contract_api.get_withdrawal_grace_period().await
    }

    pub async fn get_core_domain_separator(&self) -> Result<[u8; 32], CoreContractApiError> {
        self.contract_api.get_core_domain_separator().await
    }

    pub async fn get_supported_tokens(
        &self,
    ) -> Result<Vec<SupportedTokenInfo>, CoreContractApiError> {
        self.contract_api.get_supported_tokens().await
    }

    pub async fn commit_clearing_cycle(
        &self,
        input: ClearingCommitInput,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        self.contract_api.commit_clearing_cycle(input).await
    }

    pub async fn settle_defaults_from_collateral_batch(
        &self,
        cycle_id: B256,
        entries: Vec<DebtorSettlement>,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        self.contract_api
            .settle_defaults_from_collateral_batch(cycle_id, entries)
            .await
    }

    pub async fn fund_creditors_from_pool_batch(
        &self,
        cycle_id: B256,
        entries: Vec<CreditorSettlement>,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        self.contract_api
            .fund_creditors_from_pool_batch(cycle_id, entries)
            .await
    }

    pub async fn finalize_clearing_cycle(
        &self,
        cycle_id: B256,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        self.contract_api.finalize_clearing_cycle(cycle_id).await
    }

    pub async fn mark_cycle_shortfall(
        &self,
        cycle_id: B256,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        self.contract_api.mark_cycle_shortfall(cycle_id).await
    }

    // --- direct read-only contract calls --------------------------------------------------

    /// The aToken backing `asset`, or `None` when `asset` is not an Aave-supplied stablecoin.
    pub async fn stablecoin_a_token(
        &self,
        asset: Address,
    ) -> Result<Option<Address>, BlockchainListenerError> {
        if asset == Address::ZERO {
            return Ok(None);
        }

        let contract = self.read_contract()?;
        let a_token = contract
            .stablecoinAToken(asset)
            .call()
            .await
            .map_err(|err| {
                BlockchainListenerError::RpcFailure(format!(
                    "failed to load stablecoin aToken for asset {asset}: {err}"
                ))
            })?;

        if a_token == Address::ZERO {
            Ok(None)
        } else {
            Ok(Some(a_token))
        }
    }

    /// The user's on-chain collateral total for `asset` at `block_number`, or `None` when the
    /// asset is not supported collateral and there is nothing to reconcile.
    ///
    /// ETH is custodied directly by Core4Mica, while stablecoin collateral is supplied to Aave —
    /// there the guaranteeable capacity (principal, excluding yield) is what backs the off-chain
    /// total.
    pub async fn guaranteeable_collateral(
        &self,
        user: Address,
        asset: Address,
        block_number: u64,
    ) -> Result<Option<U256>, BlockchainListenerError> {
        let contract = self.read_contract()?;
        let block = BlockId::from(block_number);

        let total = if asset == Address::ZERO {
            contract.collateral(user, asset).block(block).call().await
        } else if self.stablecoin_a_token(asset).await?.is_some() {
            contract
                .guaranteeCapacity(user, asset)
                .block(block)
                .call()
                .await
        } else {
            return Ok(None);
        }
        .map_err(|err| {
            BlockchainListenerError::RpcFailure(format!(
                "failed to load on-chain collateral for user {user} asset {asset}: {err}"
            ))
        })?;

        Ok(Some(total))
    }

    fn read_contract(
        &self,
    ) -> Result<Core4Mica::Core4MicaInstance<DynProvider>, BlockchainListenerError> {
        let contract_address = self.contract_address.parse::<Address>().map_err(|err| {
            BlockchainListenerError::EventHandlerError(format!(
                "failed to parse contract address {}: {err}",
                self.contract_address
            ))
        })?;

        Ok(Core4Mica::new(contract_address, self.read_provider.clone()))
    }
}
