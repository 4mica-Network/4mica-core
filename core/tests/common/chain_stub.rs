//! A `CoreContractApi` for chain-free service tests. Every call panics: a test using this stub
//! is asserting that the path under test never touches the chain.

use alloy::primitives::B256;
use async_trait::async_trait;
use core_service::error::CoreContractApiError;
use core_service::ethereum::{
    ClearingCommitInput, ClearingCycleView, ClearingTxResult, CoreContractApi, CreditorSettlement,
    DebtorSettlement, GuaranteeVersionConfig,
};
use rpc::SupportedTokenInfo;

pub struct UnusedContractApi;

#[async_trait]
impl CoreContractApi for UnusedContractApi {
    async fn get_chain_id(&self) -> Result<u64, CoreContractApiError> {
        unimplemented!("chain access is not expected in this test")
    }

    async fn get_guarantee_version_config(
        &self,
        _version: u64,
    ) -> Result<GuaranteeVersionConfig, CoreContractApiError> {
        unimplemented!("chain access is not expected in this test")
    }

    async fn get_withdrawal_grace_period(&self) -> Result<u64, CoreContractApiError> {
        unimplemented!("chain access is not expected in this test")
    }

    async fn get_supported_tokens(&self) -> Result<Vec<SupportedTokenInfo>, CoreContractApiError> {
        unimplemented!("chain access is not expected in this test")
    }

    async fn commit_clearing_cycle(
        &self,
        _input: ClearingCommitInput,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        unimplemented!("chain access is not expected in this test")
    }

    async fn settle_defaults_from_collateral_batch(
        &self,
        _cycle_id: B256,
        _entries: Vec<DebtorSettlement>,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        unimplemented!("chain access is not expected in this test")
    }

    async fn fund_creditors_from_pool_batch(
        &self,
        _cycle_id: B256,
        _entries: Vec<CreditorSettlement>,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        unimplemented!("chain access is not expected in this test")
    }

    async fn finalize_clearing_cycle(
        &self,
        _cycle_id: B256,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        unimplemented!("chain access is not expected in this test")
    }

    async fn mark_cycle_shortfall(
        &self,
        _cycle_id: B256,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        unimplemented!("chain access is not expected in this test")
    }

    async fn get_clearing_cycle(
        &self,
        _cycle_id: B256,
    ) -> Result<ClearingCycleView, CoreContractApiError> {
        unimplemented!("chain access is not expected in this test")
    }
}
