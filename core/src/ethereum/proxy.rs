use crate::{
    config::AppConfig,
    error::CoreContractApiError,
    ethereum::contract_abi::*,
    metrics::{ContractErrorKind, record_contract_call_error},
};
use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
};
use anyhow::anyhow;
use async_trait::async_trait;
use log::{error, info};
use rpc::SupportedTokenInfo;
use tokio::sync::Mutex;

/// Log and record a metric for a failed contract interaction.
fn observe_contract_error(method: &'static str, err: &CoreContractApiError) {
    match err {
        CoreContractApiError::ContractRevert(revert) => {
            error!("{method} reverted: {revert}");
            record_contract_call_error(method, ContractErrorKind::Revert, &revert.label());
        }
        CoreContractApiError::ContractCall(msg) => {
            error!("{method} contract call failed (transport): {msg}");
            record_contract_call_error(method, ContractErrorKind::Transport, "transport");
        }
        CoreContractApiError::TransportFailure(e) => {
            error!("{method} transport failure: {e}");
            record_contract_call_error(method, ContractErrorKind::Transport, "transport");
        }
        CoreContractApiError::PendingTxFailure(msg) => {
            error!("{method} pending transaction failed: {msg}");
            record_contract_call_error(method, ContractErrorKind::Transport, "pending_tx");
        }
        _ => {}
    }
}

/// Extension trait to observe (log + metric) a fallible contract interaction at
/// the call site, while converting the error into [`CoreContractApiError`].
trait ObserveContractError<T> {
    fn observe(self, method: &'static str) -> Result<T, CoreContractApiError>;
}

impl<T, E: Into<CoreContractApiError>> ObserveContractError<T> for Result<T, E> {
    fn observe(self, method: &'static str) -> Result<T, CoreContractApiError> {
        self.map_err(Into::into)
            .inspect_err(|err| observe_contract_error(method, err))
    }
}

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
pub struct ClearingTxResult {
    pub tx_hash: B256,
    pub block_number: Option<u64>,
    pub block_hash: Option<B256>,
}

/// One defaulting debtor in a batch collateral-settlement call.
#[derive(Debug, Clone)]
pub struct DebtorSettlement {
    pub debtor: Address,
    pub net_debit: U256,
    pub proof: Vec<B256>,
}

/// One net creditor in a batch pool-funding call.
#[derive(Debug, Clone)]
pub struct CreditorSettlement {
    pub creditor: Address,
    pub net_credit: U256,
    pub proof: Vec<B256>,
}

/// On-chain accounting/state snapshot for a settlement cycle, used to decide whether a cycle
/// is under-funded and should be driven to the terminal Shortfall state.
#[derive(Debug, Clone)]
pub struct ClearingCycleView {
    pub total_net_debit: U256,
    pub total_net_credit: U256,
    pub total_paid_in: U256,
    pub total_claimed_out: U256,
    pub total_default_covered: U256,
    pub total_resolved_debit: U256,
    pub payment_finality_deadline: u64,
    pub status: u8,
    pub exists: bool,
}

impl ClearingCycleView {
    /// Underlying value available to creditors: paid-in plus covered defaults.
    pub fn funded(&self) -> U256 {
        self.total_paid_in + self.total_default_covered
    }

    /// True when every debtor is resolved but recovered collateral cannot fully fund creditor
    /// claims — the precondition for the terminal Shortfall state.
    pub fn is_under_funded_and_resolved(&self) -> bool {
        self.total_resolved_debit == self.total_net_debit && self.funded() < self.total_net_credit
    }

    /// The decoded on-chain cycle status.
    pub fn status(&self) -> CycleStatus {
        CycleStatus::from_u8(self.status)
    }

    pub fn is_finalized(&self) -> bool {
        self.status() == CycleStatus::Finalized
    }

    pub fn is_shortfall(&self) -> bool {
        self.status() == CycleStatus::Shortfall
    }
}

/// Mirror of `ClearingHouse.CycleStatus` (contracts/src/ClearingHouse.sol). Keep these ordinals in
/// sync with the Solidity enum; `Unknown` guards against a contract that adds states ahead of this
/// build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleStatus {
    Committed,
    PaymentWindowOpen,
    Finalized,
    Defaulted,
    Shortfall,
    Unknown(u8),
}

impl CycleStatus {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Committed,
            1 => Self::PaymentWindowOpen,
            2 => Self::Finalized,
            3 => Self::Defaulted,
            4 => Self::Shortfall,
            other => Self::Unknown(other),
        }
    }
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

    async fn get_withdrawal_grace_period(&self) -> Result<u64, CoreContractApiError>;

    async fn get_supported_tokens(&self) -> Result<Vec<SupportedTokenInfo>, CoreContractApiError>;

    async fn commit_clearing_cycle(
        &self,
        input: ClearingCommitInput,
    ) -> Result<ClearingTxResult, CoreContractApiError>;

    async fn settle_defaults_from_collateral_batch(
        &self,
        cycle_id: B256,
        entries: Vec<DebtorSettlement>,
    ) -> Result<ClearingTxResult, CoreContractApiError>;

    async fn fund_creditors_from_pool_batch(
        &self,
        cycle_id: B256,
        entries: Vec<CreditorSettlement>,
    ) -> Result<ClearingTxResult, CoreContractApiError>;

    async fn finalize_clearing_cycle(
        &self,
        cycle_id: B256,
    ) -> Result<ClearingTxResult, CoreContractApiError>;

    /// Drive an under-funded cycle to the terminal Shortfall state.
    async fn mark_cycle_shortfall(
        &self,
        cycle_id: B256,
    ) -> Result<ClearingTxResult, CoreContractApiError>;

    /// Read the on-chain accounting/state snapshot for a cycle.
    async fn get_clearing_cycle(
        &self,
        cycle_id: B256,
    ) -> Result<ClearingCycleView, CoreContractApiError>;
}

impl CoreContractProxy {
    pub async fn new(config: &AppConfig) -> Result<Self, CoreContractApiError> {
        let wallet = EthereumWallet::new(config.secrets.ethereum_private_key_signer.clone());

        // Fetch the nonce from chain per tx rather than caching it locally. Writes are serialized
        // by `tx_write_lock`, so there is no concurrency benefit to caching — and a cached nonce
        // silently advances when a `.send()` reverts at gas estimation (e.g. a caught
        // `CycleUnderfunded`), leaving every following tx stuck behind a nonce gap.
        let provider = ProviderBuilder::new()
            .with_simple_nonce_management()
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
        let chain_id = self.provider.get_chain_id().await.observe("get_chain_id")?;
        Ok(chain_id)
    }

    async fn get_guarantee_version_config(
        &self,
        version: u64,
    ) -> Result<GuaranteeVersionConfig, CoreContractApiError> {
        let contract = self.build_contract();
        let version_config = contract
            .getGuaranteeVersionConfig(version)
            .call()
            .await
            .observe("getGuaranteeVersionConfig")?;

        Ok(GuaranteeVersionConfig {
            version,
            domain_separator: version_config.domainSeparator.into(),
            decoder: version_config.decoder,
            enabled: version_config.enabled,
        })
    }

    async fn get_withdrawal_grace_period(&self) -> Result<u64, CoreContractApiError> {
        let contract = self.build_contract();
        let grace_period = contract
            .withdrawalGracePeriod()
            .call()
            .await
            .observe("withdrawalGracePeriod")?;
        Ok(grace_period.to())
    }

    async fn get_supported_tokens(&self) -> Result<Vec<SupportedTokenInfo>, CoreContractApiError> {
        let contract = self.build_contract();
        let addresses = contract
            .getERC20Tokens()
            .call()
            .await
            .observe("getERC20Tokens")?;
        let mut tokens = Vec::with_capacity(addresses.len());
        for addr in addresses {
            let erc20 = ERC20Metadata::new(addr, self.provider.clone());
            let symbol = erc20.symbol().call().await.observe("erc20.symbol")?;
            let decimals = erc20.decimals().call().await.observe("erc20.decimals")?;
            // Plain ERC-20s have no domain separator; that is not an error, it just means this
            // token cannot be used for gasless deposits.
            let domain_separator = erc20
                .DOMAIN_SEPARATOR()
                .call()
                .await
                .ok()
                .map(|value| value.to_string());
            tokens.push(SupportedTokenInfo {
                symbol,
                address: addr.to_string(),
                decimals,
                domain_separator,
            });
        }
        Ok(tokens)
    }

    async fn commit_clearing_cycle(
        &self,
        input: ClearingCommitInput,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
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

        let receipt = tx
            .send()
            .await
            .observe("commitCycle")?
            .get_receipt()
            .await
            .observe("commitCycle")?;

        info!(
            "ClearingHouse.commitCycle confirmed in tx {:?}",
            receipt.transaction_hash
        );
        Ok(ClearingTxResult {
            tx_hash: receipt.transaction_hash,
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
        })
    }

    async fn settle_defaults_from_collateral_batch(
        &self,
        cycle_id: B256,
        entries: Vec<DebtorSettlement>,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        let _guard = self.tx_write_lock.lock().await;
        let contract = self.build_clearing_house();
        let entries: Vec<DebtorEntry> = entries
            .into_iter()
            .map(|e| DebtorEntry {
                debtor: e.debtor,
                netDebit: e.net_debit,
                proof: e.proof,
            })
            .collect();

        let receipt = contract
            .settleDefaultsFromCollateralBatch(cycle_id, entries)
            .send()
            .await
            .observe("settleDefaultsFromCollateralBatch")?
            .get_receipt()
            .await
            .observe("settleDefaultsFromCollateralBatch")?;

        info!(
            "ClearingHouse.settleDefaultsFromCollateralBatch confirmed in tx {:?}",
            receipt.transaction_hash
        );
        Ok(ClearingTxResult {
            tx_hash: receipt.transaction_hash,
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
        })
    }

    async fn fund_creditors_from_pool_batch(
        &self,
        cycle_id: B256,
        entries: Vec<CreditorSettlement>,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        let _guard = self.tx_write_lock.lock().await;
        let contract = self.build_clearing_house();
        let entries: Vec<CreditorEntry> = entries
            .into_iter()
            .map(|e| CreditorEntry {
                creditor: e.creditor,
                netCredit: e.net_credit,
                proof: e.proof,
            })
            .collect();

        let receipt = contract
            .fundCreditorsFromPoolBatch(cycle_id, entries)
            .send()
            .await
            .observe("fundCreditorsFromPoolBatch")?
            .get_receipt()
            .await
            .observe("fundCreditorsFromPoolBatch")?;

        info!(
            "ClearingHouse.fundCreditorsFromPoolBatch confirmed in tx {:?}",
            receipt.transaction_hash
        );
        Ok(ClearingTxResult {
            tx_hash: receipt.transaction_hash,
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
        })
    }

    async fn finalize_clearing_cycle(
        &self,
        cycle_id: B256,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        let _guard = self.tx_write_lock.lock().await;
        let contract = self.build_clearing_house();

        let receipt = contract
            .finalizeCycle(cycle_id)
            .send()
            .await
            .observe("finalizeCycle")?
            .get_receipt()
            .await
            .observe("finalizeCycle")?;

        info!(
            "ClearingHouse.finalizeCycle confirmed in tx {:?}",
            receipt.transaction_hash
        );
        Ok(ClearingTxResult {
            tx_hash: receipt.transaction_hash,
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
        })
    }

    async fn mark_cycle_shortfall(
        &self,
        cycle_id: B256,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        let _guard = self.tx_write_lock.lock().await;
        let contract = self.build_clearing_house();

        let receipt = contract
            .markCycleShortfall(cycle_id)
            .send()
            .await
            .observe("markCycleShortfall")?
            .get_receipt()
            .await
            .observe("markCycleShortfall")?;

        info!(
            "ClearingHouse.markCycleShortfall confirmed in tx {:?}",
            receipt.transaction_hash
        );
        Ok(ClearingTxResult {
            tx_hash: receipt.transaction_hash,
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
        })
    }

    async fn get_clearing_cycle(
        &self,
        cycle_id: B256,
    ) -> Result<ClearingCycleView, CoreContractApiError> {
        let contract = self.build_clearing_house();
        let cycle = contract
            .getCycle(cycle_id)
            .call()
            .await
            .observe("getCycle")?;
        Ok(ClearingCycleView {
            total_net_debit: cycle.totalNetDebit,
            total_net_credit: cycle.totalNetCredit,
            total_paid_in: cycle.totalPaidIn,
            total_claimed_out: cycle.totalClaimedOut,
            total_default_covered: cycle.totalDefaultCovered,
            total_resolved_debit: cycle.totalResolvedDebit,
            payment_finality_deadline: cycle.paymentFinalityDeadline,
            status: cycle.status,
            exists: cycle.exists,
        })
    }
}

#[cfg(test)]
mod clearing_cycle_view_tests {
    use super::*;

    fn view(
        paid_in: u64,
        default_covered: u64,
        net_credit: u64,
        resolved: u64,
        net_debit: u64,
    ) -> ClearingCycleView {
        ClearingCycleView {
            total_net_debit: U256::from(net_debit),
            total_net_credit: U256::from(net_credit),
            total_paid_in: U256::from(paid_in),
            total_claimed_out: U256::ZERO,
            total_default_covered: U256::from(default_covered),
            total_resolved_debit: U256::from(resolved),
            payment_finality_deadline: 0,
            status: 3,
            exists: true,
        }
    }

    #[test]
    fn funded_sums_paid_in_and_default_covered() {
        assert_eq!(view(100, 40, 200, 200, 200).funded(), U256::from(140u64));
    }

    #[test]
    fn under_funded_requires_full_debt_resolution() {
        // Resolved but pool short -> shortfall-eligible.
        assert!(view(100, 40, 200, 200, 200).is_under_funded_and_resolved());
        // Fully funded -> not a shortfall.
        assert!(!view(160, 40, 200, 200, 200).is_under_funded_and_resolved());
        // Under-funded but debt not yet fully resolved -> keep settling, not shortfall.
        assert!(!view(100, 40, 200, 100, 200).is_under_funded_and_resolved());
    }
}
