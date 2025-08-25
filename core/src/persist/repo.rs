use alloy::consensus::{Transaction, TxEnvelope};
use alloy::contract::ContractInstance;
use alloy::dyn_abi::DynSolValue;
use alloy::primitives::{address, Address, TxHash, B256};
use alloy::primitives::utils::format_units;
use alloy::providers::fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller};
use alloy::providers::{Identity, RootProvider};
use alloy::sol;
use futures_util::future::join_all;
use rpc::common::UserTransactionInfo;
use blockchain::txtools::fetch_transaction;
pub(crate) use crate::persist::connector::CoreDatabaseConnector;

// TODO: this is a duplicate from elsewhere
type EthereumProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

pub(crate) struct EthereumConnector(pub(crate) EthereumProvider);

// TODO: load core contract address from .env
const CORE_CONTRACT_ADDRESS_4MICA: Address = address!("1234123412341234123412341234123412341234");

// TODO: fix ABI path
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Core4MicaContract,
    "../contracts/src/core/AuthorityContract.json"
);

impl EthereumConnector {
    /// Obtain the 4MICA Core Contract.
    fn get_core_contract(&self) -> anyhow::Result<ContractInstance<EthereumProvider>> {
        Core4MicaContract::new(CORE_CONTRACT_ADDRESS_4MICA, self.0.clone())
    }
}

impl CoreDatabaseConnector for EthereumConnector {
    async fn get_user_deposit_total(&self, user_address: Address) -> anyhow::Result<f64> {
        let user_address = DynSolValue::from(user_address);
        let user = self
            .get_core_contract()?
            .function("users", &[user_address])?
            .call()
            .await?
            .first()
            .ok_or(anyhow::Error::msg("user not registered"))?
            .as_custom_struct()
            .ok_or(anyhow::Error::msg("internal error: failed to convert collateral to f64"))?;

        // TODO: quit hardcoding field indices
        let collateral = user.2[1]
            .as_uint()
            .ok_or(anyhow::Error::msg("internal error: failed to convert collateral to f64"))?
            .0;

        format_units(collateral, "eth")?
            .parse::<f64>()
            .map_err(anyhow::Error::new)
    }

    async fn get_user_deposit_locked(&self, user_address: Address) -> anyhow::Result<f64> {
        let user_txs = self.get_user_transactions_info(user_address).await?;
        Ok(user_txs.iter().filter(|tx| !tx.finalized).map(|open_tx| open_tx.amount).sum())
    }

    async fn get_user_transactions_info(&self, user_address: Address) -> anyhow::Result<Vec<UserTransactionInfo>> {
        let user_address = DynSolValue::from(user_address);
        let transaction_hashes = self.get_core_contract()?
            // TODO: fix function name
            .function("transactions", &[user_address])?
            .call()
            .await?
            .iter()
            .map(|tx_hash| B256::from(tx_hash.as_uint().expect("valid transaction").0))
            .collect();

        self.get_transactions_info(transaction_hashes).await
    }

    async fn get_transaction_info(&self, tx_hash: TxHash) -> anyhow::Result<UserTransactionInfo> {
        let raw_tx = fetch_transaction(&self.0, tx_hash).await?;

        let inner = raw_tx.inner;
        let signer = inner.signer();
        let (to, value) = match inner.inner() {
            TxEnvelope::Eip1559(tx) => Ok((tx.to(), tx.value())),
            _ => Err(anyhow::Error::msg("invalid transaction: invalid type"))
        }?;

        let to = to.ok_or(anyhow::Error::msg("invalid transaction: invalid to-address"))?;
        // TODO: fix conversion
        let value = f64::from(value);

        Ok(UserTransactionInfo {
            user_addr: signer.to_string(),
            recipient_addr: to.to_string(),
            tx_hash: tx_hash.to_string(),
            amount: value,
            finalized: false, // ???
            failed: false, // ???
            cert: None,
            created_at: 0,
        })
    }

    async fn get_transactions_info(&self, tx_hashes: Vec<TxHash>) -> anyhow::Result<Vec<UserTransactionInfo>> {
        let transactions = tx_hashes.iter().map(async |tx_hash| self.get_transaction_info(tx_hash).await);
        join_all(transactions)
            .await
            .into_iter()
            .collect()
    }
}
