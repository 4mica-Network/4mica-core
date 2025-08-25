use alloy::primitives::{TxHash, Address};
use rpc::common::UserTransactionInfo;

/// Interface for interacting with the 4MICA core database.
pub(crate) trait CoreDatabaseConnector {
    async fn get_user_deposit_total(&self, user_address: Address) -> anyhow::Result<f64>;

    async fn get_user_transactions_info(&self, user_address: Address) -> anyhow::Result<Vec<UserTransactionInfo>>;

    async fn get_transaction_info(&self, tx_hash: TxHash) -> anyhow::Result<UserTransactionInfo>;

    async fn get_transactions_info(&self, tx_hash: Vec<TxHash>) -> anyhow::Result<Vec<UserTransactionInfo>>;
}
