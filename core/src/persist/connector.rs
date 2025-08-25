use alloy::primitives::TxHash;
use rpc::common::UserTransactionInfo;

/// Interface for interacting with the 4MICA core database.
pub(crate) trait CoreDatabaseConnector {
    async fn get_user_deposit_total(&self, user_address: String) -> anyhow::Result<f64>;

    async fn get_user_transaction_details(&self, user_address: String) -> anyhow::Result<Vec<UserTransactionInfo>>;

    async fn get_transaction_details(&self, tx_hash: TxHash) -> anyhow::Result<UserTransactionInfo>;
}
