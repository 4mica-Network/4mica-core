use alloy::primitives::{TxHash, Address};
use rpc::common::UserTransactionInfo;

/// Interface for interacting with the 4MICA core database.
pub(crate) trait CoreDatabaseConnector {
    /// Get the total deposit posted by the user associated with `user_address`.
    ///
    /// Note: the returned value is the total deposit, i.e., the sum of locked and available.
    async fn get_user_deposit_total(&self, user_address: Address) -> anyhow::Result<f64>;

    /// Get the deposit posted by the user that is locked.
    async fn get_user_deposit_locked(&self, user_address: Address) -> anyhow::Result<f64>;

    /// Get the [`UserTransactionInfo`] of all [`Transaction`] associated with `user_address`.
    async fn get_user_transactions_info(&self, user_address: Address) -> anyhow::Result<Vec<UserTransactionInfo>>;

    /// Obtain the [`UserTransactionInfo`] for the transaction with hash `tx_hash`.v
    async fn get_transaction_info(&self, tx_hash: TxHash) -> anyhow::Result<UserTransactionInfo>;

    /// Obtain the [`UserTransactionInfo`] to all transactions indicated by `tx_hashes`.
    async fn get_transactions_info(&self, tx_hash: Vec<TxHash>) -> anyhow::Result<Vec<UserTransactionInfo>>;
}
