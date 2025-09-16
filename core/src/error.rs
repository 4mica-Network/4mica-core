use sea_orm::TransactionError as SeaTransactionError;
use thiserror::Error;

/// Convert transaction-layer errors into PersistDbError
impl From<SeaTransactionError<PersistDbError>> for PersistDbError {
    fn from(err: SeaTransactionError<PersistDbError>) -> Self {
        match err {
            SeaTransactionError::Connection(db_err) => PersistDbError::DatabaseFailure(db_err),
            SeaTransactionError::Transaction(inner) => inner,
        }
    }
}

impl From<SeaTransactionError<BlockchainListenerError>> for BlockchainListenerError {
    fn from(err: SeaTransactionError<BlockchainListenerError>) -> Self {
        match err {
            SeaTransactionError::Connection(db_err) => {
                BlockchainListenerError::DatabaseFailure(db_err)
            }
            SeaTransactionError::Transaction(inner) => inner,
        }
    }
}

#[derive(Debug, Error)]
pub enum BlockchainListenerError {
    /// Errors while decoding on-chain data/logs.
    #[error("Failed to decode blockchain logs: {0}")]
    DecodingFailure(#[from] alloy::sol_types::Error),

    /// Transparently wrap any PersistDbError from the repo layer.
    /// This enables `?` on repo calls without extra glue code.
    #[error(transparent)]
    Db(#[from] PersistDbError),

    /// Direct DB errors raised in this layer (if any).
    #[error("Database operation failed: {0}")]
    DatabaseFailure(#[from] sea_orm::DbErr),

    /// Optional domain errors that may be raised directly in the listener layer.
    #[error("Tab not found: {0}")]
    TabNotFound(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    /// Catch-all for unexpected errors.
    #[error("Unexpected error: {0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum PersistDbError {
    /// Low-level database failure.
    #[error("Database operation failed: {0}")]
    DatabaseFailure(#[from] sea_orm::DbErr),

    /// Domain errors from the persistence layer.
    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Tab not found: {0}")]
    TabNotFound(String),

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(i64),

    #[error("Invalid collateral value: {0}")]
    InvalidCollateral(String),

    #[error("Invalid transaction amount: {0}")]
    InvalidTxAmount(String),

    #[error("Insufficient collateral")]
    InsufficientCollateral,

    #[error("Multiple pending withdrawals for user {user} (found {count})")]
    MultiplePendingWithdrawals { user: String, count: usize },
}
