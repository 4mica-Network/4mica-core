use anyhow::anyhow;
use rpc;
use sea_orm::TransactionError as SeaTransactionError;
use thiserror::Error;

// ---------- SeaORM transaction error conversions ----------

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

// ---------- Domain/Layer error types ----------

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

    #[error("No remunerate event found for tab {0}")]
    RemunerateEventNotFound(String),

    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(i64),

    #[error("Invalid collateral value: {0}")]
    InvalidCollateral(String),

    #[error("Invalid transaction amount: {0}")]
    InvalidTxAmount(String),

    #[error("Insufficient collateral")]
    InsufficientCollateral,

    #[error("No pending withdrawal found for user {user}")]
    WithdrawalNotFound { user: String },

    #[error("Multiple pending withdrawals for user {user} (found {count})")]
    MultiplePendingWithdrawals { user: String, count: usize },

    #[error("optimistic lock conflict for user {user}, expected version {expected_version}")]
    OptimisticLockConflict { user: String, expected_version: i32 },

    #[error("invariant violation: {0}")]
    InvariantViolation(String),
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("optimistic lock conflict")]
    OptimisticLockConflict,

    /// For unclassified DB errors; prefer mapping to a higher-level variant when possible.
    #[error("database error: {0}")]
    Db(PersistDbError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type ServiceResult<T> = Result<T, ServiceError>;

// Provide a *semantic* mapping from persistence-layer errors to service-layer errors.
// This lets call sites use `?` and still get nice outward-facing errors.
impl From<PersistDbError> for ServiceError {
    fn from(e: PersistDbError) -> Self {
        match e {
            PersistDbError::UserNotFound(_) => {
                ServiceError::InvalidParams("User not registered".into())
            }
            PersistDbError::TabNotFound(tab) => {
                ServiceError::InvalidParams(format!("Tab not found: {tab}"))
            }
            PersistDbError::RemunerateEventNotFound(tab) => {
                ServiceError::NotFound(format!("No remunerate event found for tab {tab}"))
            }
            PersistDbError::TransactionNotFound(tx) => {
                ServiceError::NotFound(format!("Transaction not found: {tx}"))
            }
            PersistDbError::InvalidTimestamp(_) => {
                ServiceError::InvalidParams("invalid timestamp".into())
            }
            PersistDbError::InvalidCollateral(msg) => ServiceError::InvalidParams(msg),
            PersistDbError::InvalidTxAmount(msg) => ServiceError::InvalidParams(msg),
            PersistDbError::InsufficientCollateral => {
                ServiceError::InvalidParams("Not enough free collateral".into())
            }
            PersistDbError::WithdrawalNotFound { user } => {
                ServiceError::NotFound(format!("No pending withdrawal found for user {user}"))
            }
            PersistDbError::MultiplePendingWithdrawals { user, count } => {
                ServiceError::InvalidParams(format!(
                    "Multiple pending withdrawals for user {user} (found {count})"
                ))
            }
            PersistDbError::OptimisticLockConflict { .. } => ServiceError::OptimisticLockConflict,
            PersistDbError::InvariantViolation(msg) => ServiceError::Other(anyhow!(msg)),
            PersistDbError::DatabaseFailure(e) => {
                ServiceError::Db(PersistDbError::DatabaseFailure(e))
            }
        }
    }
}

// ---------- Transport adapter(s) ----------
pub fn service_error_to_rpc(err: ServiceError) -> jsonrpsee::types::ErrorObjectOwned {
    match err {
        ServiceError::InvalidParams(msg) => rpc::invalid_params_error(&msg),
        ServiceError::NotFound(msg) => rpc::invalid_params_error(&msg),
        ServiceError::OptimisticLockConflict => rpc::invalid_params_error("Invalid parameters"),
        ServiceError::Db(e) => {
            log::error!("DB error: {e}");
            rpc::internal_error()
        }
        ServiceError::Other(e) => {
            log::error!("Internal error: {e:#}");
            rpc::internal_error()
        }
    }
}
