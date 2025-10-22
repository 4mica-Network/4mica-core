use alloy::signers::local::LocalSignerError;
use anyhow::anyhow;
use rpc;
use sea_orm::TransactionError as SeaTransactionError;
use thiserror::Error;
// ---------- SeaORM transaction error conversions ----------

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

impl From<SeaTransactionError<CoreContractApiError>> for CoreContractApiError {
    fn from(err: SeaTransactionError<CoreContractApiError>) -> Self {
        match err {
            SeaTransactionError::Connection(db_err) => {
                CoreContractApiError::DatabaseFailure(db_err)
            }
            SeaTransactionError::Transaction(inner) => inner,
        }
    }
}

// ---------- Domain/Layer error types ----------

#[derive(Debug, Error)]
pub enum BlockchainListenerError {
    #[error("Failed to decode blockchain logs: {0}")]
    DecodingFailure(#[from] alloy::sol_types::Error),

    #[error(transparent)]
    Db(#[from] PersistDbError),

    #[error("Database operation failed: {0}")]
    DatabaseFailure(#[from] sea_orm::DbErr),

    #[error("Event handler error: {0}")]
    EventHandlerError(String),

    #[error("Tab not found: {0}")]
    TabNotFound(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Unexpected error: {0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum CoreContractApiError {
    #[error("Failed to sign or send transaction: {0}")]
    TransportFailure(#[from] alloy::transports::TransportError),

    #[error("Private key error: {0}")]
    InvalidPrivateKey(String),

    #[error("Failed to decode ABI response: {0}")]
    AbiError(#[from] alloy::sol_types::Error),

    #[error("Database operation failed: {0}")]
    DatabaseFailure(#[from] sea_orm::DbErr),

    #[error("Invalid contract address: {0}")]
    InvalidAddress(String),

    #[error("Pending transaction failed: {0}")]
    PendingTxFailure(String),

    #[error("Unexpected core contract api error: {0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum PersistDbError {
    #[error("Database operation failed: {0}")]
    DatabaseFailure(#[from] sea_orm::DbErr),

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

    #[error("No pending withdrawal found for user {user}, asset {asset}")]
    WithdrawalNotFound { user: String, asset: String },

    #[error("Multiple pending withdrawals for user {user}, asset {asset} (found {count})")]
    MultiplePendingWithdrawals {
        user: String,
        asset: String,
        count: usize,
    },

    #[error(
        "optimistic lock conflict for user {user}, asset {asset_address}, expected version {expected_version}"
    )]
    OptimisticLockConflict {
        user: String,
        asset_address: String,
        expected_version: i32,
    },

    #[error("invariant violation: {0}")]
    InvariantViolation(String),
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("optimistic lock conflict")]
    OptimisticLockConflict,

    #[error("user not registered")]
    UserNotRegistered,

    #[error("tab already closed")]
    TabClosed,

    #[error("promise timestamp is in the future")]
    FutureTimestamp,

    #[error("req_id not valid")]
    InvalidRequestID,

    #[error("start timestamp modified")]
    ModifiedStartTs,

    #[error("database error: {0}")]
    Db(PersistDbError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type ServiceResult<T> = Result<T, ServiceError>;

impl From<PersistDbError> for ServiceError {
    fn from(e: PersistDbError) -> Self {
        match e {
            PersistDbError::UserNotFound(_) => ServiceError::UserNotRegistered,
            PersistDbError::TabNotFound(tab) => {
                ServiceError::NotFound(format!("Tab {tab} not found"))
            }
            PersistDbError::RemunerateEventNotFound(tab) => {
                ServiceError::NotFound(format!("No remunerate event found for tab {tab}"))
            }
            PersistDbError::TransactionNotFound(tx) => {
                ServiceError::NotFound(format!("Transaction {tx} not found"))
            }
            PersistDbError::InvalidTimestamp(_) => {
                ServiceError::InvalidParams("invalid timestamp".into())
            }
            PersistDbError::InvalidCollateral(msg) => ServiceError::InvalidParams(msg),
            PersistDbError::InvalidTxAmount(msg) => ServiceError::InvalidParams(msg),
            PersistDbError::InsufficientCollateral => {
                ServiceError::InvalidParams("Not enough free collateral".into())
            }
            PersistDbError::WithdrawalNotFound { user, asset } => ServiceError::NotFound(format!(
                "No pending withdrawal found for user {user}, asset {asset}"
            )),
            PersistDbError::MultiplePendingWithdrawals { user, asset, count } => {
                ServiceError::InvalidParams(format!(
                    "Multiple pending withdrawals for user {user}, asset {asset} (found {count})"
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

// ---------- Nice `From` conversions so we can use `?` everywhere ----------

// 1) Private key parsing (`.parse::<PrivateKeySigner>()?`)
impl From<LocalSignerError> for CoreContractApiError {
    fn from(e: LocalSignerError) -> Self {
        CoreContractApiError::InvalidPrivateKey(e.to_string())
    }
}

// 2) Contract method calls: `tx.send().await?`, `pending.get_receipt().await?`
impl From<alloy::contract::Error> for CoreContractApiError {
    fn from(e: alloy::contract::Error) -> Self {
        // You can introduce a dedicated variant if you prefer.
        CoreContractApiError::Other(anyhow!(e))
    }
}

impl From<alloy::providers::PendingTransactionError> for CoreContractApiError {
    fn from(e: alloy::providers::PendingTransactionError) -> Self {
        CoreContractApiError::PendingTxFailure(e.to_string())
    }
}

// ---------- Transport adapter ----------
pub fn service_error_to_rpc(err: ServiceError) -> jsonrpsee::types::ErrorObjectOwned {
    match err {
        ServiceError::InvalidParams(msg) => rpc::invalid_params_error(&msg),
        ServiceError::NotFound(msg) => rpc::invalid_params_error(&msg),
        ServiceError::UserNotRegistered => rpc::invalid_params_error("User not registered"),
        ServiceError::TabClosed => rpc::invalid_params_error("Tab is closed"),
        ServiceError::FutureTimestamp => rpc::invalid_params_error("Timestamp is in the future"),
        ServiceError::InvalidRequestID => rpc::invalid_params_error("req_id not valid"),
        ServiceError::ModifiedStartTs => rpc::invalid_params_error("start timestamp modified"),
        ServiceError::OptimisticLockConflict => {
            rpc::invalid_params_error("Optimistic lock conflict")
        }
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
