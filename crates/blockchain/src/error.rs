use thiserror::Error;

pub type Result<T> = std::result::Result<T, TxProcessingError>;

#[derive(Debug, Error)]
pub enum TxProcessingError {
    /// Generic RPC or provider error
    #[error("RPC/provider error: {0}")]
    Rpc(#[from] anyhow::Error),

    /// Invalid UTF-8 in transaction input data
    #[error("UTF-8 decode error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// Transaction not found on chain
    #[error("Transaction not found")]
    NotFound,

    /// Transaction type is not supported (e.g. not EIP-7702)
    #[error("Invalid transaction type")]
    InvalidTxType,

    /// Invalid user-supplied parameters
    #[error("{0}")]
    InvalidParams(String),
}
