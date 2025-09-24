use thiserror::Error;

#[derive(Debug, Error)]
pub enum TxProcessingError {
    #[error("RPC error: {0}")]
    Rpc(#[from] rpc::RpcError),

    #[error("Ethereum provider error: {0}")]
    Provider(#[from] alloy::providers::ProviderError),

    #[error("Persist DB error: {0}")]
    Persist(#[from] crate::persist::error::PersistDbError),

    #[error("UTF-8 decode error in tx input: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Transaction not found")]
    NotFound,

    #[error("Invalid transaction type")]
    InvalidTxType,
}
pub type Result<T> = std::result::Result<T, TxProcessingError>;
