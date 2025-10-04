use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Invalid contract address: {0}")]
    InvalidContractAddress(String),

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
}

#[derive(Error, Debug)]
pub enum Error4Mica {
    #[error(transparent)]
    Validation(#[from] ValidationError),

    #[error("Config missing: {0}")]
    ConfigMissing(String),

    #[error("Invalid params: {0}")]
    InvalidParams(String),

    #[error(transparent)]
    Rpc(#[from] jsonrpsee::core::ClientError),

    #[error(transparent)]
    ContractError(#[from] alloy::contract::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
