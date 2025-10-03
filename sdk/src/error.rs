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

    #[error(transparent)]
    Rpc(anyhow::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
