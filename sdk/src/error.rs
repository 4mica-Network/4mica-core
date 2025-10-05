use alloy::primitives::Address;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
}

#[derive(Debug, Error)]
pub enum PaymentSignError {
    #[error("address mismatch: signer={signer:?} != claims.user_address={claims}")]
    AddressMismatch { signer: Address, claims: String },

    #[error("invalid user address in claims")]
    InvalidUserAddress,

    #[error("invalid recipient address in claims")]
    InvalidRecipientAddress,

    #[error("digest failed: {0}")]
    DigestFailed(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),
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
    PaymentSign(#[from] PaymentSignError),

    #[error(transparent)]
    Rpc(#[from] jsonrpsee::core::ClientError),

    #[error(transparent)]
    ContractError(#[from] alloy::contract::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
