pub use hex::FromHexError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecodeHexError {
    #[error("invalid hex prefix, must start with '0x'")]
    InvalidPrefix,

    #[error(transparent)]
    FromHex(#[from] FromHexError),
}

/// Value must be prefixed with "0x"
pub fn decode_hex(value: &str) -> Result<Vec<u8>, DecodeHexError> {
    let Some(value) = value.strip_prefix("0x") else {
        return Err(DecodeHexError::InvalidPrefix);
    };

    let decoded = hex::decode(value)?;
    Ok(decoded)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
