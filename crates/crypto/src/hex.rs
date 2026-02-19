use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

pub use hex::FromHexError;

#[derive(Debug, Error)]
pub enum DecodeHexError {
    #[error("invalid hex prefix, must start with '0x'")]
    InvalidPrefix,

    #[error(transparent)]
    FromHex(#[from] FromHexError),
}

/// Hex-encoded bytes serialized as a lowercase hex string without a `0x` prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    /// Wrap raw bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrow the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the bytes as an owned vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Return lowercase hex without a `0x` prefix.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl From<Vec<u8>> for HexBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::from_bytes(value)
    }
}

impl From<&[u8]> for HexBytes {
    fn from(value: &[u8]) -> Self {
        Self::from_bytes(value)
    }
}

impl AsRef<[u8]> for HexBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Serialize for HexBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let value = value.strip_prefix("0x").unwrap_or(value.as_str());
        let decoded = hex::decode(value)
            .map_err(|e| serde::de::Error::custom(format!("invalid hex: {e}")))?;
        Ok(Self(decoded))
    }
}

/// Decode hex that must be prefixed with `0x`.
pub fn decode_hex(value: &str) -> Result<Vec<u8>, DecodeHexError> {
    let Some(value) = value.strip_prefix("0x") else {
        return Err(DecodeHexError::InvalidPrefix);
    };

    let decoded = hex::decode(value)?;
    Ok(decoded)
}

/// Encode bytes as hex with a `0x` prefix.
pub fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
