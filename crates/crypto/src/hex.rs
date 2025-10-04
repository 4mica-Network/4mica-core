use hex::FromHexError;
use std::ops::Deref;
use std::str::FromStr;

pub fn decode_hex(s: &str) -> Result<Vec<u8>, FromHexError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let decoded = hex::decode(s)?;
    Ok(decoded)
}

#[derive(Debug, Clone)]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for HexBytes {
    type Err = FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(decode_hex(s)?))
    }
}

impl Deref for HexBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}
