use hex::FromHexError;
use std::ops::Deref;
use std::str::FromStr;

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
        let s = s.strip_prefix("0x").unwrap_or(s);
        let decoded = hex::decode(s)?;
        Ok(Self(decoded))
    }
}

impl Deref for HexBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}