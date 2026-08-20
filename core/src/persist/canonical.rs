//! Canonical text encoding for values stored in text columns.

use std::str::FromStr;

use alloy::primitives::{Address, B256, U256};

use crate::error::PersistDbError;

pub trait Canonical: Sized {
    /// The text format written to the database.
    fn canonical(&self) -> String;

    /// Decode a value previously written by [`Canonical::canonical`].
    fn from_canonical(raw: &str) -> Result<Self, PersistDbError>;
}

impl Canonical for Address {
    /// Lowercase hex.
    fn canonical(&self) -> String {
        format!("{self:#x}")
    }

    fn from_canonical(raw: &str) -> Result<Self, PersistDbError> {
        Address::from_str(raw.trim()).map_err(|e| {
            PersistDbError::InvariantViolation(format!("stored address {raw} is not valid: {e}"))
        })
    }
}

impl Canonical for U256 {
    /// Decimal, so the stored text sorts and reads the way the amount does.
    fn canonical(&self) -> String {
        self.to_string()
    }

    fn from_canonical(raw: &str) -> Result<Self, PersistDbError> {
        U256::from_str(raw.trim()).map_err(|e| {
            PersistDbError::InvariantViolation(format!("stored u256 {raw} is not valid: {e}"))
        })
    }
}

impl Canonical for B256 {
    /// `0x`-prefixed lowercase hex.
    fn canonical(&self) -> String {
        format!("{self:#x}")
    }

    fn from_canonical(raw: &str) -> Result<Self, PersistDbError> {
        B256::from_str(raw.trim()).map_err(|e| {
            PersistDbError::InvariantViolation(format!("stored hash {raw} is not valid: {e}"))
        })
    }
}

/// A guarantee request id.
///
/// Wraps [`U256`] only to carry a different stored form: request ids are hex, while every other
/// `U256` column is decimal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReqId(pub U256);

impl ReqId {
    pub fn value(self) -> U256 {
        self.0
    }
}

impl From<U256> for ReqId {
    fn from(value: U256) -> Self {
        Self(value)
    }
}

impl Canonical for ReqId {
    fn canonical(&self) -> String {
        format!("{:#x}", self.0)
    }

    fn from_canonical(raw: &str) -> Result<Self, PersistDbError> {
        U256::from_canonical(raw).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_is_lowercase_even_when_display_checksums() {
        let addr = Address::from_str("0x7Ea9d1AEa2784d501d7C01a74C8d48356A7E3666").unwrap();
        assert_eq!(
            addr.canonical(),
            "0x7ea9d1aea2784d501d7c01a74c8d48356a7e3666"
        );
        // Display is EIP-55 checksummed, which is exactly what must never reach a column.
        assert_ne!(addr.to_string(), addr.canonical());
    }

    #[test]
    fn round_trips_through_the_stored_form() {
        let addr = Address::repeat_byte(0xAB);
        assert_eq!(Address::from_canonical(&addr.canonical()).unwrap(), addr);
    }

    #[test]
    fn any_input_casing_lands_on_one_spelling() {
        let lower = Address::from_canonical("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
        let upper = Address::from_canonical("0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD").unwrap();
        assert_eq!(lower.canonical(), upper.canonical());
    }

    #[test]
    fn a_row_that_no_longer_decodes_is_an_invariant_violation() {
        let err = Address::from_canonical("not-an-address").unwrap_err();
        assert!(matches!(err, PersistDbError::InvariantViolation(_)));
    }

    #[test]
    fn u256_is_stored_as_decimal() {
        let value = U256::from(255u64);
        assert_eq!(value.canonical(), "255");
        assert_eq!(U256::from_canonical(&value.canonical()).unwrap(), value);
    }

    #[test]
    fn req_id_is_stored_as_hex() {
        let req_id = ReqId(U256::from(255u64));
        assert_eq!(req_id.canonical(), "0xff");
        assert_eq!(ReqId::from_canonical(&req_id.canonical()).unwrap(), req_id);
        // The two u256 encodings must not be mistaken for one another.
        assert_ne!(req_id.canonical(), req_id.value().canonical());
    }

    #[test]
    fn u256_still_decodes_rows_written_as_hex() {
        // `FromStr` takes both forms, so a req_id column read as a plain u256 is not silently wrong.
        assert_eq!(U256::from_canonical("0xff").unwrap(), U256::from(255u64));
    }

    #[test]
    fn b256_round_trips_and_rejects_junk() {
        let hash = B256::repeat_byte(0x0a);
        assert_eq!(hash.canonical(), format!("0x{}", "0a".repeat(32)));
        assert_eq!(B256::from_canonical(&hash.canonical()).unwrap(), hash);
        assert!(matches!(
            B256::from_canonical("0x00").unwrap_err(),
            PersistDbError::InvariantViolation(_)
        ));
    }

    #[test]
    fn a_corrupt_number_is_an_invariant_violation() {
        assert!(matches!(
            U256::from_canonical("twelve").unwrap_err(),
            PersistDbError::InvariantViolation(_)
        ));
    }
}
