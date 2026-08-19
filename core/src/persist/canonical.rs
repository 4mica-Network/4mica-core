//! Canonical text encoding for values stored in text columns.

use std::str::FromStr;

use alloy::primitives::Address;

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
}
