//! Decoding of on-chain revert data returned by contract calls.

use std::fmt;

use alloy::primitives::{Bytes, FixedBytes};

use crate::ethereum::contract_abi::{ClearingHouse, Core4Mica};

/// Structured representation of contract revert data.
#[derive(Debug, Clone)]
pub struct ContractRevert {
    /// The 4-byte error selector (`keccak256(signature)[0..4]`).
    pub selector: FixedBytes<4>,
    /// Canonical error signature (e.g. `"InsufficientAvailable()"`) when the
    /// selector matches a known contract or builtin error; `None` otherwise.
    pub signature: Option<&'static str>,
    /// Raw ABI-encoded revert payload (selector + arguments), kept for logging.
    pub data: Bytes,
}

impl ContractRevert {
    /// Decode revert data into a [`ContractRevert`], resolving the signature
    /// against the known contract and builtin errors.
    pub fn decode(data: Bytes) -> Self {
        let selector = if data.len() >= 4 {
            FixedBytes::<4>::from_slice(&data[..4])
        } else {
            FixedBytes::<4>::ZERO
        };
        let signature = lookup_signature(selector.0);
        Self {
            selector,
            signature,
            data,
        }
    }

    /// A low-cardinality label for metrics: the canonical signature when known,
    /// otherwise the selector as a `0x`-prefixed hex string.
    pub fn label(&self) -> String {
        self.signature
            .map(str::to_string)
            .unwrap_or_else(|| alloy::hex::encode_prefixed(self.selector))
    }
}

impl fmt::Display for ContractRevert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.signature {
            Some(sig) => write!(f, "{sig} (data {})", self.data),
            None => write!(
                f,
                "unknown error {} (data {})",
                alloy::hex::encode_prefixed(self.selector),
                self.data
            ),
        }
    }
}

/// Solidity builtins: `Error(string)` (revert strings) and `Panic(uint256)`.
/// These are not part of any contract's error set, so they are matched directly.
const BUILTIN_ERRORS: &[([u8; 4], &str)] = &[
    ([0x08, 0xc3, 0x79, 0xa0], "Error(string)"),
    ([0x4e, 0x48, 0x7b, 0x71], "Panic(uint256)"),
];

/// Resolve a selector to its canonical signature, preferring the contract error
/// sets and falling back to the Solidity builtins.
fn lookup_signature(selector: [u8; 4]) -> Option<&'static str> {
    Core4Mica::Core4MicaErrors::signature_by_selector(selector)
        .or_else(|| ClearingHouse::ClearingHouseErrors::signature_by_selector(selector))
        .or_else(|| {
            BUILTIN_ERRORS
                .iter()
                .find(|(sel, _)| *sel == selector)
                .map(|(_, sig)| *sig)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolError;

    #[test]
    fn decodes_known_custom_error() {
        // `InsufficientAvailable()` selector, no arguments.
        let selector = Core4Mica::InsufficientAvailable::SELECTOR;
        let revert = ContractRevert::decode(Bytes::from(selector.to_vec()));
        assert_eq!(revert.signature, Some("InsufficientAvailable()"));
        assert_eq!(revert.label(), "InsufficientAvailable()");
    }

    #[test]
    fn decodes_builtin_error_string() {
        let revert = ContractRevert::decode(Bytes::from(vec![0x08, 0xc3, 0x79, 0xa0]));
        assert_eq!(revert.signature, Some("Error(string)"));
    }

    #[test]
    fn unknown_selector_falls_back_to_hex() {
        let revert = ContractRevert::decode(Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(revert.signature, None);
        assert_eq!(revert.label(), "0xdeadbeef");
    }

    #[test]
    fn short_data_does_not_panic() {
        let revert = ContractRevert::decode(Bytes::from(vec![0x01, 0x02]));
        assert_eq!(revert.signature, None);
    }
}
