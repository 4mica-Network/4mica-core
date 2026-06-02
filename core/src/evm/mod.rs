//! EVM-facing types and logic for the core service.
//!
//! This module gathers the Ethereum-specific encoding, hashing, signature, and
//! parsing helpers that the service layer relies on, keeping that logic out of
//! the business orchestration code. The root module holds the primitives shared
//! across domains; domain-specific logic lives in the submodules:
//!
//! - [`clearing`] — settlement-cycle / netting / clearing leaf encoding.
//! - [`guarantee`] — payment-guarantee request signing and identifiers.
//! - [`siwe`] — Sign-In With Ethereum message parsing and verification.

use std::str::FromStr;

use alloy::primitives::{Address, B256, U256, keccak256};

use crate::error::{ServiceError, ServiceResult};

pub mod clearing;
pub mod guarantee;
pub mod siwe;

/// keccak256 over the length-prefixed concatenation of `parts`.
///
/// Each part is encoded as an 8-byte big-endian length followed by its bytes,
/// which makes the digest unambiguous with respect to field boundaries (so two
/// different field splits can never collide). Both the clearing batch hash and
/// the guarantee identifier are built on this scheme.
pub fn length_prefixed_keccak(parts: &[&[u8]]) -> B256 {
    let mut encoded = Vec::new();
    for part in parts {
        encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
        encoded.extend_from_slice(part);
    }
    keccak256(encoded)
}

/// Left-pad a 20-byte address into a 32-byte EVM word (ABI address encoding).
pub fn address_word(address: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    word
}

/// The canonical on-chain identifier for a settlement cycle: keccak256 of the
/// textual cycle id. Used both as the ClearingHouse cycle id and as the
/// cycle-scoped value bound into guarantee claims.
pub fn cycle_id_hash(cycle_id: &str) -> B256 {
    keccak256(cycle_id.as_bytes())
}

/// Encode a 32-byte hash as a `0x`-prefixed lowercase hex string.
pub fn bytes32_hex(value: B256) -> String {
    crypto::hex::encode_hex(value.as_slice())
}

/// Parse a required EVM address, surfacing a labelled [`ServiceError::InvalidParams`].
pub fn parse_address(label: &str, raw: &str) -> ServiceResult<Address> {
    Address::from_str(raw.trim()).map_err(|err| {
        ServiceError::InvalidParams(format!("invalid {label} address '{raw}': {err}"))
    })
}

/// Parse an optional EVM address, treating an empty/blank value as [`Address::ZERO`].
///
/// Used for configuration that may be left unset (e.g. an unconfigured
/// ClearingHouse address defaults to the zero address).
pub fn parse_optional_address(label: &str, raw: &str) -> ServiceResult<Address> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(Address::ZERO);
    }
    parse_address(label, value)
}

/// Parse a 32-byte hash, surfacing a labelled [`ServiceError::InvalidParams`].
pub fn parse_bytes32(label: &str, raw: &str) -> ServiceResult<B256> {
    B256::from_str(raw.trim())
        .map_err(|err| ServiceError::InvalidParams(format!("invalid {label} '{raw}': {err}")))
}

/// Parse a [`U256`] amount, surfacing a labelled [`ServiceError::InvalidParams`].
pub fn parse_u256(label: &str, raw: &str) -> ServiceResult<U256> {
    U256::from_str(raw.trim())
        .map_err(|err| ServiceError::InvalidParams(format!("invalid {label} '{raw}': {err}")))
}
