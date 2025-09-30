//! contract.rs — ABI event bindings + helpers (Alloy)
//!
//! - `abi` module contains the `sol!`-generated event types.
//! - `EVENT_SIGNATURES` is a const array of the human-readable event signatures.
//! - `EVENT_SIGNATURE_HASHES` is a const array of keccak256 `topic0` hashes.
//!

#![allow(dead_code)]

use alloy::sol_types::SolEvent;
use alloy_primitives::B256;

pub mod abi {
    use alloy::sol;

    sol! {
        #[derive(Debug)]
        event UserRegistered(address indexed user, uint256 initial_collateral);

        #[derive(Debug)]
        event CollateralDeposited(address indexed user, uint256 amount);

        #[derive(Debug)]
        event RecipientRemunerated(uint256 indexed tab_id, uint256 amount);

        #[derive(Debug)]
        event CollateralWithdrawn(address indexed user, uint256 amount);

        #[derive(Debug)]
        event WithdrawalRequested(address indexed user, uint256 when, uint256 amount);

        #[derive(Debug)]
        event WithdrawalCanceled(address indexed user);

        #[derive(Debug)]
        event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);

        #[derive(Debug)]
        event RemunerationGracePeriodUpdated(uint256 newGracePeriod);

        #[derive(Debug)]
        event TabExpirationTimeUpdated(uint256 newExpirationTime);

        #[derive(Debug)]
        event SynchronizationDelayUpdated(uint256 newSynchronizationDelay);
    }
}

// Re-export events at the file root for convenient `use crate::contract::*;`
pub use abi::{
    CollateralDeposited, CollateralWithdrawn, RecipientRemunerated, RemunerationGracePeriodUpdated,
    SynchronizationDelayUpdated, TabExpirationTimeUpdated, UserRegistered, WithdrawalCanceled,
    WithdrawalGracePeriodUpdated, WithdrawalRequested,
};

/// Human-readable ABI signatures (e.g. `"UserRegistered(address,uint256)"`).
pub const EVENT_SIGNATURES: [&str; 10] = [
    UserRegistered::SIGNATURE,
    CollateralDeposited::SIGNATURE,
    RecipientRemunerated::SIGNATURE,
    CollateralWithdrawn::SIGNATURE,
    WithdrawalRequested::SIGNATURE,
    WithdrawalCanceled::SIGNATURE,
    WithdrawalGracePeriodUpdated::SIGNATURE,
    RemunerationGracePeriodUpdated::SIGNATURE,
    TabExpirationTimeUpdated::SIGNATURE,
    SynchronizationDelayUpdated::SIGNATURE,
];

/// Keccak256 topic0 hashes for the events above (as `B256`).
pub const EVENT_SIGNATURE_HASHES: [B256; 10] = [
    UserRegistered::SIGNATURE_HASH,
    CollateralDeposited::SIGNATURE_HASH,
    RecipientRemunerated::SIGNATURE_HASH,
    CollateralWithdrawn::SIGNATURE_HASH,
    WithdrawalRequested::SIGNATURE_HASH,
    WithdrawalCanceled::SIGNATURE_HASH,
    WithdrawalGracePeriodUpdated::SIGNATURE_HASH,
    RemunerationGracePeriodUpdated::SIGNATURE_HASH,
    TabExpirationTimeUpdated::SIGNATURE_HASH,
    SynchronizationDelayUpdated::SIGNATURE_HASH,
];

/// Convenience: return all event names as a `Vec`.
pub fn all_event_signatures() -> Vec<&'static str> {
    EVENT_SIGNATURES.to_vec()
}

/// Convenience: return all topic0 hashes as a `Vec`.
pub fn all_event_topics() -> Vec<B256> {
    EVENT_SIGNATURE_HASHES.to_vec()
}

/// Utility: check if a given `topic0` matches any known event here.
pub fn is_known_event_topic(topic0: &B256) -> bool {
    EVENT_SIGNATURE_HASHES.iter().any(|t| t == topic0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_and_hashes_align() {
        assert_eq!(EVENT_SIGNATURES.len(), EVENT_SIGNATURE_HASHES.len());
        assert_eq!(EVENT_SIGNATURES.len(), 10);
        // Spot check a couple of associated consts line up
        assert_eq!(EVENT_SIGNATURES[0], UserRegistered::SIGNATURE);
        assert_eq!(EVENT_SIGNATURE_HASHES[0], UserRegistered::SIGNATURE_HASH);
    }
}
