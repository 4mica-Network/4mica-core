//! contract.rs — ABI event + function bindings for the Core4Mica contract
//!
//! This module provides:
//! - Strongly typed event definitions for on-chain log decoding (used by EthereumEventScanner)
//! - Strongly typed contract function bindings for RPC calls (used for sending txs)
//!

#![allow(dead_code)]

use alloy::sol_types::SolEvent;
use alloy_primitives::B256;

// -----------------------------------------------------------------------------
// Event bindings
// -----------------------------------------------------------------------------

pub mod abi {
    use alloy::sol;
    sol! {
        #[derive(Debug)]
        event CollateralDeposited(address indexed user, address indexed asset, uint256 amount);

        #[derive(Debug)]
        event RecipientRemunerated(uint256 indexed tab_id, address indexed asset, uint256 amount);

        #[derive(Debug)]
        event CollateralWithdrawn(address indexed user, address indexed asset, uint256 amount);

        #[derive(Debug)]
        event WithdrawalRequested(address indexed user, address indexed asset, uint256 when, uint256 amount);

        #[derive(Debug)]
        event WithdrawalCanceled(address indexed user, address indexed asset);

        #[derive(Debug)]
        event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);

        #[derive(Debug)]
        event RemunerationGracePeriodUpdated(uint256 newGracePeriod);

        #[derive(Debug)]
        event TabExpirationTimeUpdated(uint256 newExpirationTime);

        #[derive(Debug)]
        event SynchronizationDelayUpdated(uint256 newSynchronizationDelay);

        #[derive(Debug)]
        event VerificationKeyUpdated((bytes32,bytes32,bytes32,bytes32) newVerificationKey);

        #[derive(Debug)]
        event PaymentRecorded(uint256 indexed tab_id, address indexed asset, uint256 amount);

        #[derive(Debug)]
        event TabPaid(
            uint256 indexed tab_id,
            address indexed asset,
            address indexed user,
            address recipient,
            uint256 amount
        );

        #[derive(Debug)]
        event GuaranteeVersionUpdated(
            uint64 indexed version,
            (bytes32,bytes32,bytes32,bytes32) verificationKey,
            bytes32 domainSeparator,
            address decoder,
            bool enabled
        );
    }
}

// Re-export events at the file root for convenient `use crate::ethereum::contract::*;`
pub use abi::{
    CollateralDeposited, CollateralWithdrawn, GuaranteeVersionUpdated, PaymentRecorded,
    RecipientRemunerated, RemunerationGracePeriodUpdated, SynchronizationDelayUpdated,
    TabExpirationTimeUpdated, TabPaid, VerificationKeyUpdated, WithdrawalCanceled,
    WithdrawalGracePeriodUpdated, WithdrawalRequested,
};

/// Human-readable ABI signatures for all contract events.
pub const EVENT_SIGNATURES: [&str; 13] = [
    CollateralDeposited::SIGNATURE,
    RecipientRemunerated::SIGNATURE,
    CollateralWithdrawn::SIGNATURE,
    WithdrawalRequested::SIGNATURE,
    WithdrawalCanceled::SIGNATURE,
    WithdrawalGracePeriodUpdated::SIGNATURE,
    RemunerationGracePeriodUpdated::SIGNATURE,
    TabExpirationTimeUpdated::SIGNATURE,
    SynchronizationDelayUpdated::SIGNATURE,
    VerificationKeyUpdated::SIGNATURE,
    PaymentRecorded::SIGNATURE,
    TabPaid::SIGNATURE,
    GuaranteeVersionUpdated::SIGNATURE,
];

/// Keccak256 topic0 hashes for the above events (as `B256`).
pub const EVENT_SIGNATURE_HASHES: [B256; 13] = [
    CollateralDeposited::SIGNATURE_HASH,
    RecipientRemunerated::SIGNATURE_HASH,
    CollateralWithdrawn::SIGNATURE_HASH,
    WithdrawalRequested::SIGNATURE_HASH,
    WithdrawalCanceled::SIGNATURE_HASH,
    WithdrawalGracePeriodUpdated::SIGNATURE_HASH,
    RemunerationGracePeriodUpdated::SIGNATURE_HASH,
    TabExpirationTimeUpdated::SIGNATURE_HASH,
    SynchronizationDelayUpdated::SIGNATURE_HASH,
    VerificationKeyUpdated::SIGNATURE_HASH,
    PaymentRecorded::SIGNATURE_HASH,
    TabPaid::SIGNATURE_HASH,
    GuaranteeVersionUpdated::SIGNATURE_HASH,
];

/// Convenience: return all event names as a Vec.
pub fn all_event_signatures() -> Vec<&'static str> {
    EVENT_SIGNATURES.to_vec()
}

/// Convenience: return all topic0 hashes as a Vec.
pub fn all_event_topics() -> Vec<B256> {
    EVENT_SIGNATURE_HASHES.to_vec()
}

/// Utility: check if a given topic0 matches any known event.
pub fn is_known_event_topic(topic0: &B256) -> bool {
    EVENT_SIGNATURE_HASHES.iter().any(|t| t == topic0)
}

// -----------------------------------------------------------------------------
// Contract function bindings (for sending txs)
// -----------------------------------------------------------------------------

pub mod contract_abi {
    use alloy::sol;
    sol! {
        struct G1Point {
            bytes32 x_a;
            bytes32 x_b;
            bytes32 y_a;
            bytes32 y_b;
        }

        #[sol(rpc)]
        contract Core4Mica {
            /// Records a successful off-chain payment for a given tab.
            /// Only callable by an AccessManager-restricted operator.
            function recordPayment(
                uint256 tab_id,
                address asset,
                uint256 amount
            ) external restricted supportedAsset(asset) nonZero(amount) nonReentrant;

            function getGuaranteeVersionConfig(
                uint64 version
            )
                external
                view
                returns (
                    G1Point memory verificationKey,
                    bytes32 domainSeparator,
                    address decoder,
                    bool enabled
                );

            function tabExpirationTime() external view returns (uint256);

            /// View: current BLS verification key.
            function GUARANTEE_VERIFICATION_KEY() external view returns (bytes32,bytes32,bytes32,bytes32);

            /// View: list of ERC20 tokens supported by the contract.
            function getERC20Tokens() external view returns (address[] memory);
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_and_hashes_align() {
        assert_eq!(EVENT_SIGNATURES.len(), EVENT_SIGNATURE_HASHES.len());
        assert_eq!(EVENT_SIGNATURES.len(), 13);
        // spot check a couple of associated consts line up
        assert_eq!(EVENT_SIGNATURES[0], CollateralDeposited::SIGNATURE);
        assert_eq!(
            EVENT_SIGNATURE_HASHES[0],
            CollateralDeposited::SIGNATURE_HASH
        );
        assert_eq!(
            EVENT_SIGNATURES[EVENT_SIGNATURES.len() - 1],
            GuaranteeVersionUpdated::SIGNATURE
        );
        assert_eq!(
            EVENT_SIGNATURE_HASHES[EVENT_SIGNATURE_HASHES.len() - 1],
            GuaranteeVersionUpdated::SIGNATURE_HASH
        );
    }
}
