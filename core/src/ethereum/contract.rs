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
        event CollateralWithdrawn(address indexed user, address indexed asset, uint256 amount);

        #[derive(Debug)]
        event WithdrawalRequested(address indexed user, address indexed asset, uint256 when, uint256 amount);

        #[derive(Debug)]
        event WithdrawalCanceled(address indexed user, address indexed asset);

        #[derive(Debug)]
        event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);

        #[derive(Debug)]
        event VerificationKeyUpdated((bytes32,bytes32,bytes32,bytes32) newVerificationKey);

        #[derive(Debug)]
        event GuaranteeVersionUpdated(
            uint64 indexed version,
            (bytes32,bytes32,bytes32,bytes32) verificationKey,
            bytes32 domainSeparator,
            address decoder,
            bool enabled
        );

        #[derive(Debug)]
        event StablecoinAssetUpdated(address indexed asset, bool enabled);

        #[derive(Debug)]
        event AaveConfigured(address indexed provider, address indexed pool);

        #[derive(Debug)]
        event YieldFeeBpsUpdated(uint256 oldFeeBps, uint256 newFeeBps);

        #[derive(Debug)]
        event ProtocolYieldClaimed(address indexed asset, address indexed to, uint256 amount);

        #[derive(Debug)]
        event SurplusATokensClaimed(address indexed asset, address indexed to, uint256 scaledAmount, uint256 nominalAmount);

        #[derive(Debug)]
        event CycleCommitted(
            bytes32 indexed cycleId,
            address indexed asset,
            bytes32 merkleRoot,
            uint256 totalNetDebit,
            uint256 totalNetCredit,
            uint64 paymentSubmissionDeadline,
            uint64 paymentFinalityDeadline
        );

        #[derive(Debug)]
        event DebtorPaid(bytes32 indexed cycleId, address indexed debtor, uint256 amount);

        #[derive(Debug)]
        event CreditorClaimed(bytes32 indexed cycleId, address indexed creditor, address indexed asset, uint256 amount);

        #[derive(Debug)]
        event DebtorDefaulted(bytes32 indexed cycleId, address indexed debtor, address indexed asset, uint256 amount);

        #[derive(Debug)]
        event CycleFinalized(bytes32 indexed cycleId);

        #[derive(Debug)]
        event SettlementSkipped(bytes32 indexed cycleId, address indexed participant, string reason);
    }
}

// Re-export events at the file root for convenient `use crate::ethereum::contract::*;`
pub use abi::{
    AaveConfigured, CollateralDeposited, CollateralWithdrawn, CreditorClaimed, CycleCommitted,
    CycleFinalized, DebtorDefaulted, DebtorPaid, GuaranteeVersionUpdated, ProtocolYieldClaimed,
    SettlementSkipped, StablecoinAssetUpdated, SurplusATokensClaimed, VerificationKeyUpdated,
    WithdrawalCanceled, WithdrawalGracePeriodUpdated, WithdrawalRequested, YieldFeeBpsUpdated,
};

/// Human-readable ABI signatures for all contract events.
pub const EVENT_SIGNATURES: [&str; 18] = [
    CollateralDeposited::SIGNATURE,
    CollateralWithdrawn::SIGNATURE,
    WithdrawalRequested::SIGNATURE,
    WithdrawalCanceled::SIGNATURE,
    WithdrawalGracePeriodUpdated::SIGNATURE,
    VerificationKeyUpdated::SIGNATURE,
    GuaranteeVersionUpdated::SIGNATURE,
    StablecoinAssetUpdated::SIGNATURE,
    AaveConfigured::SIGNATURE,
    YieldFeeBpsUpdated::SIGNATURE,
    ProtocolYieldClaimed::SIGNATURE,
    SurplusATokensClaimed::SIGNATURE,
    CycleCommitted::SIGNATURE,
    DebtorPaid::SIGNATURE,
    CreditorClaimed::SIGNATURE,
    DebtorDefaulted::SIGNATURE,
    CycleFinalized::SIGNATURE,
    SettlementSkipped::SIGNATURE,
];

/// Keccak256 topic0 hashes for the above events (as `B256`).
pub const EVENT_SIGNATURE_HASHES: [B256; 18] = [
    CollateralDeposited::SIGNATURE_HASH,
    CollateralWithdrawn::SIGNATURE_HASH,
    WithdrawalRequested::SIGNATURE_HASH,
    WithdrawalCanceled::SIGNATURE_HASH,
    WithdrawalGracePeriodUpdated::SIGNATURE_HASH,
    VerificationKeyUpdated::SIGNATURE_HASH,
    GuaranteeVersionUpdated::SIGNATURE_HASH,
    StablecoinAssetUpdated::SIGNATURE_HASH,
    AaveConfigured::SIGNATURE_HASH,
    YieldFeeBpsUpdated::SIGNATURE_HASH,
    ProtocolYieldClaimed::SIGNATURE_HASH,
    SurplusATokensClaimed::SIGNATURE_HASH,
    CycleCommitted::SIGNATURE_HASH,
    DebtorPaid::SIGNATURE_HASH,
    CreditorClaimed::SIGNATURE_HASH,
    DebtorDefaulted::SIGNATURE_HASH,
    CycleFinalized::SIGNATURE_HASH,
    SettlementSkipped::SIGNATURE_HASH,
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
// Contract function bindings
// -----------------------------------------------------------------------------
//
// This is an intentionally curated subset of the Core4Mica callable ABI used by
// core-service. It is not a full mirror of every public/external Solidity
// function in `contracts/src/Core4Mica.sol`.

pub mod contract_abi {
    #![allow(clippy::too_many_arguments)]

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

            /// View: delayed-withdrawal grace period (seconds).
            function withdrawalGracePeriod() external view returns (uint256);

            /// View: current BLS verification key.
            function GUARANTEE_VERIFICATION_KEY() external view returns (bytes32,bytes32,bytes32,bytes32);

            /// View: list of ERC20 tokens supported by the contract.
            function getERC20Tokens() external view returns (address[] memory);

            /// View: cached aToken for a configured stablecoin asset.
            function stablecoinAToken(address asset) external view returns (address);

            /// View: guaranteeable collateral for a user/asset pair.
            function guaranteeCapacity(address user, address asset) external view returns (uint256);

            // ---- Custom errors (mirrored from contracts/src/Core4Mica.sol) ----
            // Declared here only so revert data can be decoded into named errors.
            error AmountZero();
            error InsufficientAvailable();
            error TransferFailed();
            error GracePeriodNotElapsed();
            error NoWithdrawalRequested();
            error DirectTransferNotAllowed();
            error InvalidSignature();
            error InvalidRecipient();
            error UnsupportedAsset(address asset);
            error InvalidAsset(address asset);
            error UnsupportedGuaranteeVersion(uint64 version);
            error InvalidGuaranteeDomain();
            error MissingGuaranteeDecoder(uint64 version);
            error AaveNotConfigured();
            error FeeTooHigh();
            error TreasuryClaimExceedsAvailable();
            error UnsupportedTreasuryAsset(address asset);
            error StablecoinWithdrawShortfall(address asset, uint256 requested, uint256 actual);
            error AaveProviderReconfigurationBlocked();
            error UserScaledBalanceUnderflow(address asset, address user, uint256 deduction, uint256 balance);
            error ZeroAddress();
            error InvalidAToken(address asset, address aToken);
            error ReconciliationLoss(address asset, uint256 tracked, uint256 observed);
            error SurplusClaimExceedsAvailable();
            error ValueMismatch(uint256 expected, uint256 actual);
        }

        #[sol(rpc)]
        contract ERC20Metadata {
            function symbol() external view returns (string memory);
            function decimals() external view returns (uint8);
        }

        struct DebtorEntry {
            address debtor;
            uint256 netDebit;
            bytes32[] proof;
        }

        struct CreditorEntry {
            address creditor;
            uint256 netCredit;
            bytes32[] proof;
        }

        struct OnchainCycle {
            address asset;
            bytes32 merkleRoot;
            uint256 totalNetDebit;
            uint256 totalNetCredit;
            uint256 totalPaidIn;
            uint256 totalClaimedOut;
            uint256 totalDefaultCovered;
            uint256 totalResolvedDebit;
            uint64 paymentSubmissionDeadline;
            uint64 paymentFinalityDeadline;
            uint8 status;
            bool exists;
        }

        #[sol(rpc)]
        contract ClearingHouse {
            function commitCycle(
                bytes32 cycleId,
                address asset,
                bytes32 merkleRoot,
                uint256 totalNetDebit,
                uint256 totalNetCredit,
                uint64 paymentSubmissionDeadline,
                uint64 paymentFinalityDeadline
            ) external;

            /// Operator batch: seize collateral for unpaid debtors after finality.
            function settleDefaultsFromCollateralBatch(bytes32 cycleId, DebtorEntry[] entries) external;

            /// Operator batch: fund unclaimed creditors back into their Core4Mica collateral.
            function fundCreditorsFromPoolBatch(bytes32 cycleId, CreditorEntry[] entries) external;

            /// Drive an under-funded cycle to the terminal Shortfall state.
            function markCycleShortfall(bytes32 cycleId) external;

            /// Finalize a fully-resolved cycle.
            function finalizeCycle(bytes32 cycleId) external;

            /// View: full on-chain cycle accounting/state.
            function getCycle(bytes32 cycleId) external view returns (OnchainCycle memory);

            // ---- Custom errors (mirrored from contracts/src/ClearingHouse.sol) ----
            // `CycleStatus` is a Solidity enum; it ABI-encodes (and contributes to the
            // selector) as `uint8`, so it is declared as `uint8` here.
            error AmountZero();
            error CycleNotZeroSum(uint256 totalNetDebit, uint256 totalNetCredit);
            error CycleAlreadyCommitted(bytes32 cycleId);
            error CycleNotFound(bytes32 cycleId);
            error InvalidCycleStatus(bytes32 cycleId, uint8 status);
            error InvalidDeadline();
            error InvalidProof();
            error ExactPaymentRequired(uint256 expected, uint256 actual);
            error AlreadyPaid(bytes32 cycleId, address debtor);
            error AlreadyClaimed(bytes32 cycleId, address creditor);
            error PaymentFinalityPending(uint64 deadline);
            error PaymentWindowElapsed(uint64 deadline);
            error ClaimExceedsFundedLiquidity(uint256 available, uint256 requested);
            error CycleDebtUnresolved(uint256 resolved, uint256 required);
            error CycleUnderfunded(uint256 available, uint256 required);
            error CycleClaimsUnresolved(uint256 claimed, uint256 required);
            error NativeTransferFailed(address recipient, uint256 amount);
            error ZeroAddress();
            error UnauthorizedEthSender(address sender);
            error ClaimConversionShortfall(uint256 requested, uint256 got);
            error CycleFullyFunded(uint256 funded, uint256 required);
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    const EXPECTED_EVENT_SIGNATURES: [&str; 18] = [
        "CollateralDeposited(address,address,uint256)",
        "CollateralWithdrawn(address,address,uint256)",
        "WithdrawalRequested(address,address,uint256,uint256)",
        "WithdrawalCanceled(address,address)",
        "WithdrawalGracePeriodUpdated(uint256)",
        "VerificationKeyUpdated((bytes32,bytes32,bytes32,bytes32))",
        "GuaranteeVersionUpdated(uint64,(bytes32,bytes32,bytes32,bytes32),bytes32,address,bool)",
        "StablecoinAssetUpdated(address,bool)",
        "AaveConfigured(address,address)",
        "YieldFeeBpsUpdated(uint256,uint256)",
        "ProtocolYieldClaimed(address,address,uint256)",
        "SurplusATokensClaimed(address,address,uint256,uint256)",
        "CycleCommitted(bytes32,address,bytes32,uint256,uint256,uint64,uint64)",
        "DebtorPaid(bytes32,address,uint256)",
        "CreditorClaimed(bytes32,address,address,uint256)",
        "DebtorDefaulted(bytes32,address,address,uint256)",
        "CycleFinalized(bytes32)",
        "SettlementSkipped(bytes32,address,string)",
    ];

    #[test]
    fn event_signatures_and_hashes_align() {
        assert_eq!(EVENT_SIGNATURES.len(), EVENT_SIGNATURE_HASHES.len());
        assert_eq!(EVENT_SIGNATURES.len(), EXPECTED_EVENT_SIGNATURES.len());
        assert_eq!(EVENT_SIGNATURES, EXPECTED_EVENT_SIGNATURES);
        assert_eq!(EVENT_SIGNATURES[0], CollateralDeposited::SIGNATURE);
        assert_eq!(
            EVENT_SIGNATURE_HASHES[0],
            CollateralDeposited::SIGNATURE_HASH
        );
        assert_eq!(EVENT_SIGNATURES[6], GuaranteeVersionUpdated::SIGNATURE);
        assert_eq!(
            EVENT_SIGNATURE_HASHES[6],
            GuaranteeVersionUpdated::SIGNATURE_HASH
        );
        assert_eq!(EVENT_SIGNATURES[11], SurplusATokensClaimed::SIGNATURE);
        assert_eq!(
            EVENT_SIGNATURE_HASHES[11],
            SurplusATokensClaimed::SIGNATURE_HASH
        );
        assert_eq!(EVENT_SIGNATURES[12], CycleCommitted::SIGNATURE);
        assert_eq!(EVENT_SIGNATURE_HASHES[16], CycleFinalized::SIGNATURE_HASH);
        assert_eq!(
            EVENT_SIGNATURE_HASHES[17],
            SettlementSkipped::SIGNATURE_HASH
        );
    }
}
