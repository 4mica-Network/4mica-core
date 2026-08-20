use alloy::primitives::{Address, B256, U256};
use rpc::{AssetBalanceInfo as RpcAssetBalanceInfo, UserTransactionInfo as RpcUserTransactionInfo};

use crate::contract::Core4Mica;

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub asset: String,
    pub collateral: U256,
    pub withdrawal_request_amount: U256,
    pub withdrawal_request_timestamp: u64,
}

impl From<Core4Mica::UserAssetInfo> for UserInfo {
    fn from(value: Core4Mica::UserAssetInfo) -> Self {
        Self {
            asset: value.asset.to_string(),
            collateral: value.collateral,
            withdrawal_request_amount: value.withdrawalRequestAmount,
            withdrawal_request_timestamp: value.withdrawalRequestTimestamp.to(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StablecoinPosition {
    pub asset: String,
    pub principal: U256,
    pub guarantee_capacity: U256,
    pub gross_yield: U256,
    pub protocol_yield_share: U256,
    pub user_net_yield: U256,
    pub withdrawable_balance: U256,
    pub total_user_scaled_balance: U256,
    pub protocol_scaled_balance: U256,
    pub surplus_scaled_balance: U256,
    pub contract_scaled_a_token_balance: U256,
    pub stablecoin_a_token: String,
}

#[derive(Debug, Clone)]
pub struct AssetBalanceInfo {
    pub user_address: String,
    pub asset_address: String,
    pub total: U256,
    pub locked: U256,
    pub version: i32,
    pub updated_at: i64,
}

impl From<RpcAssetBalanceInfo> for AssetBalanceInfo {
    fn from(value: RpcAssetBalanceInfo) -> Self {
        Self {
            user_address: value.user_address,
            asset_address: value.asset_address,
            total: value.total,
            locked: value.locked,
            version: value.version,
            updated_at: value.updated_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecipientPaymentInfo {
    pub user_address: String,
    pub recipient_address: String,
    pub tx_hash: String,
    pub amount: U256,
    pub verified: bool,
    pub finalized: bool,
    pub failed: bool,
    pub created_at: i64,
}

impl From<RpcUserTransactionInfo> for RecipientPaymentInfo {
    fn from(value: RpcUserTransactionInfo) -> Self {
        Self {
            user_address: value.user_address,
            recipient_address: value.recipient_address,
            tx_hash: value.tx_hash,
            amount: value.amount,
            verified: value.verified,
            finalized: value.finalized,
            failed: value.failed,
            created_at: value.created_at,
        }
    }
}

/// Which asset an operation moves.
///
/// Native ETH has no gasless *deposit* path — no authorization scheme covers it — so a deposit of
/// it is always self-funded. Withdrawals are unaffected: Core4Mica verifies those signatures
/// itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asset {
    Native,
    Erc20(Address),
}

impl Asset {
    /// How the contract names the asset: the token address, or `Address::ZERO` for ETH.
    pub fn address(self) -> Address {
        match self {
            Self::Erc20(token) => token,
            Self::Native => Address::ZERO,
        }
    }
}

/// How a deposit reached the contract. Carried on [`DepositReceipt`] because "it worked" hides the
/// one thing a caller cares about: whether they paid for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositPath {
    /// EIP-3009 `receiveWithAuthorization`, submitted by the facilitator. One transaction, none of
    /// it the payer's.
    Eip3009,
    /// Permit2, submitted by the facilitator. Gasless only because the payer already approved
    /// Permit2 in some earlier transaction.
    Permit2,
    /// Permit2 with the approval signed rather than transacted, both submitted by the facilitator.
    SponsoredPermit2,
    /// The payer's own transaction, paying their own gas.
    SelfFunded,
}

impl DepositPath {
    /// Whether the payer's own funds paid for the transaction.
    pub fn costs_the_payer_gas(&self) -> bool {
        matches!(self, Self::SelfFunded)
    }
}

/// Outcome of a deposit, whichever route delivered it.
#[derive(Debug, Clone)]
pub struct DepositReceipt {
    pub tx_hash: B256,
    /// Which route delivered the deposit — in particular, whether the payer paid gas.
    pub path: DepositPath,
    /// The account credited — always whoever signed the authorization, never the facilitator.
    pub from: Address,
    pub asset: Address,
    pub amount: U256,
    pub network: Option<String>,
}

/// How a withdrawal step reached the contract.
///
/// Unlike deposits there is one sponsored route rather than three: the contract verifies the
/// signature itself, so nothing depends on what the asset implements — ETH included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawPath {
    /// Signed by the user, submitted and paid for by the facilitator.
    Sponsored,
    /// The user's own transaction, paying their own gas.
    SelfFunded,
}

impl WithdrawPath {
    /// Whether the user's own funds paid for the transaction.
    pub fn costs_the_user_gas(&self) -> bool {
        matches!(self, Self::SelfFunded)
    }
}

/// Outcome of a withdrawal request, cancellation or finalization.
#[derive(Debug, Clone)]
pub struct WithdrawReceipt {
    pub tx_hash: B256,
    /// Which route delivered it — in particular, whether the user paid gas.
    pub path: WithdrawPath,
    /// The account the action applied to — always the signer, never the facilitator.
    pub user: Address,
    /// `Address::ZERO` for ETH.
    pub asset: Address,
    pub network: Option<String>,
}

/// How a net-credit claim reached the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimPath {
    /// Submitted and paid for by the facilitator.
    Sponsored,
    /// The caller's own transaction, paying their own gas.
    SelfFunded,
}

impl ClaimPath {
    /// Whether the caller's own funds paid for the transaction.
    pub fn costs_the_caller_gas(&self) -> bool {
        matches!(self, Self::SelfFunded)
    }
}

/// Outcome of a net-credit claim.
#[derive(Debug, Clone)]
pub struct ClaimReceipt {
    pub tx_hash: B256,
    /// Which route delivered it — in particular, whether the caller paid gas.
    pub path: ClaimPath,
    /// The account the payout went to — fixed by the committed Merkle leaf, never the submitter.
    pub creditor: Address,
    pub network: Option<String>,
}

/// How a net-debit payment reached the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayPath {
    /// Submitted and paid for by the facilitator.
    Sponsored,
    /// The caller's own transaction, paying their own gas.
    SelfFunded,
}

impl PayPath {
    /// Whether the caller's own funds paid for the transaction (the debit itself always comes out
    /// of the debtor's wallet, whichever route ran).
    pub fn costs_the_caller_gas(&self) -> bool {
        matches!(self, Self::SelfFunded)
    }
}

/// Outcome of a net-debit payment.
#[derive(Debug, Clone)]
pub struct PayReceipt {
    pub tx_hash: B256,
    /// Which route delivered it — in particular, whether the caller paid gas.
    pub path: PayPath,
    /// The account whose funds paid the debit — always the signer, never the submitter.
    pub debtor: Address,
    pub network: Option<String>,
}
