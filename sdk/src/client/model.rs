use alloy::primitives::{Address, B256, U256};
use rpc::{AssetBalanceInfo as RpcAssetBalanceInfo, UserTransactionInfo as RpcUserTransactionInfo};

use crate::contract::Core4Mica;

/// The signer's standing in one asset, as the contract records it.
#[derive(Debug, Clone)]
pub struct AssetPosition {
    pub asset: Address,
    pub collateral: U256,
    pub withdrawal_request_amount: U256,
    pub withdrawal_request_timestamp: u64,
}

impl From<Core4Mica::UserAssetInfo> for AssetPosition {
    fn from(value: Core4Mica::UserAssetInfo) -> Self {
        Self {
            asset: value.asset,
            collateral: value.collateral,
            withdrawal_request_amount: value.withdrawalRequestAmount,
            withdrawal_request_timestamp: value.withdrawalRequestTimestamp.to(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StablecoinPosition {
    pub asset: Address,
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
    pub stablecoin_a_token: Address,
}

#[derive(Debug, Clone)]
pub struct AssetBalanceInfo {
    pub user: Address,
    pub asset: Address,
    pub total: U256,
    pub locked: U256,
    pub version: i32,
    pub updated_at: i64,
}

impl TryFrom<RpcAssetBalanceInfo> for AssetBalanceInfo {
    type Error = String;

    fn try_from(value: RpcAssetBalanceInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            user: value
                .user_address
                .parse()
                .map_err(|_| format!("invalid user address: {}", value.user_address))?,
            asset: value
                .asset_address
                .parse()
                .map_err(|_| format!("invalid asset address: {}", value.asset_address))?,
            total: value.total,
            locked: value.locked,
            version: value.version,
            updated_at: value.updated_at,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RecipientPaymentInfo {
    pub user: Address,
    pub recipient: Address,
    pub tx_hash: B256,
    pub amount: U256,
    pub verified: bool,
    pub finalized: bool,
    pub failed: bool,
    pub created_at: i64,
}

impl TryFrom<RpcUserTransactionInfo> for RecipientPaymentInfo {
    type Error = String;

    fn try_from(value: RpcUserTransactionInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            user: value
                .user_address
                .parse()
                .map_err(|_| format!("invalid user address: {}", value.user_address))?,
            recipient: value
                .recipient_address
                .parse()
                .map_err(|_| format!("invalid recipient address: {}", value.recipient_address))?,
            tx_hash: value
                .tx_hash
                .parse()
                .map_err(|_| format!("invalid tx hash: {}", value.tx_hash))?,
            amount: value.amount,
            verified: value.verified,
            finalized: value.finalized,
            failed: value.failed,
            created_at: value.created_at,
        })
    }
}

/// Which asset an operation moves.
///
/// Native ETH has no gasless *deposit* route — no authorization scheme covers it — so a deposit of
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

/// How a contract-verified operation (a withdrawal step, a net-credit claim) reached the chain.
///
/// One gasless route rather than several: the contract verifies the signature itself, so nothing
/// depends on what the asset implements — ETH included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Submitted and paid for by the facilitator.
    Gasless,
    /// The caller's own transaction, paying their own gas.
    SelfFunded,
}

impl Route {
    /// Whether someone other than the caller paid for the transaction.
    pub fn is_gasless(&self) -> bool {
        matches!(self, Self::Gasless)
    }
}

/// How a token-moving operation (a deposit, a net-debit payment) reached the chain. Unlike
/// [`Route`], the authorization scheme matters here — it decides which tokens qualify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRoute {
    /// EIP-3009 `receiveWithAuthorization`, submitted by the facilitator. One transaction, none of
    /// it the signer's.
    Eip3009,
    /// Permit2, submitted by the facilitator. Gasless only because the signer already approved
    /// Permit2 in some earlier transaction.
    Permit2,
    /// Permit2 with the approval signed (EIP-2612) rather than transacted, both submitted by the
    /// facilitator.
    SponsoredPermit2,
    /// The signer's own transaction, paying their own gas.
    SelfFunded,
}

impl TokenRoute {
    /// Whether someone other than the signer paid for the transaction.
    pub fn is_gasless(&self) -> bool {
        !matches!(self, Self::SelfFunded)
    }
}

/// Outcome of a deposit, whichever route delivered it.
#[derive(Debug, Clone)]
pub struct DepositReceipt {
    pub tx_hash: B256,
    /// Which route delivered the deposit — in particular, whether the signer paid gas.
    pub route: TokenRoute,
    /// The account credited — always whoever signed the authorization, never the facilitator.
    pub account: Address,
    pub asset: Address,
    pub amount: U256,
    pub network: Option<String>,
}

/// Outcome of a withdrawal request, cancellation or finalization.
#[derive(Debug, Clone)]
pub struct WithdrawReceipt {
    pub tx_hash: B256,
    /// Which route delivered it — in particular, whether the user paid gas.
    pub route: Route,
    /// The account the action applied to — always the signer, never the facilitator.
    pub account: Address,
    /// `Address::ZERO` for ETH.
    pub asset: Address,
    pub network: Option<String>,
}

/// Outcome of a net-credit claim.
#[derive(Debug, Clone)]
pub struct ClaimReceipt {
    pub tx_hash: B256,
    /// Which route delivered it — in particular, whether the caller paid gas.
    pub route: Route,
    /// The account the payout went to — fixed by the committed Merkle leaf, never the submitter.
    pub account: Address,
    pub network: Option<String>,
}

/// Outcome of a net-debit payment.
#[derive(Debug, Clone)]
pub struct PayReceipt {
    pub tx_hash: B256,
    /// Which route delivered it — in particular, whether the caller paid gas. The debit itself
    /// always comes out of the debtor's wallet, whichever route ran.
    pub route: TokenRoute,
    /// The account whose funds paid the debit — always the signer, never the submitter.
    pub account: Address,
    pub network: Option<String>,
}
