use alloy::primitives::U256;
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
