use alloy::primitives::U256;
use rpc::{
    AssetBalanceInfo as RpcAssetBalanceInfo, CollateralEventInfo as RpcCollateralEventInfo,
    GuaranteeInfo as RpcGuaranteeInfo, PendingRemunerationInfo as RpcPendingRemunerationInfo,
    TabInfo as RpcTabInfo, UserTransactionInfo as RpcUserTransactionInfo,
};

use crate::contract::Core4Mica;

#[derive(Debug, Clone)]
pub struct TabPaymentStatus {
    pub paid: U256,
    pub remunerated: bool,
    pub asset: String,
}

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
pub struct TabInfo {
    pub tab_id: U256,
    pub user_address: String,
    pub recipient_address: String,
    pub asset_address: String,
    pub start_timestamp: i64,
    pub ttl_seconds: i64,
    pub status: String,
    pub settlement_status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<RpcTabInfo> for TabInfo {
    fn from(value: RpcTabInfo) -> Self {
        Self {
            tab_id: value.tab_id,
            user_address: value.user_address,
            recipient_address: value.recipient_address,
            asset_address: value.asset_address,
            start_timestamp: value.start_timestamp,
            ttl_seconds: value.ttl_seconds,
            status: value.status,
            settlement_status: value.settlement_status,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GuaranteeInfo {
    pub tab_id: U256,
    pub req_id: U256,
    pub from_address: String,
    pub to_address: String,
    pub asset_address: String,
    pub amount: U256,
    pub timestamp: u64,
    pub certificate: Option<String>,
}

impl From<RpcGuaranteeInfo> for GuaranteeInfo {
    fn from(value: RpcGuaranteeInfo) -> Self {
        Self {
            tab_id: value.tab_id,
            req_id: value.req_id,
            from_address: value.from_address,
            to_address: value.to_address,
            asset_address: value.asset_address,
            amount: value.amount,
            timestamp: value.start_timestamp as u64,
            certificate: value.certificate,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingRemunerationInfo {
    pub tab: TabInfo,
    pub latest_guarantee: Option<GuaranteeInfo>,
}

impl From<RpcPendingRemunerationInfo> for PendingRemunerationInfo {
    fn from(value: RpcPendingRemunerationInfo) -> Self {
        Self {
            tab: value.tab.into(),
            latest_guarantee: value.latest_guarantee.map(Into::into),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CollateralEventInfo {
    pub id: String,
    pub user_address: String,
    pub asset_address: String,
    pub amount: U256,
    pub event_type: String,
    pub tab_id: Option<U256>,
    pub req_id: Option<U256>,
    pub tx_id: Option<String>,
    pub created_at: i64,
}

impl From<RpcCollateralEventInfo> for CollateralEventInfo {
    fn from(value: RpcCollateralEventInfo) -> Self {
        Self {
            id: value.id,
            user_address: value.user_address,
            asset_address: value.asset_address,
            amount: value.amount,
            event_type: value.event_type,
            tab_id: value.tab_id,
            req_id: value.req_id,
            tx_id: value.tx_id,
            created_at: value.created_at,
        }
    }
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
