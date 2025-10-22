use alloy::primitives::U256;

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
