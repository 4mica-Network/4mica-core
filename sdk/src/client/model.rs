use alloy::primitives::U256;

use crate::contract::Core4Mica;

#[derive(Debug, Clone)]
pub struct TabPaymentStatus {
    pub paid: U256,
    pub remunerated: bool,
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub collateral: U256,
    pub withdrawal_request_amount: U256,
    pub withdrawal_request_timestamp: u64,
}

impl From<Core4Mica::getUserReturn> for UserInfo {
    fn from(value: Core4Mica::getUserReturn) -> Self {
        Self {
            collateral: value._collateral,
            withdrawal_request_amount: value.withdrawal_request_amount,
            withdrawal_request_timestamp: value.withdrawal_request_timestamp.to(),
        }
    }
}
