use std::str::FromStr;

use alloy::primitives::{Address, FixedBytes, U256};
use rpc::common::PaymentGuaranteeClaims;

use crate::contract::Core4Mica::{G2Point, Guarantee};

impl TryFrom<PaymentGuaranteeClaims> for Guarantee {
    type Error = anyhow::Error;

    fn try_from(claims: PaymentGuaranteeClaims) -> Result<Self, Self::Error> {
        let guarantee = Guarantee {
            tab_id: claims.tab_id,
            tab_timestamp: U256::from(claims.timestamp),
            client: Address::from_str(&claims.user_address)
                .map_err(|e| anyhow::anyhow!("Invalid client address: {}", e))?,
            recipient: Address::from_str(&claims.recipient_address)
                .map_err(|e| anyhow::anyhow!("Invalid recipient address: {}", e))?,
            req_id: claims.req_id,
            amount: claims.amount,
            asset: Address::from_str(&claims.asset_address)
                .map_err(|e| anyhow::anyhow!("Invalid asset address: {}", e))?,
        };
        Ok(guarantee)
    }
}

impl From<[[u8; 32]; 8]> for G2Point {
    fn from(value: [[u8; 32]; 8]) -> Self {
        let [x0_hi, x0_lo, x1_hi, x1_lo, y0_hi, y0_lo, y1_hi, y1_lo] = value;
        G2Point {
            x_c0_a: FixedBytes::from(x0_hi),
            x_c0_b: FixedBytes::from(x0_lo),
            x_c1_a: FixedBytes::from(x1_hi),
            x_c1_b: FixedBytes::from(x1_lo),
            y_c0_a: FixedBytes::from(y0_hi),
            y_c0_b: FixedBytes::from(y0_lo),
            y_c1_a: FixedBytes::from(y1_hi),
            y_c1_b: FixedBytes::from(y1_lo),
        }
    }
}
