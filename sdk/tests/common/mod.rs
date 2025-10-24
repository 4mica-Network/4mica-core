#![allow(dead_code)]

use alloy::primitives::Address;
use std::time::Duration;

use rust_sdk_4mica::UserInfo;

pub const ETH_ASSET_ADDRESS: Address = Address::ZERO;

pub fn get_now() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
}

pub fn extract_asset_info(assets: &[UserInfo], asset_address: Address) -> Option<&UserInfo> {
    assets
        .iter()
        .find(|info| info.asset == asset_address.to_string())
}
