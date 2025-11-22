#![allow(dead_code)]

use anyhow::bail;
use rust_sdk_4mica::{Address, U256, UserInfo, client::recipient::RecipientClient};
use std::time::{Duration, Instant};

pub mod x402;

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

pub async fn wait_for_collateral_increase(
    recipient_client: &RecipientClient,
    user_address: &str,
    asset_address: Address,
    starting_total: U256,
    increase_by: U256,
) -> anyhow::Result<()> {
    let poll_interval = Duration::from_millis(500);
    let timeout = Duration::from_secs(60);
    let start = Instant::now();
    let user_address = user_address.to_string();
    let asset_address = asset_address.to_string();
    let target_total = starting_total + increase_by;
    let mut last_total = starting_total;

    loop {
        if let Some(balance) = recipient_client
            .get_user_asset_balance(user_address.clone(), asset_address.clone())
            .await?
        {
            last_total = balance.total;
            if last_total >= target_total {
                return Ok(());
            }
        }

        if start.elapsed() > timeout {
            bail!(
                "timed out waiting for collateral increase to {target_total:?} for user {user_address}, last observed total {last_total:?}"
            );
        }

        tokio::time::sleep(poll_interval).await;
    }
}
