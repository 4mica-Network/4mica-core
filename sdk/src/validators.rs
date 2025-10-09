use std::str::FromStr;

use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use url::Url;

pub fn validate_url(url: &str) -> anyhow::Result<Url> {
    Url::parse(url).map_err(|e| anyhow::anyhow!("invalid URL: {}", e))
}

pub fn validate_address(address: &str) -> anyhow::Result<Address> {
    Address::from_str(address).map_err(|e| anyhow::anyhow!("invalid address: {}", e))
}

pub fn validate_wallet_private_key(key: &str) -> anyhow::Result<PrivateKeySigner> {
    PrivateKeySigner::from_str(key).map_err(|e| anyhow::anyhow!("invalid private key: {}", e))
}
