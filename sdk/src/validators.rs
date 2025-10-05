use std::str::FromStr;

use crate::error::ValidationError;
use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use url::Url;

pub fn validate_url(url: &str) -> Result<Url, ValidationError> {
    Url::parse(url).map_err(|e| ValidationError::InvalidUrl(e.to_string()))
}

pub fn validate_address(address: &str) -> Result<Address, ValidationError> {
    Address::from_str(address).map_err(|e| ValidationError::InvalidAddress(e.to_string()))
}

pub fn validate_wallet_private_key(key: &str) -> Result<PrivateKeySigner, ValidationError> {
    PrivateKeySigner::from_str(key).map_err(|e| ValidationError::InvalidPrivateKey(e.to_string()))
}
