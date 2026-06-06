use super::constants::{SCOPE_PAYMENT_READ, SCOPE_TAB_READ_LEGACY, WALLET_STATUS_ACTIVE, WALLET_STATUS_ALLOWED};
use crate::error::{ServiceError, ServiceResult};
use alloy::primitives::Address;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::str::FromStr;

pub fn generate_token(prefix: &str) -> String {
    let bytes: [u8; 32] = rand::random();
    format!("{prefix}_{}", hex::encode(bytes))
}

pub fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn parse_rfc3339_date(label: &str, raw: &str) -> ServiceResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_| ServiceError::InvalidParams(format!("invalid {label} timestamp")))
}

/// Map legacy scope names to their current equivalents.
///
/// `tab:read` was renamed to `payment:read` when tabs were removed; existing
/// wallet rows and unexpired tokens may still carry the old name.
pub fn normalize_legacy_scope(scope: &str) -> &str {
    if scope.trim().eq_ignore_ascii_case(SCOPE_TAB_READ_LEGACY) {
        SCOPE_PAYMENT_READ
    } else {
        scope
    }
}

pub fn parse_wallet_scopes(address: &str, value: serde_json::Value) -> ServiceResult<Vec<String>> {
    let scopes: Vec<String> = serde_json::from_value(value)
        .map_err(|e| ServiceError::Other(anyhow!("invalid scopes for wallet role {address}: {e}")))?;
    Ok(scopes
        .iter()
        .map(|s| normalize_legacy_scope(s).to_string())
        .collect())
}

pub fn parse_wallet_address(raw: &str) -> ServiceResult<Address> {
    Address::from_str(raw.trim())
        .map_err(|_| ServiceError::InvalidParams("invalid wallet address".into()))
}

pub fn normalize_wallet_address(raw: &str) -> ServiceResult<String> {
    let address = parse_wallet_address(raw)?;
    Ok(format!("{address:#x}"))
}

pub fn validate_wallet_status(status: &str) -> ServiceResult<()> {
    let status = status.trim();
    if status.is_empty() {
        return Err(ServiceError::Unauthorized(
            "wallet role status missing".into(),
        ));
    }
    if !WALLET_STATUS_ALLOWED
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(status))
    {
        return Err(ServiceError::Unauthorized(
            "wallet role status invalid".into(),
        ));
    }
    if !status.eq_ignore_ascii_case(WALLET_STATUS_ACTIVE) {
        return Err(ServiceError::Unauthorized("wallet role not active".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{normalize_legacy_scope, normalize_wallet_address};

    #[test]
    fn normalize_wallet_address_returns_lowercase_hex() {
        let normalized = normalize_wallet_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
            .expect("valid address");

        assert_eq!(normalized, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
    }

    #[test]
    fn legacy_tab_read_scope_normalizes_to_payment_read() {
        assert_eq!(normalize_legacy_scope("tab:read"), "payment:read");
        assert_eq!(normalize_legacy_scope("TAB:READ"), "payment:read");
        assert_eq!(normalize_legacy_scope("  tab:read  "), "payment:read");
        assert_eq!(normalize_legacy_scope("payment:read"), "payment:read");
        assert_eq!(normalize_legacy_scope("guarantee:issue"), "guarantee:issue");
    }
}
