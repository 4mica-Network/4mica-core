use alloy_primitives::U256;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Create a unique tab id by hashing the user address, recipient address,
/// ttl and a random UUID with SHA-256.
pub fn generate_tab_id(user: &str, recipient: &str, ttl: u64) -> U256 {
    // Random component to avoid collisions
    let random = Uuid::new_v4().to_string();

    // Concatenate all inputs into a single string
    let input = format!("{}:{}:{}:{}", user, recipient, ttl, random);

    // Hash it with SHA256
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();

    // Convert the hash bytes directly into U256
    U256::from_be_bytes(hash.into())
}

pub fn parse_tab_id(raw: &str) -> anyhow::Result<U256> {
    let trimmed = raw.trim();
    let parsed = if let Some(rest) = trimmed.strip_prefix("0x") {
        U256::from_str_radix(rest, 16)
    } else {
        U256::from_str_radix(trimmed, 10)
    };
    parsed.map_err(|err| anyhow::anyhow!("invalid tab id {raw}: {err}"))
}

pub fn u256_to_string(val: U256) -> String {
    format!("{:#x}", val)
}

pub fn now_naive() -> chrono::NaiveDateTime {
    Utc::now().naive_utc()
}
