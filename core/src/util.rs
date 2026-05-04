use alloy_primitives::U256;
use chrono::Utc;
use crypto::hex::DecodeHexError;

pub fn u256_to_string(val: U256) -> String {
    format!("{:#x}", val)
}

pub fn now_naive() -> chrono::NaiveDateTime {
    Utc::now().naive_utc()
}

pub fn normalize_and_decode_hex(value: &str) -> Result<Vec<u8>, DecodeHexError> {
    let normalized = if value.starts_with("0x") {
        value
    } else {
        &format!("0x{}", value)
    };

    let decoded = crypto::hex::decode_hex(normalized)?;
    Ok(decoded)
}
