use alloy::primitives::{Address, U256};
use std::str::FromStr;

/// Mirrors Solidity:
/// abi.encodePacked(tab_id, req_id, client, recipient, amount, uint256(tab_timestamp))
pub fn encode_guarantee_bytes(
    tab_id: U256,
    req_id: U256,
    client: &str,
    recipient: &str,
    amount: U256,
    tab_timestamp: u64,
) -> anyhow::Result<Vec<u8>> {
    // 32 + 32 + 20 + 20 + 32 + 32 = 168
    let mut out = Vec::with_capacity(32 + 32 + 20 + 20 + 32 + 32);

    let addr_client = Address::from_str(client)?;
    let addr_recipient = Address::from_str(recipient)?;

    // uint256 fields (big-endian 32 bytes)
    out.extend_from_slice(&tab_id.to_be_bytes::<32>());
    out.extend_from_slice(&req_id.to_be_bytes::<32>());

    // address fields (20 bytes)
    out.extend_from_slice(addr_client.as_slice());
    out.extend_from_slice(addr_recipient.as_slice());

    // uint256 amount (32 bytes)
    out.extend_from_slice(&amount.to_be_bytes::<32>());

    // uint256 timestamp (must be 32 bytes, big-endian)
    let mut ts32 = [0u8; 32];
    ts32[24..].copy_from_slice(&tab_timestamp.to_be_bytes()); // right-most 8 bytes
    out.extend_from_slice(&ts32);

    // Hard length assertion to catch silent mistakes
    debug_assert_eq!(
        out.len(),
        168,
        "encode_guarantee_bytes(): wrong length (expected 168)"
    );
    assert_eq!(
        out.len(),
        168,
        "encode_guarantee_bytes(): wrong length (expected 168)"
    );
    // Optional sanity in debug: verify the last 32 bytes match ts32
    #[cfg(debug_assertions)]
    {
        let tail = &out[out.len() - 32..];
        assert_eq!(
            tail, &ts32,
            "Timestamp tail != expected 32-byte padded timestamp"
        );
        // Uncomment if you want to see it
        // eprintln!("packed msg: {}", hex::encode(&out));
    }

    Ok(out)
}
