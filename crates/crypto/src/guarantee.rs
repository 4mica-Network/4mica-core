use alloy::primitives::{Address, U256, keccak256};
use std::{convert::TryInto, str::FromStr, sync::OnceLock};

const GUARANTEE_DOMAIN_TAG: &str = "4MICA_CORE_GUARANTEE_V1";
static GUARANTEE_DOMAIN_SEPARATOR: OnceLock<[u8; 32]> = OnceLock::new();

fn ensure_domain_separator() -> anyhow::Result<[u8; 32]> {
    GUARANTEE_DOMAIN_SEPARATOR
        .get()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("guarantee domain separator not initialized"))
}

pub fn guarantee_domain_separator() -> anyhow::Result<[u8; 32]> {
    ensure_domain_separator()
}

pub fn set_guarantee_domain_separator(domain: [u8; 32]) -> anyhow::Result<()> {
    match GUARANTEE_DOMAIN_SEPARATOR.set(domain) {
        Ok(()) => Ok(()),
        Err(_) => {
            if GUARANTEE_DOMAIN_SEPARATOR
                .get()
                .map(|existing| existing == &domain)
                .unwrap_or(false)
            {
                Ok(())
            } else {
                anyhow::bail!("guarantee domain separator already set to a different value");
            }
        }
    }
}

pub fn compute_guarantee_domain_separator(
    chain_id: u64,
    contract: Address,
) -> anyhow::Result<[u8; 32]> {
    let mut encoded = Vec::with_capacity(32 * 4); // head + string data

    // slot 0: offset to string data (3 * 32 = 96)
    encoded.extend_from_slice(&U256::from(96).to_be_bytes::<32>());

    // slot 1: chain id
    encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());

    // slot 2: contract address, left-padded
    let mut addr_bytes = [0u8; 32];
    addr_bytes[12..].copy_from_slice(contract.as_slice());
    encoded.extend_from_slice(&addr_bytes);

    // dynamic tail: string length and data
    let tag_bytes = GUARANTEE_DOMAIN_TAG.as_bytes();
    let mut len_bytes = [0u8; 32];
    len_bytes[24..].copy_from_slice(&(tag_bytes.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&len_bytes);

    let padded_len = tag_bytes.len().div_ceil(32) * 32;
    let mut tag_padded = vec![0u8; padded_len];
    tag_padded[..tag_bytes.len()].copy_from_slice(tag_bytes);
    encoded.extend_from_slice(&tag_padded);

    Ok(keccak256(encoded).into())
}

pub fn init_guarantee_domain_separator(
    chain_id: u64,
    contract: Address,
) -> anyhow::Result<[u8; 32]> {
    let domain = compute_guarantee_domain_separator(chain_id, contract)?;
    set_guarantee_domain_separator(domain)?;
    Ok(domain)
}

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
    // 32 (domain) + 32 + 32 + 20 + 20 + 32 + 32 = 200
    let mut out = Vec::with_capacity(32 + 32 + 32 + 20 + 20 + 32 + 32);

    let addr_client = Address::from_str(client)?;
    let addr_recipient = Address::from_str(recipient)?;

    let domain = ensure_domain_separator()?;
    out.extend_from_slice(&domain);

    // uint256 fields (big-endian 32 bytes)
    out.extend_from_slice(&tab_id.to_be_bytes::<32>());
    out.extend_from_slice(&req_id.to_be_bytes::<32>());

    // address fields (20 bytes)
    out.extend_from_slice(addr_client.as_slice());
    out.extend_from_slice(addr_recipient.as_slice());

    // uint256 amount (32 bytes)
    out.extend_from_slice(&amount.to_be_bytes::<32>());

    // uint256 timestamp (32 bytes, big-endian)
    let mut ts32 = [0u8; 32];
    ts32[24..].copy_from_slice(&tab_timestamp.to_be_bytes());
    out.extend_from_slice(&ts32);

    // Hard length assertion to catch silent mistakes
    debug_assert_eq!(
        out.len(),
        200,
        "encode_guarantee_bytes(): wrong length (expected 200)"
    );
    assert_eq!(
        out.len(),
        200,
        "encode_guarantee_bytes(): wrong length (expected 200)"
    );

    Ok(out)
}

type DecodedGuarantee = (
    [u8; 32], // domain separator
    U256,     // tab_id
    U256,     // req_id
    Address,  // client
    Address,  // recipient
    U256,     // amount
    u64,      // tab_timestamp
);

pub fn decode_guarantee_bytes(data: &[u8]) -> anyhow::Result<DecodedGuarantee> {
    if data.len() != 176 && data.len() != 200 {
        anyhow::bail!(
            "decode_guarantee_bytes(): wrong length (expected 176 or 200, got {})",
            data.len()
        );
    }

    // Offsets
    let mut offset = 0;

    // domain (32 bytes)
    let mut domain = [0u8; 32];
    domain.copy_from_slice(&data[offset..offset + 32]);
    offset += 32;

    let take_timestamp_as_u256 = data.len() == 200;

    // tab_id (32 bytes)
    let tab_id = U256::from_be_slice(&data[offset..offset + 32]);
    offset += 32;

    // req_id (32 bytes)
    let req_id = U256::from_be_slice(&data[offset..offset + 32]);
    offset += 32;

    // client (20 bytes)
    let client = Address::from_slice(&data[offset..offset + 20]);
    offset += 20;

    // recipient (20 bytes)
    let recipient = Address::from_slice(&data[offset..offset + 20]);
    offset += 20;

    // amount (32 bytes)
    let amount = U256::from_be_slice(&data[offset..offset + 32]);
    offset += 32;

    // timestamp
    let tab_timestamp = if take_timestamp_as_u256 {
        let ts_slice = &data[offset + 24..offset + 32];
        u64::from_be_bytes(ts_slice.try_into()?)
    } else {
        let ts_slice = &data[offset..offset + 8];
        u64::from_be_bytes(ts_slice.try_into()?)
    };

    Ok((
        domain,
        tab_id,
        req_id,
        client,
        recipient,
        amount,
        tab_timestamp,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn domain_separator_matches_contract_logic() {
        let addr = Address::from_str("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512").unwrap();
        let domain = compute_guarantee_domain_separator(31337, addr).unwrap();
        assert_eq!(
            hex::encode(domain),
            "e4f5b272986961cff4544562b3901c6366b50ae7d8ef498db47bbedaf402e0ac"
        );
    }
}
