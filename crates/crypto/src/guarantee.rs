use alloy::primitives::{Address, U256, keccak256};
use anyhow::{bail, ensure};
use std::{convert::TryInto, str::FromStr, sync::OnceLock};

const GUARANTEE_DOMAIN_TAG: &str = "4MICA_CORE_GUARANTEE_V1";
static GUARANTEE_DOMAIN_SEPARATOR: OnceLock<[u8; 32]> = OnceLock::new();

const WORD_SIZE: usize = 32;
const ADDRESS_SIZE: usize = 20;
const ENCODED_GUARANTEE_LEN: usize = 220;
const LEGACY_LEN_U64_TIMESTAMP: usize = 176;
const LEGACY_LEN_U256_TIMESTAMP: usize = 200;
const TIMESTAMP_SIZE: usize = std::mem::size_of::<u64>();

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum EncodingFormat {
    LegacyU64Timestamp,
    LegacyU256Timestamp,
    Current,
}

impl EncodingFormat {
    fn from_len(len: usize) -> anyhow::Result<Self> {
        match len {
            LEGACY_LEN_U64_TIMESTAMP => Ok(Self::LegacyU64Timestamp),
            LEGACY_LEN_U256_TIMESTAMP => Ok(Self::LegacyU256Timestamp),
            ENCODED_GUARANTEE_LEN => Ok(Self::Current),
            _ => bail!(
                "decode_guarantee_bytes(): wrong length (expected {}, {}, or {}, got {})",
                LEGACY_LEN_U64_TIMESTAMP,
                LEGACY_LEN_U256_TIMESTAMP,
                ENCODED_GUARANTEE_LEN,
                len
            ),
        }
    }
}

pub fn guarantee_domain_separator() -> anyhow::Result<[u8; 32]> {
    GUARANTEE_DOMAIN_SEPARATOR
        .get()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("guarantee domain separator not initialized"))
}

pub fn set_guarantee_domain_separator(domain: [u8; 32]) -> anyhow::Result<()> {
    match GUARANTEE_DOMAIN_SEPARATOR.set(domain) {
        Ok(()) => Ok(()),
        Err(_) => {
            let current = guarantee_domain_separator()?;
            if current == domain {
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
    const STRING_HEAD_OFFSET: usize = WORD_SIZE * 3;

    fn align_to_word(len: usize) -> usize {
        let remainder = len % WORD_SIZE;
        len + ((WORD_SIZE - remainder) % WORD_SIZE)
    }

    fn push_u256(buf: &mut Vec<u8>, value: U256) {
        buf.extend_from_slice(&value.to_be_bytes::<WORD_SIZE>());
    }

    let tag_bytes = GUARANTEE_DOMAIN_TAG.as_bytes();
    let padded_len = align_to_word(tag_bytes.len());

    let mut encoded = Vec::with_capacity(WORD_SIZE * 4 + padded_len);

    // slot 0: offset to string data (3 * 32 = 96)
    push_u256(&mut encoded, U256::from(STRING_HEAD_OFFSET));

    // slot 1: chain id
    push_u256(&mut encoded, U256::from(chain_id));

    // slot 2: contract address, left-padded
    let mut addr_bytes = [0u8; WORD_SIZE];
    addr_bytes[WORD_SIZE - ADDRESS_SIZE..].copy_from_slice(contract.as_slice());
    encoded.extend_from_slice(&addr_bytes);

    // slot 3: string length
    let mut len_bytes = [0u8; WORD_SIZE];
    len_bytes[WORD_SIZE - 8..].copy_from_slice(&(tag_bytes.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&len_bytes);

    // dynamic tail: tag data padded to 32 bytes
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

fn push_timestamp_as_u256(buf: &mut Vec<u8>, tab_timestamp: u64) {
    let mut ts = [0u8; WORD_SIZE];
    ts[WORD_SIZE - TIMESTAMP_SIZE..].copy_from_slice(&tab_timestamp.to_be_bytes());
    buf.extend_from_slice(&ts);
}

/// Mirrors Solidity:
/// abi.encodePacked(tab_id, req_id, client, recipient, amount, uint256(tab_timestamp))
pub fn encode_guarantee_bytes(
    tab_id: U256,
    req_id: U256,
    client: &str,
    recipient: &str,
    amount: U256,
    asset: &str,
    tab_timestamp: u64,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(ENCODED_GUARANTEE_LEN);

    let addr_client = Address::from_str(client)?;
    let addr_recipient = Address::from_str(recipient)?;
    let addr_asset = Address::from_str(asset)?;

    let domain = guarantee_domain_separator()?;
    out.extend_from_slice(&domain);

    // uint256 fields (big-endian 32 bytes)
    out.extend_from_slice(&tab_id.to_be_bytes::<WORD_SIZE>());
    out.extend_from_slice(&req_id.to_be_bytes::<WORD_SIZE>());

    // address fields (20 bytes)
    out.extend_from_slice(addr_client.as_slice());
    out.extend_from_slice(addr_recipient.as_slice());

    // uint256 amount (32 bytes)
    out.extend_from_slice(&amount.to_be_bytes::<WORD_SIZE>());

    // asset address (20 bytes)
    out.extend_from_slice(addr_asset.as_slice());

    // uint256 timestamp (32 bytes, big-endian)
    push_timestamp_as_u256(&mut out, tab_timestamp);

    ensure!(
        out.len() == ENCODED_GUARANTEE_LEN,
        "encode_guarantee_bytes(): wrong length (expected {}, got {})",
        ENCODED_GUARANTEE_LEN,
        out.len()
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
    Address,  // asset
    u64,      // tab_timestamp
);

struct Decoder<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, len: usize) -> anyhow::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("decode_guarantee_bytes(): overflow reading input"))?;
        ensure!(
            end <= self.data.len(),
            "decode_guarantee_bytes(): truncated payload"
        );
        let slice = &self.data[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> anyhow::Result<[u8; N]> {
        let slice = self.take(N)?;
        let mut buf = [0u8; N];
        buf.copy_from_slice(slice);
        Ok(buf)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.data.len()
    }
}

pub fn decode_guarantee_bytes(data: &[u8]) -> anyhow::Result<DecodedGuarantee> {
    let encoding = EncodingFormat::from_len(data.len())?;
    let mut decoder = Decoder::new(data);

    let domain = decoder.take_array::<WORD_SIZE>()?;
    let tab_id = U256::from_be_slice(decoder.take(WORD_SIZE)?);
    let req_id = U256::from_be_slice(decoder.take(WORD_SIZE)?);
    let client = Address::from_slice(decoder.take(ADDRESS_SIZE)?);
    let recipient = Address::from_slice(decoder.take(ADDRESS_SIZE)?);
    let amount = U256::from_be_slice(decoder.take(WORD_SIZE)?);

    let asset = match encoding {
        EncodingFormat::Current => Address::from_slice(decoder.take(ADDRESS_SIZE)?),
        EncodingFormat::LegacyU64Timestamp | EncodingFormat::LegacyU256Timestamp => Address::ZERO,
    };

    let tab_timestamp = match encoding {
        EncodingFormat::LegacyU64Timestamp => {
            let raw = decoder.take_array::<TIMESTAMP_SIZE>()?;
            u64::from_be_bytes(raw)
        }
        EncodingFormat::LegacyU256Timestamp | EncodingFormat::Current => {
            let raw = decoder.take_array::<WORD_SIZE>()?;
            let tail: [u8; TIMESTAMP_SIZE] = raw[WORD_SIZE - TIMESTAMP_SIZE..].try_into()?;
            u64::from_be_bytes(tail)
        }
    };

    ensure!(
        decoder.is_finished(),
        "decode_guarantee_bytes(): trailing bytes detected"
    );

    Ok((
        domain,
        tab_id,
        req_id,
        client,
        recipient,
        amount,
        asset,
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

    #[test]
    fn encode_decode_round_trip_current_format() {
        let contract = Address::from_str("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512").unwrap();
        init_guarantee_domain_separator(31337, contract).unwrap();

        let tab_id = U256::from(42);
        let req_id = U256::from(7);
        let amount = U256::from(12345);
        let client = "0x0000000000000000000000000000000000000001";
        let recipient = "0x0000000000000000000000000000000000000002";
        let asset = "0x0000000000000000000000000000000000000010";
        let timestamp = 1_700_000_000u64;

        let encoded =
            encode_guarantee_bytes(tab_id, req_id, client, recipient, amount, asset, timestamp)
                .unwrap();

        assert_eq!(encoded.len(), ENCODED_GUARANTEE_LEN);

        let (_, dec_tab, dec_req, dec_client, dec_recipient, dec_amount, dec_asset, dec_ts) =
            decode_guarantee_bytes(&encoded).unwrap();
        assert_eq!(dec_tab, tab_id);
        assert_eq!(dec_req, req_id);
        assert_eq!(dec_client, Address::from_str(client).unwrap());
        assert_eq!(dec_recipient, Address::from_str(recipient).unwrap());
        assert_eq!(dec_amount, amount);
        assert_eq!(dec_asset, Address::from_str(asset).unwrap());
        assert_eq!(dec_ts, timestamp);
    }

    #[test]
    fn decode_legacy_formats() {
        let contract = Address::from_str("0xe7f1725e7734ce288f8367e1bb143e90bb3f0512").unwrap();
        init_guarantee_domain_separator(31337, contract).unwrap();
        let domain = guarantee_domain_separator().unwrap();
        let tab_id = U256::from(1u64).to_be_bytes::<WORD_SIZE>();
        let req_id = U256::from(2u64).to_be_bytes::<WORD_SIZE>();
        let amount = U256::from(3u64).to_be_bytes::<WORD_SIZE>();
        let client = Address::from_str("0x0000000000000000000000000000000000000003").unwrap();
        let recipient = Address::from_str("0x0000000000000000000000000000000000000004").unwrap();
        let timestamp = 99u64.to_be_bytes();

        // Legacy payload with 8-byte timestamp.
        let mut legacy_short = Vec::with_capacity(LEGACY_LEN_U64_TIMESTAMP);
        legacy_short.extend_from_slice(&domain);
        legacy_short.extend_from_slice(&tab_id);
        legacy_short.extend_from_slice(&req_id);
        legacy_short.extend_from_slice(client.as_slice());
        legacy_short.extend_from_slice(recipient.as_slice());
        legacy_short.extend_from_slice(&amount);
        legacy_short.extend_from_slice(&timestamp);
        assert_eq!(legacy_short.len(), LEGACY_LEN_U64_TIMESTAMP);

        let (_, _, _, _, _, _, asset_short, ts_short) =
            decode_guarantee_bytes(&legacy_short).unwrap();
        assert_eq!(asset_short, Address::ZERO);
        assert_eq!(ts_short, 99u64);

        // Legacy payload with 32-byte timestamp and implicit asset.
        let mut legacy_full = legacy_short[..legacy_short.len() - TIMESTAMP_SIZE].to_vec();
        let mut ts_word = [0u8; WORD_SIZE];
        ts_word[WORD_SIZE - TIMESTAMP_SIZE..].copy_from_slice(&timestamp);
        legacy_full.extend_from_slice(&ts_word);
        assert_eq!(legacy_full.len(), LEGACY_LEN_U256_TIMESTAMP);

        let (_, _, _, _, _, _, asset_full, ts_full) = decode_guarantee_bytes(&legacy_full).unwrap();
        assert_eq!(asset_full, Address::ZERO);
        assert_eq!(ts_full, 99u64);
    }
}
