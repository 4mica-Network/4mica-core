use crate::error::{ServiceError, ServiceResult};
use alloy::network::TransactionBuilder;
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy_primitives::{Address, B256, Bytes, Signature, eip191_hash_message};
use alloy_sol_types::{SolCall, sol};
use anyhow::anyhow;
use std::str::FromStr;

const SIWE_HEADER_SUFFIX: &str = " wants you to sign in with your Ethereum account:";
const ERC1271_MAGIC_VALUE: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

sol! {
    function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiweMessage {
    pub domain: String,
    pub address: Address,
    pub statement: Option<String>,
    pub uri: String,
    pub version: String,
    pub chain_id: u64,
    pub nonce: String,
    pub issued_at: String,
    pub expiration_time: Option<String>,
    pub not_before: Option<String>,
    pub request_id: Option<String>,
    pub resources: Vec<String>,
}

pub fn parse_siwe_message(raw: &str) -> ServiceResult<SiweMessage> {
    let lines: Vec<&str> = raw.lines().collect();
    if lines.len() < 2 {
        return Err(invalid_siwe("message must include header and address"));
    }

    let header = lines[0].trim();
    if !header.ends_with(SIWE_HEADER_SUFFIX) {
        return Err(invalid_siwe("invalid header line"));
    }
    let domain = header
        .strip_suffix(SIWE_HEADER_SUFFIX)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_siwe("missing domain"))?
        .to_string();

    let address_line = lines[1].trim();
    let address =
        Address::from_str(address_line).map_err(|_| invalid_siwe("invalid address in message"))?;

    let mut index = 2;
    if index < lines.len() && lines[index].trim().is_empty() {
        index += 1;
    }

    let mut statement = None;
    if index < lines.len() {
        let candidate = lines[index].trim();
        if !candidate.is_empty() && !candidate.starts_with("URI:") {
            statement = Some(candidate.to_string());
            index += 1;
            if index < lines.len() && lines[index].trim().is_empty() {
                index += 1;
            }
        }
    }

    let mut uri = None;
    let mut version = None;
    let mut chain_id = None;
    let mut nonce = None;
    let mut issued_at = None;
    let mut expiration_time = None;
    let mut not_before = None;
    let mut request_id = None;
    let mut resources = Vec::new();

    let mut i = index;
    while i < lines.len() {
        let line = lines[i].trim();
        if line.is_empty() {
            i += 1;
            continue;
        }

        if line == "Resources:" {
            i += 1;
            while i < lines.len() {
                let res_line = lines[i].trim();
                if res_line.is_empty() {
                    i += 1;
                    continue;
                }
                if let Some(resource) = res_line.strip_prefix("- ") {
                    resources.push(resource.trim().to_string());
                    i += 1;
                    continue;
                }
                break;
            }
            break;
        }

        if let Some(value) = parse_field(line, "URI:") {
            uri = Some(value.to_string());
            i += 1;
            continue;
        }
        if let Some(value) = parse_field(line, "Version:") {
            version = Some(value.to_string());
            i += 1;
            continue;
        }
        if let Some(value) = parse_field(line, "Chain ID:") {
            chain_id = Some(
                value
                    .parse::<u64>()
                    .map_err(|_| invalid_siwe("invalid chain id"))?,
            );
            i += 1;
            continue;
        }
        if let Some(value) = parse_field(line, "Nonce:") {
            nonce = Some(value.to_string());
            i += 1;
            continue;
        }
        if let Some(value) = parse_field(line, "Issued At:") {
            issued_at = Some(value.to_string());
            i += 1;
            continue;
        }
        if let Some(value) = parse_field(line, "Expiration Time:") {
            expiration_time = Some(value.to_string());
            i += 1;
            continue;
        }
        if let Some(value) = parse_field(line, "Not Before:") {
            not_before = Some(value.to_string());
            i += 1;
            continue;
        }
        if let Some(value) = parse_field(line, "Request ID:") {
            request_id = Some(value.to_string());
            i += 1;
            continue;
        }

        i += 1;
    }

    Ok(SiweMessage {
        domain,
        address,
        statement,
        uri: uri.ok_or_else(|| invalid_siwe("missing uri"))?,
        version: version.ok_or_else(|| invalid_siwe("missing version"))?,
        chain_id: chain_id.ok_or_else(|| invalid_siwe("missing chain id"))?,
        nonce: nonce.ok_or_else(|| invalid_siwe("missing nonce"))?,
        issued_at: issued_at.ok_or_else(|| invalid_siwe("missing issued_at"))?,
        expiration_time,
        not_before,
        request_id,
        resources,
    })
}

pub async fn verify_siwe_message<P: Provider>(
    provider: &P,
    expected_address: &str,
    raw_message: &str,
    signature_hex: &str,
) -> ServiceResult<SiweMessage> {
    let message = parse_siwe_message(raw_message)?;
    let expected = Address::from_str(expected_address)
        .map_err(|_| invalid_siwe("invalid expected address"))?;
    if expected != message.address {
        return Err(invalid_siwe("message address does not match request"));
    }

    let signature_bytes = crypto::hex::decode_hex(signature_hex)
        .map_err(|_| invalid_siwe("invalid signature hex"))?;

    let eoa_verified = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(signature) => {
            let digest = siwe_message_hash(raw_message);
            match signature.recover_address_from_prehash(&digest) {
                Ok(recovered) => recovered == message.address,
                Err(_) => false,
            }
        }
        Err(_) => false,
    };

    if eoa_verified {
        return Ok(message);
    }

    if verify_erc1271_signature(provider, message.address, raw_message, &signature_bytes).await? {
        Ok(message)
    } else {
        Err(invalid_siwe("invalid signature"))
    }
}

fn parse_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key).map(str::trim)
}

fn siwe_message_hash(raw_message: &str) -> B256 {
    eip191_hash_message(raw_message.as_bytes())
}

async fn verify_erc1271_signature<P: Provider>(
    provider: &P,
    address: Address,
    raw_message: &str,
    signature_bytes: &[u8],
) -> ServiceResult<bool> {
    let digest = siwe_message_hash(raw_message);
    let call = isValidSignatureCall {
        hash: digest,
        signature: Bytes::copy_from_slice(signature_bytes),
    };
    let input = Bytes::from(call.abi_encode());
    let tx = TransactionRequest::default()
        .with_to(address)
        .with_input(input);

    let response = provider
        .call(tx)
        .await
        .map_err(|err| ServiceError::Other(anyhow!("erc1271 call failed: {err}")))?;

    Ok(response.len() >= 4 && response.as_ref()[0..4] == ERC1271_MAGIC_VALUE)
}

fn invalid_siwe(msg: &str) -> ServiceError {
    ServiceError::InvalidParams(format!("invalid siwe message: {msg}"))
}
