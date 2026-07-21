//! ERC-8004 validation registry adapter.
//!
//! Reads the registry over a chain provider, so a verdict stays re-derivable from public state.
//!
//! - **Identity** (`uri`): CAIP-10 account id, `eip155:<chainId>:<registryAddress>`.
//! - **Subject**: the ERC-8004 request hash.
//! - **Params**: `abi.encode(address validator, uint256 agentId, uint8 minScore, string tag)`.
//!   An empty `tag` accepts any tag.

use alloy::providers::DynProvider;
use alloy::sol;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolType, SolValue};
use anyhow::{Context, bail};
use async_trait::async_trait;
use log::warn;
use rpc::ValidationRequirement;
use serde::{Deserialize, Serialize};

use crate::{ValidatorAdapter, Verdict, VerdictStatus, parse_config};

pub const KIND: &str = "erc8004";

sol! {
    #[sol(rpc)]
    contract IValidationRegistry {
        function getValidationStatus(bytes32 requestHash)
            external
            view
            returns (
                address validatorAddress,
                uint256 agentId,
                uint8 response,
                bytes32 responseHash,
                string memory tag,
                uint256 lastUpdate
            );
    }

    struct AcceptancePolicy {
        address validator;
        uint256 agentId;
        uint8 minScore;
        string tag;
    }

    struct ObservedStatus {
        address validatorAddress;
        uint256 agentId;
        uint8 response;
        bytes32 responseHash;
        string tag;
        uint256 lastUpdate;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Erc8004Config {}

pub struct Erc8004Adapter {
    registry: Address,
    chain_id: u64,
    provider: DynProvider,
}

impl Erc8004Adapter {
    pub fn new(
        uri: &str,
        config: &serde_json::Value,
        provider: DynProvider,
    ) -> anyhow::Result<Self> {
        let _config: Erc8004Config = parse_config(KIND, config)?;
        let (chain_id, registry) = parse_caip10(uri)?;
        Ok(Self {
            registry,
            chain_id,
            provider,
        })
    }

    /// The chain this registry lives on.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

#[async_trait]
impl ValidatorAdapter for Erc8004Adapter {
    fn kind(&self) -> &str {
        KIND
    }

    fn validate_requirement(&self, req: &ValidationRequirement) -> anyhow::Result<()> {
        let policy = decode_policy(&req.params)?;
        if !(1..=100).contains(&policy.minScore) {
            bail!(
                "minScore must be between 1 and 100, got {}",
                policy.minScore
            );
        }
        if req.subject.is_zero() {
            bail!("subject must be a non-zero ERC-8004 request hash");
        }
        Ok(())
    }

    async fn resolve(&self, req: &ValidationRequirement) -> anyhow::Result<Verdict> {
        let policy = decode_policy(&req.params)?;
        let observed_at = crate::now_unix();

        let status = match IValidationRegistry::new(self.registry, self.provider.clone())
            .getValidationStatus(req.subject)
            .call()
            .await
        {
            Ok(status) => status,
            Err(err) => {
                warn!(
                    "erc8004: status read failed for registry {} subject {}: {err}",
                    self.registry, req.subject
                );
                return Ok(pending(req.subject, observed_at));
            }
        };

        let evidence = ObservedStatus {
            validatorAddress: status.validatorAddress,
            agentId: status.agentId,
            response: status.response,
            responseHash: status.responseHash,
            tag: status.tag.clone(),
            lastUpdate: status.lastUpdate,
        }
        .abi_encode();

        if status.lastUpdate.is_zero() {
            return Ok(Verdict {
                status: VerdictStatus::Pending,
                subject: req.subject,
                evidence: evidence.into(),
                observed_at,
            });
        }

        let accepted = status.response >= policy.minScore
            && status.validatorAddress == policy.validator
            && status.agentId == policy.agentId
            && (policy.tag.is_empty() || status.tag == policy.tag);

        Ok(Verdict {
            status: if accepted {
                VerdictStatus::Approved
            } else {
                VerdictStatus::Rejected
            },
            subject: req.subject,
            evidence: evidence.into(),
            observed_at,
        })
    }
}

fn pending(subject: B256, observed_at: u64) -> Verdict {
    Verdict {
        status: VerdictStatus::Pending,
        subject,
        evidence: Bytes::new(),
        observed_at,
    }
}

fn decode_policy(params: &Bytes) -> anyhow::Result<AcceptancePolicy> {
    <AcceptancePolicy as SolType>::abi_decode(params).context(
        "erc8004 params must be abi.encode(address validator, uint256 agentId, uint8 minScore, string tag)",
    )
}

/// Encode an acceptance policy into the `params` of a [`ValidationRequirement`].
pub fn encode_policy(validator: Address, agent_id: U256, min_score: u8, tag: &str) -> Bytes {
    AcceptancePolicy {
        validator,
        agentId: agent_id,
        minScore: min_score,
        tag: tag.to_string(),
    }
    .abi_encode()
    .into()
}

fn parse_caip10(uri: &str) -> anyhow::Result<(u64, Address)> {
    let mut parts = uri.split(':');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("eip155"), Some(chain), Some(address), None) => {
            let chain_id: u64 = chain
                .parse()
                .with_context(|| format!("invalid chain id in validator uri '{uri}'"))?;
            let address: Address = address
                .parse()
                .with_context(|| format!("invalid registry address in validator uri '{uri}'"))?;
            Ok((chain_id, address))
        }
        _ => {
            bail!("erc8004 validator uri must be CAIP-10 'eip155:<chainId>:<address>', got '{uri}'")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_caip10_identity() {
        let (chain_id, address) =
            parse_caip10("eip155:8453:0x1111111111111111111111111111111111111111").expect("parse");
        assert_eq!(chain_id, 8453);
        assert_eq!(address, Address::repeat_byte(0x11));
    }

    #[test]
    fn rejects_non_caip10_identity() {
        assert!(parse_caip10("https://validator.acme.io").is_err());
        assert!(parse_caip10("eip155:8453").is_err());
    }

    #[test]
    fn policy_roundtrips_through_params() {
        let params = encode_policy(Address::repeat_byte(0x22), U256::from(7u64), 80, "final");
        let policy = decode_policy(&params).expect("decode");
        assert_eq!(policy.validator, Address::repeat_byte(0x22));
        assert_eq!(policy.agentId, U256::from(7u64));
        assert_eq!(policy.minScore, 80);
        assert_eq!(policy.tag, "final");
    }
}
