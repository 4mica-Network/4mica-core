use serde::{Deserialize, Serialize};

/// A single ERC-20 token supported by the Core4Mica contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedTokenInfo {
    pub symbol: String,
    pub address: String,
    pub decimals: u8,
}

/// Response from `GET /core/tokens`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedTokensResponse {
    pub chain_id: u64,
    pub tokens: Vec<SupportedTokenInfo>,
}

fn default_max_accepted_guarantee_version() -> u64 {
    crate::guarantee::GUARANTEE_CLAIMS_VERSION
}

fn default_validation_hash_canonicalization_version() -> String {
    crate::guarantee::VALIDATION_REQUEST_BINDING_DOMAIN_V2.to_string()
}

fn default_accepted_guarantee_versions() -> Vec<u64> {
    Vec::new()
}

/// Static parameters exposed by the core service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorePublicParameters {
    /// Operator BLS public key.
    pub public_key: Vec<u8>,
    /// Address of the on-chain core contract.
    pub contract_address: String,
    /// Ethereum RPC endpoint URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ethereum_http_rpc_url: String,
    /// EIP-712 domain name.
    pub eip712_name: String,
    /// EIP-712 domain version.
    pub eip712_version: String,
    /// Chain identifier used for the signing domain.
    pub chain_id: u64,
    /// Highest guarantee version accepted by core. The output version is determined by the
    /// incoming claim, not this field — this is the ceiling for default accepted-version ranges.
    #[serde(default = "default_max_accepted_guarantee_version")]
    pub max_accepted_guarantee_version: u64,
    /// Guarantee request/claims versions accepted by core.
    #[serde(default = "default_accepted_guarantee_versions")]
    pub accepted_guarantee_versions: Vec<u64>,
    /// Domain separator used by core for BLS guarantee signing at `max_accepted_guarantee_version`.
    #[serde(default)]
    pub active_guarantee_domain_separator: String,
    /// Trusted validation registries configured in core (address allowlist).
    #[serde(default)]
    pub trusted_validation_registries: Vec<String>,
    /// Canonicalization identifier used for `validation_request_hash` derivation.
    #[serde(default = "default_validation_hash_canonicalization_version")]
    pub validation_hash_canonicalization_version: String,
}

impl CorePublicParameters {
    /// Returns the accepted guarantee versions, falling back to a sensible default when the field
    /// is absent (e.g. from an older core service).
    ///
    /// Default: every version from 1 up to and including `max_accepted_guarantee_version`.
    /// V1-only cores → `[1]`, V2 cores → `[1, 2]`, future V3 cores → `[1, 2, 3]` automatically.
    pub fn accepted_guarantee_versions_or_default(&self) -> Vec<u64> {
        if self.accepted_guarantee_versions.is_empty() {
            (crate::guarantee::GUARANTEE_CLAIMS_VERSION..=self.max_accepted_guarantee_version)
                .collect()
        } else {
            self.accepted_guarantee_versions.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CorePublicParameters;

    fn public_params(ethereum_http_rpc_url: &str) -> CorePublicParameters {
        CorePublicParameters {
            public_key: vec![1, 2, 3],
            contract_address: "0x0000000000000000000000000000000000000001".to_string(),
            ethereum_http_rpc_url: ethereum_http_rpc_url.to_string(),
            eip712_name: "4Mica".to_string(),
            eip712_version: "1".to_string(),
            chain_id: 1,
            max_accepted_guarantee_version: 1,
            accepted_guarantee_versions: vec![1],
            active_guarantee_domain_separator: String::new(),
            trusted_validation_registries: Vec::new(),
            validation_hash_canonicalization_version:
                crate::guarantee::VALIDATION_REQUEST_BINDING_DOMAIN_V2.to_string(),
        }
    }

    #[test]
    fn public_params_omit_empty_ethereum_http_rpc_url() {
        let value = serde_json::to_value(public_params("")).expect("serialize public params");

        assert!(value.get("ethereum_http_rpc_url").is_none());
    }

    #[test]
    fn public_params_include_non_empty_ethereum_http_rpc_url() {
        let value =
            serde_json::to_value(public_params("https://public-rpc.example")).expect("serialize");

        assert_eq!(
            value
                .get("ethereum_http_rpc_url")
                .and_then(|value| value.as_str()),
            Some("https://public-rpc.example")
        );
    }
}
