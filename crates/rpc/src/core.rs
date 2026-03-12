use serde::{Deserialize, Serialize};

fn default_active_guarantee_version() -> u64 {
    crate::guarantee::GUARANTEE_CLAIMS_VERSION
}

fn default_validation_hash_canonicalization_version() -> String {
    crate::guarantee::VALIDATION_REQUEST_BINDING_DOMAIN_V1.to_string()
}

/// Static parameters exposed by the core service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorePublicParameters {
    /// Operator BLS public key.
    pub public_key: Vec<u8>,
    /// Address of the on-chain core contract.
    pub contract_address: String,
    /// Ethereum RPC endpoint URL.
    pub ethereum_http_rpc_url: String,
    /// EIP-712 domain name.
    pub eip712_name: String,
    /// EIP-712 domain version.
    pub eip712_version: String,
    /// Chain identifier used for the signing domain.
    pub chain_id: u64,
    /// Active guarantee request/claims version expected by core.
    #[serde(default = "default_active_guarantee_version")]
    pub active_guarantee_version: u64,
    /// Domain separator used by core for BLS guarantee signing at `active_guarantee_version`.
    #[serde(default)]
    pub active_guarantee_domain_separator: String,
    /// Trusted validation registries configured in core (address allowlist).
    #[serde(default)]
    pub trusted_validation_registries: Vec<String>,
    /// Canonicalization identifier used for `validation_request_hash` derivation.
    #[serde(default = "default_validation_hash_canonicalization_version")]
    pub validation_hash_canonicalization_version: String,
}
