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

/// Participant role in a committed clearing cycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClearingParticipantRole {
    NetDebtor,
    NetCreditor,
}

/// Response from `GET /core/cycles/{cycle_id}/participants/{participant}/clearing-proof`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClearingParticipantProofResponse {
    /// On-chain bytes32 cycle identifier.
    pub cycle_id: String,
    /// Core database cycle identifier.
    pub cycle_id_text: String,
    pub asset_address: String,
    pub participant: String,
    pub role: ClearingParticipantRole,
    /// Amount used with the participant's role-specific ClearingHouse call.
    pub amount: String,
    pub net_debit: String,
    pub net_credit: String,
    pub leaf: String,
    pub merkle_root: String,
    pub proof: Vec<String>,
}

/// ClearingHouse participant action to prepare from a participant proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClearingSettlementAction {
    PayNetDebit,
    ClaimNetCredit,
    MarkDefaulted,
}

/// Response from `GET /core/cycles/{cycle_id}/participants/{participant}/clearing-action`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClearingSettlementActionResponse {
    /// ClearingHouse contract address.
    pub contract_address: String,
    /// Contract function name to call.
    pub function_name: String,
    /// Prepared participant action.
    pub action: ClearingSettlementAction,
    /// On-chain bytes32 cycle identifier.
    pub cycle_id: String,
    /// Core database cycle identifier.
    pub cycle_id_text: String,
    pub asset_address: String,
    /// Participant whose committed Merkle leaf is proven.
    pub participant: String,
    /// Alias for `participant` when `action = mark_defaulted`.
    pub debtor: Option<String>,
    /// Amount argument for the selected ClearingHouse function.
    pub amount: String,
    /// Native value to attach. This is non-zero only for native-asset debtor payments.
    pub payable_value: String,
    pub proof: Vec<String>,
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
    use super::{
        ClearingParticipantRole, ClearingSettlementAction, ClearingSettlementActionResponse,
    };

    #[test]
    fn clearing_settlement_action_uses_snake_case_json() {
        let value = serde_json::to_value(ClearingSettlementAction::PayNetDebit).unwrap();
        assert_eq!(value, serde_json::json!("pay_net_debit"));

        let action: ClearingSettlementAction =
            serde_json::from_value(serde_json::json!("mark_defaulted")).unwrap();
        assert_eq!(action, ClearingSettlementAction::MarkDefaulted);
    }

    #[test]
    fn clearing_participant_role_uses_screaming_snake_case_json() {
        let value = serde_json::to_value(ClearingParticipantRole::NetCreditor).unwrap();
        assert_eq!(value, serde_json::json!("NET_CREDITOR"));
    }

    #[test]
    fn clearing_action_response_contains_contract_call_payload() {
        let response = ClearingSettlementActionResponse {
            contract_address: "0x1111111111111111111111111111111111111111".to_string(),
            function_name: "markDefaulted".to_string(),
            action: ClearingSettlementAction::MarkDefaulted,
            cycle_id: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            cycle_id_text: "cycle".to_string(),
            asset_address: "0x2222222222222222222222222222222222222222".to_string(),
            participant: "0x3333333333333333333333333333333333333333".to_string(),
            debtor: Some("0x3333333333333333333333333333333333333333".to_string()),
            amount: "10".to_string(),
            payable_value: "0".to_string(),
            proof: vec![
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            ],
        };

        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["action"], "mark_defaulted");
        assert_eq!(value["function_name"], "markDefaulted");
        assert_eq!(
            value["debtor"],
            "0x3333333333333333333333333333333333333333"
        );
    }
}
