use serde::{Deserialize, Serialize};

/// A single ERC-20 token supported by the Core4Mica contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedTokenInfo {
    pub symbol: String,
    pub address: String,
    pub decimals: u8,
    /// The token's own EIP-712 `DOMAIN_SEPARATOR()`, read on-chain by core.
    ///
    /// Relayed so clients can build a gasless-deposit signature without an Ethereum RPC of their
    /// own. `None` for tokens that do not expose it — those cannot be deposited gaslessly.
    ///
    /// Note this is the separator itself, not the `name`/`version` pair x402 servers advertise for
    /// clients to reconstruct one from; see `sdk::digest::eip712_domain_separator` for that path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_separator: Option<String>,
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
    /// Amount argument for the selected ClearingHouse function.
    pub amount: String,
    /// Native value to attach. This is non-zero only for native-asset debtor payments.
    pub payable_value: String,
    pub proof: Vec<String>,
}

fn default_supported_guarantee_versions() -> Vec<u64> {
    crate::guarantee::SUPPORTED_GUARANTEE_VERSIONS.to_vec()
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
    /// Guarantee claims versions this core can decode. Clients always sign at their own
    /// [`crate::guarantee::GUARANTEE_CLAIMS_VERSION`]; this lets a client fail fast with a clear
    /// message when it is newer than the core it is talking to.
    #[serde(default = "default_supported_guarantee_versions")]
    pub supported_guarantee_versions: Vec<u64>,
    /// Domain separator core uses for BLS guarantee signing at the current version.
    #[serde(default)]
    pub guarantee_domain_separator: String,
    /// Validators this operator whitelisted. A validation requirement may only name one of these.
    #[serde(default)]
    pub validators: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::{
        ClearingParticipantRole, ClearingSettlementAction, ClearingSettlementActionResponse,
        CorePublicParameters,
    };

    #[test]
    fn clearing_settlement_action_uses_snake_case_json() {
        let value = serde_json::to_value(ClearingSettlementAction::PayNetDebit).unwrap();
        assert_eq!(value, serde_json::json!("pay_net_debit"));

        let action: ClearingSettlementAction =
            serde_json::from_value(serde_json::json!("claim_net_credit")).unwrap();
        assert_eq!(action, ClearingSettlementAction::ClaimNetCredit);
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
            function_name: "payNetDebit".to_string(),
            action: ClearingSettlementAction::PayNetDebit,
            cycle_id: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            cycle_id_text: "cycle".to_string(),
            asset_address: "0x2222222222222222222222222222222222222222".to_string(),
            participant: "0x3333333333333333333333333333333333333333".to_string(),
            amount: "10".to_string(),
            payable_value: "0".to_string(),
            proof: vec![
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            ],
        };

        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["action"], "pay_net_debit");
        assert_eq!(value["function_name"], "payNetDebit");
        assert_eq!(
            value["participant"],
            "0x3333333333333333333333333333333333333333"
        );
    }

    fn public_params(ethereum_http_rpc_url: &str) -> CorePublicParameters {
        CorePublicParameters {
            public_key: vec![1, 2, 3],
            contract_address: "0x0000000000000000000000000000000000000001".to_string(),
            ethereum_http_rpc_url: ethereum_http_rpc_url.to_string(),
            eip712_name: "4Mica".to_string(),
            eip712_version: "1".to_string(),
            chain_id: 1,
            supported_guarantee_versions: vec![1],
            guarantee_domain_separator: String::new(),
            validators: Vec::new(),
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
