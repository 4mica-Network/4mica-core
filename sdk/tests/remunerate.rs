use alloy::primitives::{Address, B256, U256};
use rpc::{ClearingSettlementAction, ClearingSettlementActionResponse};

#[test]
fn clearing_claim_action_response_carries_cycle_native_claim_payload() {
    let response = ClearingSettlementActionResponse {
        cycle_id: format!("{:#x}", B256::repeat_byte(0x11)),
        cycle_id_text: "asset:1800000000".to_string(),
        participant: Address::repeat_byte(0x22).to_string(),
        function_name: "claimNetCredit".to_string(),
        asset_address: Address::ZERO.to_string(),
        debtor: None,
        amount: U256::from(42u64).to_string(),
        action: ClearingSettlementAction::ClaimNetCredit,
        contract_address: Address::repeat_byte(0x33).to_string(),
        payable_value: "0".to_string(),
        proof: vec![format!("{:#x}", B256::repeat_byte(0x44))],
    };

    assert_eq!(response.action, ClearingSettlementAction::ClaimNetCredit);
    assert_eq!(response.function_name, "claimNetCredit");
    assert_eq!(response.amount, U256::from(42u64).to_string());
    assert_eq!(response.cycle_id_text, "asset:1800000000");
}
