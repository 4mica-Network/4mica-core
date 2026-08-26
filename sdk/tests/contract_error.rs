use alloy::primitives::{Address, B256, U256};
use rpc::{ClearingSettlementAction, ClearingSettlementActionResponse};
use sdk_4mica::error::SettlementError;

#[test]
fn clearing_settlement_error_wraps_rpc_failures() {
    let err = SettlementError::Rpc(rpc::ApiClientError::Api {
        status: reqwest::StatusCode::BAD_REQUEST,
        message: "settlement cycle has no clearing batch".to_string(),
    });

    assert!(
        err.to_string()
            .contains("settlement cycle has no clearing batch")
    );
}

#[test]
fn debtor_payment_action_is_cycle_scoped() {
    let action = ClearingSettlementActionResponse {
        cycle_id: format!("{:#x}", B256::repeat_byte(0xaa)),
        cycle_id_text: "eth:1800000000".to_string(),
        participant: Address::repeat_byte(0xbb).to_string(),
        function_name: "payNetDebit".to_string(),
        asset_address: Address::ZERO.to_string(),
        amount: U256::from(5u64).to_string(),
        action: ClearingSettlementAction::PayNetDebit,
        contract_address: Address::repeat_byte(0xcc).to_string(),
        payable_value: U256::from(5u64).to_string(),
        proof: vec![],
    };

    assert_eq!(action.action, ClearingSettlementAction::PayNetDebit);
    assert_eq!(action.amount, U256::from(5u64).to_string());
    assert_eq!(action.function_name, "payNetDebit");
}
