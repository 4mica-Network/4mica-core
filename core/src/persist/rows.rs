//! Decoded forms of the stored rows.

use alloy::primitives::{Address, B256, U256};
use chrono::NaiveDateTime;
use entities::sea_orm_active_enums::{
    GuaranteeSettlementStatus, ParticipantCycleRole, ParticipantCycleStatus,
};
use entities::{clearing_batch, cycle_exposure_edge, cycle_participant_position, guarantee};

use crate::error::PersistDbError;
use crate::persist::canonical::Canonical;

/// Decode a stored 32-byte hash, which is held as `0x`-prefixed hex.
fn decode_b256(field: &str, raw: &str) -> Result<B256, PersistDbError> {
    raw.trim().parse::<B256>().map_err(|e| {
        PersistDbError::InvariantViolation(format!("stored {field} {raw} is not a hash: {e}"))
    })
}

/// Decode a stored `U256`.
fn decode_u256(field: &str, raw: &str) -> Result<U256, PersistDbError> {
    raw.parse::<U256>().map_err(|e| {
        PersistDbError::InvariantViolation(format!("stored {field} {raw} is not a u256: {e}"))
    })
}

/// The values needed to write a new guarantee row, for `store_cycle_guarantee_on`.
#[derive(Debug, Clone)]
pub struct StoreCycleGuaranteeInput {
    pub guarantee_id: String,
    pub cycle_id: String,
    pub req_id: U256,
    pub version: u64,
    pub from: Address,
    pub to: Address,
    pub asset: Address,
    pub value: U256,
    pub start_ts: NaiveDateTime,
    pub cert: String,
    pub request: Option<String>,
    pub settlement_status: GuaranteeSettlementStatus,
}

/// A guarantee row, with its on-chain values decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleGuarantee {
    pub guarantee_id: String,
    pub cycle_id: String,
    pub req_id: U256,
    /// The `from` side, who owes the value and whose collateral is locked.
    pub payer: Address,
    /// The `to` side, who is owed the value.
    pub payee: Address,
    pub asset: Address,
    pub value: U256,
    pub version: i32,
    pub start_ts: NaiveDateTime,
    pub cert: String,
    pub request: Option<String>,
    pub settlement_status: GuaranteeSettlementStatus,
    pub dispute_deadline: Option<NaiveDateTime>,
    pub finalized_at: Option<NaiveDateTime>,
    pub netted_at: Option<NaiveDateTime>,
    pub settled_at: Option<NaiveDateTime>,
}

impl TryFrom<guarantee::Model> for CycleGuarantee {
    type Error = PersistDbError;

    fn try_from(m: guarantee::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            req_id: decode_u256("guarantee req_id", &m.req_id)?,
            payer: Address::from_canonical(&m.from_address)?,
            payee: Address::from_canonical(&m.to_address)?,
            asset: Address::from_canonical(&m.asset_address)?,
            value: decode_u256("guarantee value", &m.value)?,
            guarantee_id: m.guarantee_id,
            cycle_id: m.cycle_id,
            version: m.version,
            start_ts: m.start_ts,
            cert: m.cert,
            request: m.request,
            settlement_status: m.settlement_status,
            dispute_deadline: m.dispute_deadline,
            finalized_at: m.finalized_at,
            netted_at: m.netted_at,
            settled_at: m.settled_at,
        })
    }
}

/// A participant's net position within a cycle, with its amounts decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantPosition {
    pub cycle_id: String,
    pub participant: Address,
    pub asset_address: Address,
    pub gross_outgoing: U256,
    pub gross_incoming: U256,
    pub net_debit: U256,
    pub net_credit: U256,
    pub role: ParticipantCycleRole,
    pub status: ParticipantCycleStatus,
    pub settlement_tx_hash: Option<String>,
}

impl TryFrom<cycle_participant_position::Model> for ParticipantPosition {
    type Error = PersistDbError;

    fn try_from(m: cycle_participant_position::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            participant: Address::from_canonical(&m.participant)?,
            asset_address: Address::from_canonical(&m.asset_address)?,
            gross_outgoing: decode_u256("position gross_outgoing", &m.gross_outgoing)?,
            gross_incoming: decode_u256("position gross_incoming", &m.gross_incoming)?,
            net_debit: decode_u256("position net_debit", &m.net_debit)?,
            net_credit: decode_u256("position net_credit", &m.net_credit)?,
            cycle_id: m.cycle_id,
            role: m.role,
            status: m.status,
            settlement_tx_hash: m.settlement_tx_hash,
        })
    }
}

/// A cycle's netted exposure between one payer and one payee, with its amounts decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureEdge {
    pub cycle_id: String,
    pub payer: Address,
    pub payee: Address,
    pub asset_address: Address,
    pub gross_amount: U256,
    pub finalized_payable_amount: U256,
    pub disputed_amount: U256,
    pub cancelled_amount: U256,
    pub guarantee_count: i64,
}

impl TryFrom<cycle_exposure_edge::Model> for ExposureEdge {
    type Error = PersistDbError;

    fn try_from(m: cycle_exposure_edge::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            payer: Address::from_canonical(&m.payer)?,
            payee: Address::from_canonical(&m.payee)?,
            asset_address: Address::from_canonical(&m.asset_address)?,
            gross_amount: decode_u256("edge gross_amount", &m.gross_amount)?,
            finalized_payable_amount: decode_u256(
                "edge finalized_payable_amount",
                &m.finalized_payable_amount,
            )?,
            disputed_amount: decode_u256("edge disputed_amount", &m.disputed_amount)?,
            cancelled_amount: decode_u256("edge cancelled_amount", &m.cancelled_amount)?,
            cycle_id: m.cycle_id,
            guarantee_count: m.guarantee_count,
        })
    }
}

/// A cycle's committed clearing batch, with its totals and Merkle root decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearingBatch {
    pub cycle_id: String,
    pub asset_address: Address,
    pub batch_hash: B256,
    pub merkle_root: B256,
    pub total_net_debit: U256,
    pub total_net_credit: U256,
    pub debtor_count: i64,
    pub creditor_count: i64,
    pub committed_at: NaiveDateTime,
    pub commit_tx_hash: Option<String>,
}

impl TryFrom<clearing_batch::Model> for ClearingBatch {
    type Error = PersistDbError;

    fn try_from(m: clearing_batch::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            asset_address: Address::from_canonical(&m.asset_address)?,
            batch_hash: decode_b256("batch hash", &m.batch_hash)?,
            merkle_root: decode_b256("batch merkle_root", &m.merkle_root)?,
            total_net_debit: decode_u256("batch total_net_debit", &m.total_net_debit)?,
            total_net_credit: decode_u256("batch total_net_credit", &m.total_net_credit)?,
            cycle_id: m.cycle_id,
            debtor_count: m.debtor_count,
            creditor_count: m.creditor_count,
            committed_at: m.committed_at,
            commit_tx_hash: m.commit_tx_hash,
        })
    }
}

/// Decode a batch of rows, failing on the first that does not.
pub fn decode_all<T, M>(models: Vec<M>) -> Result<Vec<T>, PersistDbError>
where
    T: TryFrom<M, Error = PersistDbError>,
{
    models.into_iter().map(T::try_from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn position_model(net_debit: &str, participant: &str) -> cycle_participant_position::Model {
        let now = Utc::now().naive_utc();
        cycle_participant_position::Model {
            cycle_id: "cycle".to_string(),
            participant: participant.to_string(),
            asset_address: "0x0000000000000000000000000000000000000000".to_string(),
            gross_outgoing: "0".to_string(),
            gross_incoming: "0".to_string(),
            net_debit: net_debit.to_string(),
            net_credit: "0".to_string(),
            role: ParticipantCycleRole::NetDebtor,
            status: ParticipantCycleStatus::Unpaid,
            settlement_tx_hash: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn a_stored_row_decodes_into_typed_values() {
        let addr = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        let decoded = ParticipantPosition::try_from(position_model("10", addr)).expect("decodes");

        assert_eq!(decoded.net_debit, U256::from(10));
        assert_eq!(decoded.participant, addr.parse::<Address>().unwrap());
    }

    #[test]
    fn a_corrupt_amount_is_an_invariant_violation_not_bad_input() {
        let addr = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        let err = ParticipantPosition::try_from(position_model("not-a-number", addr))
            .expect_err("must not decode");

        assert!(matches!(err, PersistDbError::InvariantViolation(_)));
    }

    #[test]
    fn a_corrupt_address_is_an_invariant_violation_too() {
        let err = ParticipantPosition::try_from(position_model("10", "not-an-address"))
            .expect_err("must not decode");

        assert!(matches!(err, PersistDbError::InvariantViolation(_)));
    }
}
