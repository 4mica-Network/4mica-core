//! Decoded forms of the stored rows.

use alloy::primitives::{Address, B256, U256};
use chrono::NaiveDateTime;
use entities::sea_orm_active_enums::UserTransactionStatus;
use entities::sea_orm_active_enums::{
    GuaranteeSettlementStatus, ParticipantCycleRole, ParticipantCycleStatus,
};
use entities::{
    clearing_batch, cycle_exposure_edge, cycle_participant_position, guarantee, user_asset_balance,
    user_transaction,
};

use crate::error::PersistDbError;
use crate::persist::canonical::{Canonical, ReqId};

/// The values needed to write a new guarantee row, for `store_cycle_guarantee_on`.
#[derive(Debug, Clone)]
pub struct StoreCycleGuaranteeInput {
    pub guarantee_id: String,
    pub cycle_id: String,
    pub req_id: ReqId,
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
    pub req_id: ReqId,
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
            req_id: ReqId::from_canonical(&m.req_id)?,
            payer: Address::from_canonical(&m.from_address)?,
            payee: Address::from_canonical(&m.to_address)?,
            asset: Address::from_canonical(&m.asset_address)?,
            value: U256::from_canonical(&m.value)?,
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
            gross_outgoing: U256::from_canonical(&m.gross_outgoing)?,
            gross_incoming: U256::from_canonical(&m.gross_incoming)?,
            net_debit: U256::from_canonical(&m.net_debit)?,
            net_credit: U256::from_canonical(&m.net_credit)?,
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
            gross_amount: U256::from_canonical(&m.gross_amount)?,
            finalized_payable_amount: U256::from_canonical(&m.finalized_payable_amount)?,
            disputed_amount: U256::from_canonical(&m.disputed_amount)?,
            cancelled_amount: U256::from_canonical(&m.cancelled_amount)?,
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
            batch_hash: B256::from_canonical(&m.batch_hash)?,
            merkle_root: B256::from_canonical(&m.merkle_root)?,
            total_net_debit: U256::from_canonical(&m.total_net_debit)?,
            total_net_credit: U256::from_canonical(&m.total_net_credit)?,
            cycle_id: m.cycle_id,
            debtor_count: m.debtor_count,
            creditor_count: m.creditor_count,
            committed_at: m.committed_at,
            commit_tx_hash: m.commit_tx_hash,
        })
    }
}

/// A user's collateral position in one asset, with its amounts decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetBalance {
    pub user_address: Address,
    pub asset_address: Address,
    /// Everything deposited, including whatever `locked` covers.
    pub total: U256,
    /// The part of `total` committed to open guarantees and so unavailable.
    pub locked: U256,
    /// Guards writes: a caller passes the version it read back to the update.
    pub version: i32,
    pub updated_at: NaiveDateTime,
}

impl AssetBalance {
    /// What the user can still spend: `total` minus what is already committed.
    pub fn free(&self) -> U256 {
        self.total.saturating_sub(self.locked)
    }
}

impl TryFrom<user_asset_balance::Model> for AssetBalance {
    type Error = PersistDbError;

    fn try_from(m: user_asset_balance::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            user_address: Address::from_canonical(&m.user_address)?,
            asset_address: Address::from_canonical(&m.asset_address)?,
            total: U256::from_canonical(&m.total)?,
            locked: U256::from_canonical(&m.locked)?,
            version: m.version,
            updated_at: m.updated_at,
        })
    }
}

/// A payment transaction row, with its addresses and amount decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserTransaction {
    pub tx_id: String,
    pub user_address: Address,
    pub recipient_address: Address,
    pub asset_address: Address,
    pub amount: U256,
    pub block_number: Option<i64>,
    pub block_hash: Option<String>,
    pub status: UserTransactionStatus,
    pub verified: bool,
    pub finalized: bool,
    pub failed: bool,
    pub created_at: NaiveDateTime,
}

impl TryFrom<user_transaction::Model> for UserTransaction {
    type Error = PersistDbError;

    fn try_from(m: user_transaction::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            user_address: Address::from_canonical(&m.user_address)?,
            recipient_address: Address::from_canonical(&m.recipient_address)?,
            asset_address: Address::from_canonical(&m.asset_address)?,
            amount: U256::from_canonical(&m.amount)?,
            tx_id: m.tx_id,
            block_number: m.block_number,
            block_hash: m.block_hash,
            status: m.status,
            verified: m.verified,
            finalized: m.finalized,
            failed: m.failed,
            created_at: m.created_at,
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
