use alloy::rpc::types::Log;
use alloy_sol_types::SolEvent;
use serde::{Deserialize, Serialize};

use crate::error::BlockchainListenerError;
use crate::ethereum::contract::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StoredEventData {
    CollateralDeposited {
        user: String,
        asset: String,
        amount: String,
    },
    CollateralWithdrawn {
        user: String,
        asset: String,
        amount: String,
    },
    WithdrawalRequested {
        user: String,
        asset: String,
        when: i64,
        amount: String,
    },
    WithdrawalCanceled {
        user: String,
        asset: String,
    },
    CycleCommitted {
        cycle_id: String,
        asset: String,
        merkle_root: String,
        total_net_debit: String,
        total_net_credit: String,
        payment_submission_deadline: u64,
        payment_finality_deadline: u64,
    },
    DebtorPaid {
        cycle_id: String,
        debtor: String,
        amount: String,
        tx_hash: String,
    },
    CreditorClaimed {
        cycle_id: String,
        creditor: String,
        asset: String,
        amount: String,
        tx_hash: String,
    },
    DebtorDefaulted {
        cycle_id: String,
        debtor: String,
        asset: String,
        amount: String,
    },
    CycleFinalized {
        cycle_id: String,
    },
    SettlementSkipped {
        cycle_id: String,
        participant: String,
        reason: String,
    },
    Unknown {
        name: String,
    },
}

#[derive(Clone, Debug)]
pub struct EventMeta {
    pub chain_id: u64,
    pub block_hash: String,
    pub tx_hash: String,
    pub log_index: u64,
}

impl TryInto<StoredEventData> for &Log {
    type Error = BlockchainListenerError;

    fn try_into(self) -> Result<StoredEventData, Self::Error> {
        match self.topic0() {
            Some(&CollateralDeposited::SIGNATURE_HASH) => {
                let CollateralDeposited {
                    user,
                    asset,
                    amount,
                    ..
                } = *self.log_decode()?.data();
                Ok(StoredEventData::CollateralDeposited {
                    user: user.to_string(),
                    asset: asset.to_string(),
                    amount: amount.to_string(),
                })
            }
            Some(&CollateralWithdrawn::SIGNATURE_HASH) => {
                let CollateralWithdrawn {
                    user,
                    asset,
                    amount,
                    ..
                } = *self.log_decode()?.data();
                Ok(StoredEventData::CollateralWithdrawn {
                    user: user.to_string(),
                    asset: asset.to_string(),
                    amount: amount.to_string(),
                })
            }
            Some(&WithdrawalRequested::SIGNATURE_HASH) => {
                let WithdrawalRequested {
                    user,
                    asset,
                    when,
                    amount,
                    ..
                } = *self.log_decode()?.data();
                Ok(StoredEventData::WithdrawalRequested {
                    user: user.to_string(),
                    asset: asset.to_string(),
                    when: when.to(),
                    amount: amount.to_string(),
                })
            }
            Some(&WithdrawalCanceled::SIGNATURE_HASH) => {
                let WithdrawalCanceled { user, asset, .. } = *self.log_decode()?.data();
                Ok(StoredEventData::WithdrawalCanceled {
                    user: user.to_string(),
                    asset: asset.to_string(),
                })
            }
            Some(&CycleCommitted::SIGNATURE_HASH) => {
                let CycleCommitted {
                    cycleId,
                    asset,
                    merkleRoot,
                    totalNetDebit,
                    totalNetCredit,
                    paymentSubmissionDeadline,
                    paymentFinalityDeadline,
                    ..
                } = *self.log_decode()?.data();
                Ok(StoredEventData::CycleCommitted {
                    cycle_id: format!("{:#x}", cycleId),
                    asset: asset.to_string(),
                    merkle_root: format!("{:#x}", merkleRoot),
                    total_net_debit: totalNetDebit.to_string(),
                    total_net_credit: totalNetCredit.to_string(),
                    payment_submission_deadline: paymentSubmissionDeadline,
                    payment_finality_deadline: paymentFinalityDeadline,
                })
            }
            Some(&DebtorPaid::SIGNATURE_HASH) => {
                let DebtorPaid {
                    cycleId,
                    debtor,
                    amount,
                    ..
                } = *self.log_decode()?.data();
                let tx_hash = self
                    .transaction_hash
                    .map(|h| format!("{:#x}", h))
                    .unwrap_or_default();
                Ok(StoredEventData::DebtorPaid {
                    cycle_id: format!("{:#x}", cycleId),
                    debtor: debtor.to_string(),
                    amount: amount.to_string(),
                    tx_hash,
                })
            }
            Some(&CreditorClaimed::SIGNATURE_HASH) => {
                let CreditorClaimed {
                    cycleId,
                    creditor,
                    asset,
                    amount,
                    ..
                } = *self.log_decode()?.data();
                let tx_hash = self
                    .transaction_hash
                    .map(|h| format!("{:#x}", h))
                    .unwrap_or_default();
                Ok(StoredEventData::CreditorClaimed {
                    cycle_id: format!("{:#x}", cycleId),
                    creditor: creditor.to_string(),
                    asset: asset.to_string(),
                    amount: amount.to_string(),
                    tx_hash,
                })
            }
            Some(&DebtorDefaulted::SIGNATURE_HASH) => {
                let DebtorDefaulted {
                    cycleId,
                    debtor,
                    asset,
                    amount,
                    ..
                } = *self.log_decode()?.data();
                Ok(StoredEventData::DebtorDefaulted {
                    cycle_id: format!("{:#x}", cycleId),
                    debtor: debtor.to_string(),
                    asset: asset.to_string(),
                    amount: amount.to_string(),
                })
            }
            Some(&CycleFinalized::SIGNATURE_HASH) => {
                let CycleFinalized { cycleId, .. } = *self.log_decode()?.data();
                Ok(StoredEventData::CycleFinalized {
                    cycle_id: format!("{:#x}", cycleId),
                })
            }
            Some(&SettlementSkipped::SIGNATURE_HASH) => {
                let SettlementSkipped {
                    cycleId,
                    participant,
                    reason,
                } = self.log_decode::<SettlementSkipped>()?.data().clone();
                Ok(StoredEventData::SettlementSkipped {
                    cycle_id: format!("{:#x}", cycleId),
                    participant: participant.to_string(),
                    reason,
                })
            }
            Some(&WithdrawalGracePeriodUpdated::SIGNATURE_HASH) => Ok(StoredEventData::Unknown {
                name: "WithdrawalGracePeriodUpdated".to_string(),
            }),
            _ => Ok(StoredEventData::Unknown {
                name: "unknown".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, Log as PrimitiveLog};
    use alloy_sol_types::SolEvent;

    #[test]
    fn decodes_settlement_skipped_with_reason() {
        let cycle = B256::repeat_byte(0xab);
        let participant = Address::repeat_byte(0x11);
        let event = SettlementSkipped {
            cycleId: cycle,
            participant,
            reason: "invalid proof".to_string(),
        };
        let rpc_log = Log {
            inner: PrimitiveLog {
                address: Address::ZERO,
                data: event.encode_log_data(),
            },
            block_hash: None,
            block_number: None,
            block_timestamp: None,
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            removed: false,
        };

        let decoded: StoredEventData = (&rpc_log).try_into().expect("decode");
        match decoded {
            StoredEventData::SettlementSkipped {
                cycle_id,
                participant: p,
                reason,
            } => {
                assert_eq!(reason, "invalid proof");
                assert_eq!(cycle_id, format!("{cycle:#x}"));
                assert_eq!(p.to_lowercase(), format!("{participant:#x}"));
            }
            other => panic!("expected SettlementSkipped, got {other:?}"),
        }
    }
}
