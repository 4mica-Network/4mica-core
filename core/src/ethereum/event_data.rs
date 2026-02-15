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
    RecipientRemunerated {
        tab_id: String,
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
    TabPaid {
        tab_id: String,
        user: String,
        recipient: String,
        asset: String,
        amount: String,
        tx_hash: String,
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
            Some(&RecipientRemunerated::SIGNATURE_HASH) => {
                let RecipientRemunerated {
                    tab_id,
                    asset,
                    amount,
                    ..
                } = *self.log_decode()?.data();
                Ok(StoredEventData::RecipientRemunerated {
                    tab_id: format!("{:#x}", tab_id),
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
            Some(&TabPaid::SIGNATURE_HASH) => {
                let TabPaid {
                    tab_id,
                    asset,
                    user,
                    recipient,
                    amount,
                    ..
                } = *self.log_decode()?.data();
                let tx_hash = self
                    .transaction_hash
                    .map(|h| format!("{:#x}", h))
                    .unwrap_or_default();
                Ok(StoredEventData::TabPaid {
                    tab_id: format!("{:#x}", tab_id),
                    user: user.to_string(),
                    recipient: recipient.to_string(),
                    asset: asset.to_string(),
                    amount: amount.to_string(),
                    tx_hash,
                })
            }
            Some(&WithdrawalGracePeriodUpdated::SIGNATURE_HASH) => Ok(StoredEventData::Unknown {
                name: "WithdrawalGracePeriodUpdated".to_string(),
            }),
            Some(&RemunerationGracePeriodUpdated::SIGNATURE_HASH) => Ok(StoredEventData::Unknown {
                name: "RemunerationGracePeriodUpdated".to_string(),
            }),
            Some(&TabExpirationTimeUpdated::SIGNATURE_HASH) => Ok(StoredEventData::Unknown {
                name: "TabExpirationTimeUpdated".to_string(),
            }),
            Some(&SynchronizationDelayUpdated::SIGNATURE_HASH) => Ok(StoredEventData::Unknown {
                name: "SynchronizationDelayUpdated".to_string(),
            }),
            _ => Ok(StoredEventData::Unknown {
                name: "unknown".to_string(),
            }),
        }
    }
}
