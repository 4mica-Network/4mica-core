use serde::{Deserialize, Serialize};

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
