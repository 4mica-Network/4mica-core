use crate::persist::canonical::Canonical;
use crate::persist::rows::{AssetBalance, UserTransaction};
use entities::user;
use rpc::{AssetBalanceInfo, UserSuspensionStatus, UserTransactionInfo};

pub fn asset_balance_to_info(balance: AssetBalance) -> AssetBalanceInfo {
    AssetBalanceInfo {
        user_address: balance.user_address.canonical(),
        asset_address: balance.asset_address.canonical(),
        total: balance.total,
        locked: balance.locked,
        version: balance.version,
        updated_at: balance.updated_at.and_utc().timestamp(),
    }
}

pub fn user_transaction_to_info(tx: UserTransaction) -> UserTransactionInfo {
    UserTransactionInfo {
        user_address: tx.user_address.canonical(),
        recipient_address: tx.recipient_address.canonical(),
        tx_hash: tx.tx_id,
        amount: tx.amount,
        verified: tx.verified,
        finalized: tx.finalized,
        failed: tx.failed,
        created_at: tx.created_at.and_utc().timestamp_millis(),
    }
}

pub fn user_model_to_suspension_status(model: user::Model) -> UserSuspensionStatus {
    UserSuspensionStatus {
        user_address: model.address,
        suspended: model.is_suspended,
        updated_at: model.updated_at.and_utc().timestamp(),
    }
}
