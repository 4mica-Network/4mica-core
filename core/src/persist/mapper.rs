use crate::error::ServiceResult;
use alloy::primitives::U256;
use anyhow::anyhow;
use entities::user;
use rpc::{AssetBalanceInfo, UserSuspensionStatus};
use std::str::FromStr;

pub fn asset_balance_model_to_info(
    model: entities::user_asset_balance::Model,
) -> ServiceResult<AssetBalanceInfo> {
    let total = U256::from_str(&model.total)
        .map_err(|e| anyhow!("invalid asset balance total {}: {e}", model.total))?;
    let locked = U256::from_str(&model.locked)
        .map_err(|e| anyhow!("invalid asset balance locked {}: {e}", model.locked))?;

    Ok(AssetBalanceInfo {
        user_address: model.user_address,
        asset_address: model.asset_address,
        total,
        locked,
        version: model.version,
        updated_at: model.updated_at.and_utc().timestamp(),
    })
}

pub fn user_model_to_suspension_status(model: user::Model) -> UserSuspensionStatus {
    UserSuspensionStatus {
        user_address: model.address,
        suspended: model.is_suspended,
        updated_at: model.updated_at.and_utc().timestamp(),
    }
}
