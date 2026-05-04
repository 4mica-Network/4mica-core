use crate::error::ServiceResult;
use alloy::primitives::U256;
use anyhow::anyhow;
use entities::{sea_orm_active_enums::CollateralEventType, user};
use rpc::{AssetBalanceInfo, CollateralEventInfo, UserSuspensionStatus};
use std::str::FromStr;

pub fn collateral_event_type_to_str(t: CollateralEventType) -> &'static str {
    match t {
        CollateralEventType::Deposit => "DEPOSIT",
        CollateralEventType::Withdraw => "WITHDRAW",
        CollateralEventType::Reserve => "RESERVE",
        CollateralEventType::CancelReserve => "CANCEL_RESERVE",
        CollateralEventType::Unlock => "UNLOCK",
        CollateralEventType::Remunerate => "REMUNERATE",
    }
}

pub fn collateral_event_model_to_info(
    model: entities::collateral_event::Model,
) -> ServiceResult<CollateralEventInfo> {
    let amount = U256::from_str(&model.amount)
        .map_err(|e| anyhow!("invalid collateral event amount {}: {e}", model.amount))?;

    let req_id = match model.req_id {
        Some(ref id) => Some(
            U256::from_str(id)
                .map_err(|e| anyhow!("invalid collateral event req id {}: {e}", id))?,
        ),
        None => None,
    };

    Ok(CollateralEventInfo {
        id: model.id,
        user_address: model.user_address,
        asset_address: model.asset_address,
        amount,
        event_type: collateral_event_type_to_str(model.event_type).to_string(),
        req_id,
        tx_id: model.tx_id,
        created_at: model.created_at.and_utc().timestamp(),
    })
}

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
