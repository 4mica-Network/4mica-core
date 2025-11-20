use crate::error::{ServiceError, ServiceResult};
use alloy::primitives::U256;
use anyhow::anyhow;
use entities::{
    admin_api_key,
    sea_orm_active_enums::{CollateralEventType, SettlementStatus, TabStatus},
    tabs, user,
};
use rpc::{
    AdminApiKeyInfo, AssetBalanceInfo, CollateralEventInfo, GuaranteeInfo, TabInfo,
    UserSuspensionStatus,
};
use std::str::FromStr;

pub fn tab_status_to_str(status: TabStatus) -> &'static str {
    match status {
        TabStatus::Pending => "PENDING",
        TabStatus::Open => "OPEN",
        TabStatus::Closed => "CLOSED",
    }
}

pub fn settlement_status_to_str(status: SettlementStatus) -> &'static str {
    match status {
        SettlementStatus::Pending => "PENDING",
        SettlementStatus::Settled => "SETTLED",
        SettlementStatus::Failed => "FAILED",
        SettlementStatus::Remunerated => "REMUNERATED",
    }
}

pub fn tab_model_to_info(tab: tabs::Model) -> ServiceResult<TabInfo> {
    let tab_id = U256::from_str(&tab.id)
        .map_err(|e| ServiceError::Other(anyhow!("invalid tab id {}: {e}", tab.id)))?;
    let status = tab_status_to_str(tab.status).to_string();
    let settlement_status = settlement_status_to_str(tab.settlement_status).to_string();

    let start_timestamp = tab.start_ts.and_utc().timestamp();
    let created_at = tab.created_at.and_utc().timestamp();
    let updated_at = tab.updated_at.and_utc().timestamp();

    Ok(TabInfo {
        tab_id,
        user_address: tab.user_address,
        recipient_address: tab.server_address,
        asset_address: tab.asset_address,
        start_timestamp,
        ttl_seconds: tab.ttl,
        status,
        settlement_status,
        created_at,
        updated_at,
    })
}

pub fn guarantee_model_to_info(model: entities::guarantee::Model) -> ServiceResult<GuaranteeInfo> {
    let entities::guarantee::Model {
        tab_id: tab_id_str,
        req_id: req_id_str,
        from_address,
        to_address,
        asset_address,
        value,
        start_ts,
        cert,
        ..
    } = model;

    let tab_id = U256::from_str(&tab_id_str)
        .map_err(|e| ServiceError::Other(anyhow!("invalid tab id {}: {e}", tab_id_str)))?;
    let req_id = U256::from_str(&req_id_str)
        .map_err(|e| ServiceError::Other(anyhow!("invalid req id {}: {e}", req_id_str)))?;
    let amount = U256::from_str(&value)
        .map_err(|e| ServiceError::Other(anyhow!("invalid guarantee amount {}: {e}", value)))?;
    let start_timestamp = start_ts.and_utc().timestamp();
    let certificate = if cert.is_empty() { None } else { Some(cert) };

    Ok(GuaranteeInfo {
        tab_id,
        req_id,
        from_address,
        to_address,
        asset_address,
        amount,
        start_timestamp,
        certificate,
    })
}

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
    let amount = U256::from_str(&model.amount).map_err(|e| {
        ServiceError::Other(anyhow!(
            "invalid collateral event amount {}: {e}",
            model.amount
        ))
    })?;

    let tab_id = match model.tab_id {
        Some(ref id) => Some(U256::from_str(id).map_err(|e| {
            ServiceError::Other(anyhow!("invalid collateral event tab id {}: {e}", id))
        })?),
        None => None,
    };

    let req_id = match model.req_id {
        Some(ref id) => Some(U256::from_str(id).map_err(|e| {
            ServiceError::Other(anyhow!("invalid collateral event req id {}: {e}", id))
        })?),
        None => None,
    };

    Ok(CollateralEventInfo {
        id: model.id,
        user_address: model.user_address,
        asset_address: model.asset_address,
        amount,
        event_type: collateral_event_type_to_str(model.event_type).to_string(),
        tab_id,
        req_id,
        tx_id: model.tx_id,
        created_at: model.created_at.and_utc().timestamp(),
    })
}

pub fn asset_balance_model_to_info(
    model: entities::user_asset_balance::Model,
) -> ServiceResult<AssetBalanceInfo> {
    let total = U256::from_str(&model.total).map_err(|e| {
        ServiceError::Other(anyhow!("invalid asset balance total {}: {e}", model.total))
    })?;
    let locked = U256::from_str(&model.locked).map_err(|e| {
        ServiceError::Other(anyhow!(
            "invalid asset balance locked {}: {e}",
            model.locked
        ))
    })?;

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

pub fn admin_api_key_model_to_info(model: admin_api_key::Model) -> ServiceResult<AdminApiKeyInfo> {
    let scopes: Vec<String> = serde_json::from_value(model.scopes).map_err(|e| {
        ServiceError::Other(anyhow!(
            "invalid scopes for admin api key {}: {e}",
            model.id
        ))
    })?;

    Ok(AdminApiKeyInfo {
        id: model.id.to_string(),
        name: model.name,
        scopes,
        created_at: model.created_at.and_utc().timestamp(),
        revoked_at: model.revoked_at.map(|ts| ts.and_utc().timestamp()),
    })
}

pub fn parse_settlement_statuses(
    statuses: Option<Vec<String>>,
) -> ServiceResult<Vec<SettlementStatus>> {
    fn parse_one(value: &str) -> Option<SettlementStatus> {
        match value.to_ascii_uppercase().as_str() {
            "PENDING" => Some(SettlementStatus::Pending),
            "SETTLED" => Some(SettlementStatus::Settled),
            "FAILED" => Some(SettlementStatus::Failed),
            "REMUNERATED" => Some(SettlementStatus::Remunerated),
            _ => None,
        }
    }

    match statuses {
        Some(values) => {
            let mut parsed = Vec::with_capacity(values.len());
            for value in values {
                match parse_one(&value) {
                    Some(status) => parsed.push(status),
                    None => {
                        return Err(ServiceError::InvalidParams(format!(
                            "invalid settlement status: {}",
                            value
                        )));
                    }
                }
            }
            Ok(parsed)
        }
        None => Ok(Vec::new()),
    }
}
