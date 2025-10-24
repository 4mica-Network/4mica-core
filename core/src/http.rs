use std::{str::FromStr, sync::Arc};

use crate::{error::ServiceError, service::CoreService};
use alloy_primitives::U256;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use crypto::bls::BLSCert;
use entities::sea_orm_active_enums::SettlementStatus;
use http::StatusCode;
use rpc::{
    common::{
        AssetBalanceInfo, CollateralEventInfo, CreatePaymentTabRequest, CreatePaymentTabResult,
        GuaranteeInfo, PaymentGuaranteeRequest, PendingRemunerationInfo, TabInfo,
        UserTransactionInfo,
    },
    core::CorePublicParameters,
};

type SharedService = Arc<CoreService>;

pub fn router(service: CoreService) -> Router {
    let shared = Arc::new(service);
    Router::new()
        .route("/core/public-params", get(get_public_params))
        .route("/core/payment-tabs", post(create_payment_tab))
        .route("/core/guarantees", post(issue_guarantee))
        .route(
            "/core/recipients/:recipient_address/settled-tabs",
            get(list_settled_tabs),
        )
        .route(
            "/core/recipients/:recipient_address/pending-remunerations",
            get(list_pending_remunerations),
        )
        .route("/core/tabs/:tab_id", get(get_tab))
        .route(
            "/core/recipients/:recipient_address/tabs",
            get(list_recipient_tabs),
        )
        .route("/core/tabs/:tab_id/guarantees", get(get_tab_guarantees))
        .route(
            "/core/tabs/:tab_id/guarantees/latest",
            get(get_latest_guarantee),
        )
        .route(
            "/core/tabs/:tab_id/guarantees/:req_id",
            get(get_specific_guarantee),
        )
        .route(
            "/core/recipients/:recipient_address/payments",
            get(list_recipient_payments),
        )
        .route(
            "/core/tabs/:tab_id/collateral-events",
            get(get_collateral_events_for_tab),
        )
        .route(
            "/core/users/:user_address/assets/:asset_address",
            get(get_user_asset_balance),
        )
        .with_state(shared)
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({ "error": self.message }));
        (self.status, body).into_response()
    }
}

impl From<ServiceError> for ApiError {
    fn from(err: ServiceError) -> Self {
        match err {
            ServiceError::InvalidParams(msg) => ApiError::new(StatusCode::BAD_REQUEST, msg),
            ServiceError::NotFound(msg) => ApiError::new(StatusCode::NOT_FOUND, msg),
            ServiceError::OptimisticLockConflict => {
                ApiError::new(StatusCode::CONFLICT, "optimistic lock conflict")
            }
            ServiceError::UserNotRegistered => {
                ApiError::new(StatusCode::BAD_REQUEST, "user not registered")
            }
            ServiceError::TabClosed => ApiError::new(StatusCode::CONFLICT, "tab already closed"),
            ServiceError::FutureTimestamp => {
                ApiError::new(StatusCode::BAD_REQUEST, "timestamp is in the future")
            }
            ServiceError::InvalidRequestID => {
                ApiError::new(StatusCode::BAD_REQUEST, "req_id not valid")
            }
            ServiceError::ModifiedStartTs => {
                ApiError::new(StatusCode::BAD_REQUEST, "start timestamp modified")
            }
            ServiceError::Db(e) => {
                log::error!("database error: {e}");
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
            ServiceError::Other(e) => {
                log::error!("internal error: {e:#}");
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
        }
    }
}

fn parse_u256(value: &str) -> Result<U256, ApiError> {
    U256::from_str(value).map_err(|e| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("invalid 256-bit value {value}: {e}"),
        )
    })
}

async fn get_public_params(
    State(service): State<SharedService>,
) -> Result<Json<CorePublicParameters>, ApiError> {
    Ok(Json(service.public_params()))
}

async fn issue_guarantee(
    State(service): State<SharedService>,
    Json(req): Json<PaymentGuaranteeRequest>,
) -> Result<Json<BLSCert>, ApiError> {
    let cert = service.handle_promise(req).await.map_err(ApiError::from)?;
    Ok(Json(cert))
}

async fn create_payment_tab(
    State(service): State<SharedService>,
    Json(req): Json<CreatePaymentTabRequest>,
) -> Result<Json<CreatePaymentTabResult>, ApiError> {
    let result = service
        .create_payment_tab(req)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(result))
}

async fn list_settled_tabs(
    State(service): State<SharedService>,
    Path(recipient): Path<String>,
) -> Result<Json<Vec<TabInfo>>, ApiError> {
    let tabs = service
        .list_tabs_for_recipient(recipient, vec![SettlementStatus::Settled])
        .await
        .map_err(ApiError::from)?;
    Ok(Json(tabs))
}

async fn list_pending_remunerations(
    State(service): State<SharedService>,
    Path(recipient): Path<String>,
) -> Result<Json<Vec<PendingRemunerationInfo>>, ApiError> {
    let items = service
        .list_pending_remunerations(recipient)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(items))
}

async fn get_tab(
    State(service): State<SharedService>,
    Path(tab_id): Path<String>,
) -> Result<Json<Option<TabInfo>>, ApiError> {
    let tab_id = parse_u256(&tab_id)?;
    let tab = service.get_tab(tab_id).await.map_err(ApiError::from)?;
    Ok(Json(tab))
}

#[cfg(test)]
mod tests {}

async fn list_recipient_tabs(
    State(service): State<SharedService>,
    Path(recipient): Path<String>,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<Vec<TabInfo>>, ApiError> {
    let statuses: Vec<String> = params
        .into_iter()
        .filter_map(|(key, value)| {
            if key == "settlement_status" {
                Some(value)
            } else {
                None
            }
        })
        .collect();

    let parsed = if statuses.is_empty() {
        Vec::new()
    } else {
        CoreService::parse_settlement_statuses(Some(statuses)).map_err(ApiError::from)?
    };
    let tabs = service
        .list_tabs_for_recipient(recipient, parsed)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(tabs))
}

async fn get_tab_guarantees(
    State(service): State<SharedService>,
    Path(tab_id): Path<String>,
) -> Result<Json<Vec<GuaranteeInfo>>, ApiError> {
    let tab_id = parse_u256(&tab_id)?;
    let guarantees = service
        .get_tab_guarantees(tab_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(guarantees))
}

async fn get_latest_guarantee(
    State(service): State<SharedService>,
    Path(tab_id): Path<String>,
) -> Result<Json<Option<GuaranteeInfo>>, ApiError> {
    let tab_id = parse_u256(&tab_id)?;
    let guarantee = service
        .get_latest_guarantee(tab_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(guarantee))
}

async fn get_specific_guarantee(
    State(service): State<SharedService>,
    Path((tab_id, req_id)): Path<(String, String)>,
) -> Result<Json<Option<GuaranteeInfo>>, ApiError> {
    let tab_id = parse_u256(&tab_id)?;
    let req_id = parse_u256(&req_id)?;
    let guarantee = service
        .get_guarantee(tab_id, req_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(guarantee))
}

async fn list_recipient_payments(
    State(service): State<SharedService>,
    Path(recipient): Path<String>,
) -> Result<Json<Vec<UserTransactionInfo>>, ApiError> {
    let payments = service
        .list_recipient_payments(recipient)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(payments))
}

async fn get_collateral_events_for_tab(
    State(service): State<SharedService>,
    Path(tab_id): Path<String>,
) -> Result<Json<Vec<CollateralEventInfo>>, ApiError> {
    let tab_id = parse_u256(&tab_id)?;
    let events = service
        .get_collateral_events_for_tab(tab_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(events))
}

async fn get_user_asset_balance(
    State(service): State<SharedService>,
    Path((user, asset)): Path<(String, String)>,
) -> Result<Json<Option<AssetBalanceInfo>>, ApiError> {
    let balance = service
        .get_user_asset_balance(user, asset)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(balance))
}
