use crate::auth::access::{self, AccessContext};
use crate::{error::ServiceError, persist::mapper, service::CoreService};
use alloy_primitives::U256;
use axum::{
    Json, Router,
    extract::{Extension, Path, Query, Request, State},
    http::HeaderMap,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use crypto::bls::BLSCert;
use entities::sea_orm_active_enums::SettlementStatus;
use http::{StatusCode, header::AUTHORIZATION};
use rpc::{
    AssetBalanceInfo, AuthLogoutRequest, AuthLogoutResponse, AuthNonceRequest, AuthNonceResponse,
    AuthRefreshRequest, AuthRefreshResponse, AuthVerifyRequest, AuthVerifyResponse,
    CollateralEventInfo, CorePublicParameters, CreatePaymentTabRequest, CreatePaymentTabResult,
    GuaranteeInfo, PaymentGuaranteeRequest, PendingRemunerationInfo, TabInfo,
    UpdateUserSuspensionRequest, UserSuspensionStatus, UserTransactionInfo,
};
use std::str::FromStr;

pub fn router(service: CoreService) -> Router {
    Router::new()
        .route("/auth/nonce", post(post_auth_nonce))
        .route("/auth/verify", post(post_auth_verify))
        .route("/auth/refresh", post(post_auth_refresh))
        .route("/auth/logout", post(post_auth_logout))
        .route("/core/health", get(get_health))
        .route("/core/public-params", get(get_public_params))
        .route("/core/payment-tabs", post(create_payment_tab))
        .route("/core/guarantees", post(issue_guarantee))
        .route(
            "/core/recipients/{recipient_address}/settled-tabs",
            get(list_settled_tabs),
        )
        .route(
            "/core/recipients/{recipient_address}/pending-remunerations",
            get(list_pending_remunerations),
        )
        .route("/core/tabs/{tab_id}", get(get_tab))
        .route(
            "/core/recipients/{recipient_address}/tabs",
            get(list_recipient_tabs),
        )
        .route("/core/tabs/{tab_id}/guarantees", get(get_tab_guarantees))
        .route(
            "/core/tabs/{tab_id}/guarantees/latest",
            get(get_latest_guarantee),
        )
        .route(
            "/core/tabs/{tab_id}/guarantees/{req_id}",
            get(get_specific_guarantee),
        )
        .route(
            "/core/recipients/{recipient_address}/payments",
            get(list_recipient_payments),
        )
        .route(
            "/core/tabs/{tab_id}/collateral-events",
            get(get_collateral_events_for_tab),
        )
        .route(
            "/core/users/{user_address}/assets/{asset_address}",
            get(get_user_asset_balance),
        )
        .route(
            "/core/users/{user_address}/suspension",
            post(update_user_suspension),
        )
        .layer(middleware::from_fn_with_state(
            service.clone(),
            auth_middleware,
        ))
        .with_state(service)
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
                ApiError::new(StatusCode::CONFLICT, "request failed, please retry")
            }
            ServiceError::UserNotRegistered => {
                ApiError::new(StatusCode::BAD_REQUEST, "user not registered")
            }
            ServiceError::UserSuspended => ApiError::new(StatusCode::FORBIDDEN, "user suspended"),
            ServiceError::TabClosed => ApiError::new(StatusCode::CONFLICT, "tab already closed"),
            ServiceError::Unauthorized(msg) => ApiError::new(StatusCode::UNAUTHORIZED, msg),
            ServiceError::FutureTimestamp => {
                ApiError::new(StatusCode::BAD_REQUEST, "timestamp is in the future")
            }
            ServiceError::InvalidRequestID => {
                ApiError::new(StatusCode::BAD_REQUEST, "req_id not valid")
            }
            ServiceError::DuplicateGuarantee { req_id } => ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("another guarantee with req_id {req_id} already exists"),
            ),
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

async fn auth_middleware(
    State(service): State<CoreService>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if is_public_path(req.uri().path()) {
        return Ok(next.run(req).await);
    }

    let token = bearer_token(req.headers())?;
    let claims = service.validate_access_token(token)?;

    req.extensions_mut().insert(AccessContext {
        wallet_address: claims.sub,
        role: claims.role,
        scopes: claims.scopes,
    });

    Ok(next.run(req).await)
}

fn is_public_path(path: &str) -> bool {
    if matches!(path, "/core/health" | "/core/public-params") {
        return true;
    }
    path == "/auth" || path.starts_with("/auth/")
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "missing authorization"))?;

    let value = value.trim();
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid authorization"))?;

    if token.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "missing bearer token",
        ));
    }

    Ok(token)
}

async fn get_public_params(
    State(service): State<CoreService>,
) -> Result<Json<CorePublicParameters>, ApiError> {
    Ok(Json(service.public_params()))
}

async fn post_auth_nonce(
    State(service): State<CoreService>,
    Json(req): Json<AuthNonceRequest>,
) -> Result<Json<AuthNonceResponse>, ApiError> {
    let res = service.create_auth_nonce(req).await?;
    Ok(Json(res))
}

async fn post_auth_verify(
    State(service): State<CoreService>,
    Json(req): Json<AuthVerifyRequest>,
) -> Result<Json<AuthVerifyResponse>, ApiError> {
    let res = service.verify_auth(req).await?;
    Ok(Json(res))
}

async fn post_auth_refresh(
    State(service): State<CoreService>,
    Json(req): Json<AuthRefreshRequest>,
) -> Result<Json<AuthRefreshResponse>, ApiError> {
    let res = service.refresh_auth(req).await?;
    Ok(Json(res))
}

async fn post_auth_logout(
    State(service): State<CoreService>,
    Json(req): Json<AuthLogoutRequest>,
) -> Result<Json<AuthLogoutResponse>, ApiError> {
    let res = service.logout_auth(req).await?;
    Ok(Json(res))
}

async fn get_health(
    State(_service): State<CoreService>,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

async fn issue_guarantee(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Json(req): Json<PaymentGuaranteeRequest>,
) -> Result<Json<BLSCert>, ApiError> {
    let cert = service
        .issue_payment_guarantee(&auth, req)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(cert))
}

async fn create_payment_tab(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Json(req): Json<CreatePaymentTabRequest>,
) -> Result<Json<CreatePaymentTabResult>, ApiError> {
    let result = service
        .create_payment_tab(&auth, req)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(result))
}

async fn list_settled_tabs(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path(recipient): Path<String>,
) -> Result<Json<Vec<TabInfo>>, ApiError> {
    // Treat Remunerated as a settled state for API consumers.
    let tabs = service
        .list_tabs_for_recipient(
            &auth,
            recipient,
            &[SettlementStatus::Settled, SettlementStatus::Remunerated],
        )
        .await
        .map_err(ApiError::from)?;
    Ok(Json(tabs))
}

async fn list_pending_remunerations(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path(recipient): Path<String>,
) -> Result<Json<Vec<PendingRemunerationInfo>>, ApiError> {
    let items = service
        .list_pending_remunerations(&auth, recipient)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(items))
}

async fn get_tab(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path(tab_id): Path<String>,
) -> Result<Json<Option<TabInfo>>, ApiError> {
    let tab_id = parse_u256(&tab_id)?;
    let tab = service
        .get_tab(&auth, tab_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(tab))
}

async fn list_recipient_tabs(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
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

    let parsed = mapper::parse_settlement_statuses(&statuses).map_err(ApiError::from)?;
    let tabs = service
        .list_tabs_for_recipient(&auth, recipient, &parsed)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(tabs))
}

async fn get_tab_guarantees(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path(tab_id): Path<String>,
) -> Result<Json<Vec<GuaranteeInfo>>, ApiError> {
    let tab_id = parse_u256(&tab_id)?;
    let guarantees = service
        .get_tab_guarantees(&auth, tab_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(guarantees))
}

async fn get_latest_guarantee(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path(tab_id): Path<String>,
) -> Result<Json<Option<GuaranteeInfo>>, ApiError> {
    let tab_id = parse_u256(&tab_id)?;
    let guarantee = service
        .get_latest_guarantee(&auth, tab_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(guarantee))
}

async fn get_specific_guarantee(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path((tab_id, req_id)): Path<(String, String)>,
) -> Result<Json<Option<GuaranteeInfo>>, ApiError> {
    let tab_id = parse_u256(&tab_id)?;
    let req_id = parse_u256(&req_id)?;
    let guarantee = service
        .get_guarantee(&auth, tab_id, req_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(guarantee))
}

async fn list_recipient_payments(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path(recipient): Path<String>,
) -> Result<Json<Vec<UserTransactionInfo>>, ApiError> {
    let payments = service
        .list_recipient_payments(&auth, recipient)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(payments))
}

async fn get_collateral_events_for_tab(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path(tab_id): Path<String>,
) -> Result<Json<Vec<CollateralEventInfo>>, ApiError> {
    let tab_id = parse_u256(&tab_id)?;
    let events = service
        .get_collateral_events_for_tab(&auth, tab_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(events))
}

async fn get_user_asset_balance(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path((user, asset)): Path<(String, String)>,
) -> Result<Json<Option<AssetBalanceInfo>>, ApiError> {
    let balance = service
        .get_user_asset_balance(&auth, user, asset)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(balance))
}

async fn update_user_suspension(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path(user): Path<String>,
    Json(req): Json<UpdateUserSuspensionRequest>,
) -> Result<Json<UserSuspensionStatus>, ApiError> {
    access::require_admin_role(&auth)?;
    let status = service
        .set_user_suspension(user, req.suspended)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(status))
}
