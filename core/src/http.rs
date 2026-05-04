use crate::auth::{
    access::{self, AccessContext},
    constants::SCOPE_TAB_READ,
};
use crate::{error::ServiceError, service::CoreService};
use alloy_primitives::B256;
use axum::extract::FromRef;
use axum::{
    Json, Router,
    extract::{Extension, Path, Query, Request, State},
    http::HeaderMap,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use crypto::bls::BLSCert;
use entities::sea_orm_active_enums::ParticipantCycleRole;
use http::{StatusCode, header::AUTHORIZATION};
use log::{debug, warn};
use metrics_4mica::http::HttpMetricsMiddleware;
use metrics_exporter_prometheus::PrometheusHandle;
use rpc::{
    AssetBalanceInfo, AuthLogoutRequest, AuthLogoutResponse, AuthNonceRequest, AuthNonceResponse,
    AuthRefreshRequest, AuthRefreshResponse, AuthVerifyRequest, AuthVerifyResponse,
    ClearingParticipantProofResponse, ClearingParticipantRole, ClearingSettlementAction,
    ClearingSettlementActionResponse, CorePublicParameters, PaymentGuaranteeRequest,
    SupportedTokensResponse, UpdateUserSuspensionRequest, UserSuspensionStatus,
    UserTransactionInfo,
};
use serde::Deserialize;

#[derive(Clone)]
pub struct AppState {
    pub service: CoreService,
    pub metrics: PrometheusHandle,
}

impl FromRef<AppState> for CoreService {
    fn from_ref(state: &AppState) -> Self {
        state.service.clone()
    }
}

impl FromRef<AppState> for PrometheusHandle {
    fn from_ref(state: &AppState) -> Self {
        state.metrics.clone()
    }
}

pub fn router(service: CoreService, metrics_recorder: PrometheusHandle) -> Router {
    let state = AppState {
        service,
        metrics: metrics_recorder,
    };

    Router::new()
        .route("/metrics", get(get_metrics))
        .route("/auth/nonce", post(post_auth_nonce))
        .route("/auth/verify", post(post_auth_verify))
        .route("/auth/refresh", post(post_auth_refresh))
        .route("/auth/logout", post(post_auth_logout))
        .route("/core/health", get(get_health))
        .route("/core/public-params", get(get_public_params))
        .route("/core/tokens", get(get_supported_tokens))
        .route("/core/guarantees", post(issue_guarantee))
        .route(
            "/core/cycles/{cycle_id}/participants/{participant}/clearing-proof",
            get(get_clearing_participant_proof),
        )
        .route(
            "/core/cycles/{cycle_id}/participants/{participant}/clearing-action",
            get(get_clearing_participant_action),
        )
        .route(
            "/core/recipients/{recipient_address}/payments",
            get(list_recipient_payments),
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
            state.clone(),
            auth_middleware,
        ))
        .layer(HttpMetricsMiddleware)
        .with_state(state)
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

fn bytes32_hex(value: B256) -> String {
    format!("{value:#x}")
}

fn participant_role_to_response(
    role: ParticipantCycleRole,
) -> Result<ClearingParticipantRole, ApiError> {
    match role {
        ParticipantCycleRole::NetDebtor => Ok(ClearingParticipantRole::NetDebtor),
        ParticipantCycleRole::NetCreditor => Ok(ClearingParticipantRole::NetCreditor),
        ParticipantCycleRole::Flat => Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "flat participants do not have a clearing proof",
        )),
    }
}

#[derive(Debug, Deserialize)]
struct ClearingActionQuery {
    action: ClearingSettlementAction,
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
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let claims = service.validate_access_token(token).map_err(|err| {
        warn!(
            "auth token denied: method={}, path={}, error={}",
            method, path, err
        );
        ApiError::from(err)
    })?;
    debug!(
        "auth token accepted: method={}, path={}, wallet={}, role={}, scopes={:?}",
        method, path, claims.sub, claims.role, claims.scopes
    );

    req.extensions_mut().insert(AccessContext {
        wallet_address: claims.sub,
        role: claims.role,
        scopes: claims.scopes,
    });

    Ok(next.run(req).await)
}

fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/auth" | "/core/health" | "/core/public-params" | "/core/tokens" | "/metrics"
    ) || path.starts_with("/auth/")
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

async fn get_metrics(State(metrics): State<PrometheusHandle>) -> Result<String, ApiError> {
    Ok(metrics.render())
}

async fn get_public_params(
    State(service): State<CoreService>,
) -> Result<Json<CorePublicParameters>, ApiError> {
    Ok(Json(service.public_params()))
}

async fn get_supported_tokens(
    State(service): State<CoreService>,
) -> Result<Json<SupportedTokensResponse>, ApiError> {
    let tokens = service.get_supported_tokens().await?;
    Ok(Json(tokens))
}

async fn get_clearing_participant_proof(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path((cycle_id, participant)): Path<(String, String)>,
) -> Result<Json<ClearingParticipantProofResponse>, ApiError> {
    access::require_scope(&auth, SCOPE_TAB_READ)?;
    if !access::addresses_match(&auth.wallet_address, &participant)
        && access::require_admin_role(&auth).is_err()
        && access::require_facilitator_role(&auth).is_err()
    {
        return Err(ApiError::from(ServiceError::Unauthorized(
            "participant proof access denied".to_string(),
        )));
    }

    let proof = service
        .get_participant_clearing_proof(&cycle_id, &participant)
        .await?;
    Ok(Json(clearing_proof_response(proof)?))
}

async fn get_clearing_participant_action(
    State(service): State<CoreService>,
    Extension(auth): Extension<AccessContext>,
    Path((cycle_id, participant)): Path<(String, String)>,
    Query(query): Query<ClearingActionQuery>,
) -> Result<Json<ClearingSettlementActionResponse>, ApiError> {
    access::require_scope(&auth, SCOPE_TAB_READ)?;
    if query.action != ClearingSettlementAction::MarkDefaulted
        && !access::addresses_match(&auth.wallet_address, &participant)
        && access::require_admin_role(&auth).is_err()
        && access::require_facilitator_role(&auth).is_err()
    {
        return Err(ApiError::from(ServiceError::Unauthorized(
            "participant clearing action access denied".to_string(),
        )));
    }

    let proof = service
        .get_participant_clearing_proof(&cycle_id, &participant)
        .await?;
    let contract_address = service.clearing_house_address();
    Ok(Json(clearing_action_response(
        contract_address,
        query.action,
        proof,
    )?))
}

fn clearing_proof_response(
    proof: crate::service::netting::ClearingParticipantProof,
) -> Result<ClearingParticipantProofResponse, ApiError> {
    let role = participant_role_to_response(proof.role.clone())?;
    Ok(ClearingParticipantProofResponse {
        cycle_id: bytes32_hex(proof.cycle_id),
        cycle_id_text: proof.cycle_id_text,
        asset_address: proof.asset_address.to_string(),
        participant: proof.participant.to_string(),
        role,
        amount: proof.amount.to_string(),
        net_debit: proof.net_debit.to_string(),
        net_credit: proof.net_credit.to_string(),
        leaf: bytes32_hex(proof.leaf),
        merkle_root: bytes32_hex(proof.merkle_root),
        proof: proof.proof.into_iter().map(bytes32_hex).collect(),
    })
}

fn clearing_action_response(
    contract_address: String,
    action: ClearingSettlementAction,
    proof: crate::service::netting::ClearingParticipantProof,
) -> Result<ClearingSettlementActionResponse, ApiError> {
    let role = participant_role_to_response(proof.role)?;
    let (required_role, function_name, debtor) = match action {
        ClearingSettlementAction::PayNetDebit => {
            (ClearingParticipantRole::NetDebtor, "payNetDebit", None)
        }
        ClearingSettlementAction::ClaimNetCredit => {
            (ClearingParticipantRole::NetCreditor, "claimNetCredit", None)
        }
        ClearingSettlementAction::MarkDefaulted => (
            ClearingParticipantRole::NetDebtor,
            "markDefaulted",
            Some(proof.participant.to_string()),
        ),
    };
    if role != required_role {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("{function_name} requires participant role {required_role:?}"),
        ));
    }

    let payable_value = if action == ClearingSettlementAction::PayNetDebit
        && proof.asset_address == alloy_primitives::Address::ZERO
    {
        proof.amount.to_string()
    } else {
        "0".to_string()
    };

    Ok(ClearingSettlementActionResponse {
        contract_address,
        function_name: function_name.to_string(),
        action,
        cycle_id: bytes32_hex(proof.cycle_id),
        cycle_id_text: proof.cycle_id_text,
        asset_address: proof.asset_address.to_string(),
        participant: proof.participant.to_string(),
        debtor,
        amount: proof.amount.to_string(),
        payable_value,
        proof: proof.proof.into_iter().map(bytes32_hex).collect(),
    })
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

async fn get_health(State(service): State<CoreService>) -> Result<impl IntoResponse, ApiError> {
    let report = service.run_health_checks().await;
    let status = if report.is_healthy() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    Ok((status, Json(report)))
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
