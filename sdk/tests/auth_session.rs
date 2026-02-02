use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::net::TcpListener;
use url::Url;

use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::{AuthConfig, AuthSession};

#[derive(Clone)]
struct AuthTestState {
    refresh_calls: Arc<AtomicUsize>,
    verify_calls: Arc<AtomicUsize>,
    fail_refresh_once: Arc<AtomicBool>,
    verify_expires_in: u64,
    refresh_expires_in: u64,
}

impl AuthTestState {
    fn new(fail_refresh_once: bool, verify_expires_in: u64, refresh_expires_in: u64) -> Self {
        Self {
            refresh_calls: Arc::new(AtomicUsize::new(0)),
            verify_calls: Arc::new(AtomicUsize::new(0)),
            fail_refresh_once: Arc::new(AtomicBool::new(fail_refresh_once)),
            verify_expires_in,
            refresh_expires_in,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AuthNonceRequest {
    address: String,
}

#[derive(Debug, Serialize)]
struct AuthNonceResponse {
    nonce: String,
    siwe: SiweTemplate,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SiweTemplate {
    domain: String,
    uri: String,
    chain_id: u64,
    statement: String,
    expiration: String,
    issued_at: String,
}

#[derive(Debug, Deserialize)]
struct AuthVerifyRequest {
    address: String,
    message: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct AuthRefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Serialize)]
struct AuthTokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

async fn spawn_router(
    router: Router,
) -> Result<(String, tokio::task::JoinHandle<()>), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router.into_make_service()).await {
            eprintln!("test server stopped: {err}");
        }
    });
    Ok((format!("http://{}", addr), handle))
}

fn build_template() -> SiweTemplate {
    SiweTemplate {
        domain: "example.com".to_string(),
        uri: "http://localhost/login".to_string(),
        chain_id: 1,
        statement: "Sign in to tests.".to_string(),
        expiration: "2024-01-01T00:10:00Z".to_string(),
        issued_at: "2024-01-01T00:00:00Z".to_string(),
    }
}

async fn post_auth_nonce(
    State(_state): State<AuthTestState>,
    Json(req): Json<AuthNonceRequest>,
) -> impl IntoResponse {
    if req.address.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "address is required" })),
        )
            .into_response();
    }
    Json(AuthNonceResponse {
        nonce: "nonce-1".to_string(),
        siwe: build_template(),
    })
    .into_response()
}

async fn post_auth_verify(
    State(state): State<AuthTestState>,
    Json(req): Json<AuthVerifyRequest>,
) -> impl IntoResponse {
    if req.address.trim().is_empty()
        || req.message.trim().is_empty()
        || req.signature.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid auth payload" })),
        )
            .into_response();
    }
    let call = state.verify_calls.fetch_add(1, Ordering::SeqCst) + 1;
    Json(AuthTokenResponse {
        access_token: format!("access-verify-{call}"),
        refresh_token: format!("refresh-verify-{call}"),
        expires_in: state.verify_expires_in,
    })
    .into_response()
}

async fn post_auth_refresh(
    State(state): State<AuthTestState>,
    Json(req): Json<AuthRefreshRequest>,
) -> impl IntoResponse {
    if req.refresh_token.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "refresh_token is required" })),
        )
            .into_response();
    }
    let call = state.refresh_calls.fetch_add(1, Ordering::SeqCst) + 1;
    if state.fail_refresh_once.swap(false, Ordering::SeqCst) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid refresh token" })),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(AuthTokenResponse {
            access_token: format!("access-refresh-{call}"),
            refresh_token: format!("refresh-refresh-{call}"),
            expires_in: state.refresh_expires_in,
        }),
    )
        .into_response()
}

#[tokio::test]
#[serial_test::serial]
async fn auth_session_single_flight_refresh() {
    let state = AuthTestState::new(false, 0, 60);
    let router = Router::new()
        .route("/auth/nonce", post(post_auth_nonce))
        .route("/auth/verify", post(post_auth_verify))
        .route("/auth/refresh", post(post_auth_refresh))
        .with_state(state.clone());

    let Ok((base, handle)) = spawn_router(router).await else {
        eprintln!("skipping test: failed to bind local port");
        return;
    };

    let cfg = AuthConfig {
        auth_url: Url::parse(&base).expect("auth url"),
        refresh_margin_secs: 0,
    };
    let signer = PrivateKeySigner::random();
    let session = AuthSession::new(cfg, signer);
    session.login().await.expect("login");

    let session = Arc::new(session);
    let s1 = session.clone();
    let s2 = session.clone();
    let s3 = session.clone();

    let (r1, r2, r3) = tokio::join!(s1.access_token(), s2.access_token(), s3.access_token());
    r1.expect("access token 1");
    r2.expect("access token 2");
    r3.expect("access token 3");

    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);

    handle.abort();
}

#[tokio::test]
#[serial_test::serial]
async fn auth_session_refresh_unauthorized_falls_back_to_login() {
    let state = AuthTestState::new(true, 0, 60);
    let router = Router::new()
        .route("/auth/nonce", post(post_auth_nonce))
        .route("/auth/verify", post(post_auth_verify))
        .route("/auth/refresh", post(post_auth_refresh))
        .with_state(state.clone());

    let Ok((base, handle)) = spawn_router(router).await else {
        eprintln!("skipping test: failed to bind local port");
        return;
    };

    let cfg = AuthConfig {
        auth_url: Url::parse(&base).expect("auth url"),
        refresh_margin_secs: 0,
    };
    let signer = PrivateKeySigner::random();
    let session = AuthSession::new(cfg, signer);
    session.login().await.expect("login");

    let token = session.access_token().await.expect("access token");
    assert!(!token.is_empty());
    assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
    assert_eq!(state.verify_calls.load(Ordering::SeqCst), 2);

    handle.abort();
}
