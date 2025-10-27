use axum::{Json, Router, routing::get};
use rpc::{RpcProxy, core::CorePublicParameters};
use serde_json::json;
use tokio::net::TcpListener;

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

#[tokio::test]
async fn rpc_proxy_get_public_params_round_trip() {
    let params = CorePublicParameters {
        public_key: vec![1, 2, 3],
        contract_address: "0x1234567890abcdef1234567890abcdef12345678".into(),
        ethereum_http_rpc_url: "http://localhost:8545".into(),
        eip712_name: "4mica".into(),
        eip712_version: "1".into(),
        chain_id: 1337,
    };

    let router = Router::new().route(
        "/core/public-params",
        get({
            let params = params.clone();
            move || {
                let params = params.clone();
                async move { Json(params) }
            }
        }),
    );
    let Ok((base, handle)) = spawn_router(router).await else {
        eprintln!("skipping test: failed to bind local port");
        return;
    };

    let proxy = RpcProxy::new(&base).expect("create proxy");
    let got = proxy.get_public_params().await.expect("get params");
    assert_eq!(got.chain_id, 1337);
    assert_eq!(got.contract_address, params.contract_address);

    handle.abort();
}

#[tokio::test]
async fn rpc_proxy_surfaces_api_errors() {
    let router = Router::new().route(
        "/core/recipients/{recipient}/tabs",
        get(|| async {
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid settlement status: unknown"})),
            )
        }),
    );
    let Ok((base, handle)) = spawn_router(router).await else {
        eprintln!("skipping test: failed to bind local port");
        return;
    };

    let proxy = RpcProxy::new(&base).expect("create proxy");
    let err = proxy
        .list_recipient_tabs("0xdeadbeef".into(), Some(vec!["unknown".into()]))
        .await
        .expect_err("expected API error");
    match err {
        rpc::ApiClientError::Api { status, message } => {
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
            assert!(
                message.contains("invalid settlement status"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    handle.abort();
}

#[tokio::test]
async fn rpc_proxy_returns_decode_error_on_invalid_json() {
    let router = Router::new().route(
        "/core/public-params",
        get(|| async { (axum::http::StatusCode::OK, "not-json") }),
    );
    let Ok((base, handle)) = spawn_router(router).await else {
        eprintln!("skipping test: failed to bind local port");
        return;
    };

    let proxy = RpcProxy::new(&base).expect("create proxy");
    let err = proxy
        .get_public_params()
        .await
        .expect_err("expected decode error");
    assert!(matches!(err, rpc::ApiClientError::Decode(_)));
    assert!(err.status().is_none());

    handle.abort();
}
