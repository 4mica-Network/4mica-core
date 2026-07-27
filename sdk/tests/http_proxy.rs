use alloy::primitives::{B256, U256};
use axum::{Json, Router, routing::get};
use crypto::bls::{BLSCert, BlsClaims, KeyMaterial};
use rpc::{
    CorePublicParameters, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims, RpcProxy,
    SigningScheme, ValidationRequirement,
};
use serde_json::json;
use std::str::FromStr;
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
#[serial_test::file_serial]
async fn rpc_proxy_get_public_params_round_trip() {
    let params = CorePublicParameters {
        public_key: vec![1, 2, 3],
        contract_address: "0x1234567890abcdef1234567890abcdef12345678".into(),
        ethereum_http_rpc_url: "http://localhost:8545".into(),
        eip712_name: "4mica".into(),
        eip712_version: "1".into(),
        chain_id: 1337,
        supported_guarantee_versions: vec![1],
        guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
        validators: vec![],
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
#[serial_test::file_serial]
async fn rpc_proxy_surfaces_api_errors() {
    let router = Router::new().route(
        "/core/public-params",
        get(|| async {
            (
                axum::http::StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid request"})),
            )
        }),
    );
    let Ok((base, handle)) = spawn_router(router).await else {
        eprintln!("skipping test: failed to bind local port");
        return;
    };

    let proxy = RpcProxy::new(&base).expect("create proxy");
    let err = proxy
        .get_public_params()
        .await
        .expect_err("expected API error");
    match err {
        rpc::ApiClientError::Api { status, message } => {
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
            assert!(
                message.contains("invalid request"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    handle.abort();
}

#[tokio::test]
#[serial_test::file_serial]
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

#[tokio::test]
#[serial_test::file_serial]
async fn rpc_proxy_get_public_params_round_trip_validation_metadata() {
    let params = CorePublicParameters {
        public_key: vec![7, 8, 9],
        contract_address: "0x1234567890abcdef1234567890abcdef12345678".into(),
        ethereum_http_rpc_url: "http://localhost:8545".into(),
        eip712_name: "4mica".into(),
        eip712_version: "1".into(),
        chain_id: 84532,
        supported_guarantee_versions: vec![1],
        guarantee_domain_separator:
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        validators: vec![
            "eip155:84532:0x1111111111111111111111111111111111111111".into(),
            "https://validator.acme.io/checks".into(),
        ],
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
    assert_eq!(got.supported_guarantee_versions, vec![1]);
    assert_eq!(
        got.guarantee_domain_separator,
        params.guarantee_domain_separator
    );
    assert_eq!(got.validators, params.validators);

    handle.abort();
}

fn build_test_bls_cert() -> BLSCert {
    let key =
        KeyMaterial::from_str("0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3")
            .expect("valid test key");
    BLSCert::sign(&key, BlsClaims::from_bytes(vec![0x01, 0x02, 0x03])).expect("valid cert")
}

fn build_validated_request() -> PaymentGuaranteeRequest {
    let claims = PaymentGuaranteeRequestClaims::new(
        "0x1234567890123456789012345678901234567890".to_string(),
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
        U256::from(3u64),
        U256::from(100u64),
        1_736_000_000,
        None,
    )
    .with_validation(ValidationRequirement {
        validator: "eip155:84532:0x1111111111111111111111111111111111111111".to_string(),
        subject: B256::repeat_byte(0x11),
        deadline: Some(1_736_003_600),
        params: vec![0x0a, 0x0b].into(),
    });

    PaymentGuaranteeRequest::new(claims, "0x1234".to_string(), SigningScheme::Eip712)
}

#[tokio::test]
#[serial_test::file_serial]
async fn rpc_proxy_issue_guarantee_round_trip_validated_request() {
    let expected = build_validated_request();
    let cert = build_test_bls_cert();

    let router = Router::new().route(
        "/core/guarantees",
        axum::routing::post({
            let cert = cert.clone();
            let expected = expected.clone();
            move |Json(body): Json<PaymentGuaranteeRequest>| {
                let cert = cert.clone();
                let expected = expected.clone();
                async move {
                    assert_eq!(body.claims, expected.claims);
                    Json(cert)
                }
            }
        }),
    );

    let Ok((base, handle)) = spawn_router(router).await else {
        eprintln!("skipping test: failed to bind local port");
        return;
    };

    let proxy = RpcProxy::new(&base).expect("create proxy");
    let got = proxy
        .issue_guarantee(expected.clone())
        .await
        .expect("issue guarantee");
    assert_eq!(got.claims().to_hex(), cert.claims().to_hex());
    assert_eq!(got.signature().to_hex(), cert.signature().to_hex());

    handle.abort();
}
