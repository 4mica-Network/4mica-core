use alloy::primitives::{Address, B256, U256};
use axum::{Json, Router, routing::get};
use crypto::bls::{BLSCert, BlsClaims, KeyMaterial};
use rpc::{
    CorePublicParameters, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestClaimsV2, PaymentGuaranteeValidationPolicyV2, RpcProxy, SigningScheme,
    compute_validation_request_hash, compute_validation_subject_hash,
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
#[serial_test::serial]
async fn rpc_proxy_get_public_params_round_trip() {
    let params = CorePublicParameters {
        public_key: vec![1, 2, 3],
        contract_address: "0x1234567890abcdef1234567890abcdef12345678".into(),
        ethereum_http_rpc_url: "http://localhost:8545".into(),
        eip712_name: "4mica".into(),
        eip712_version: "1".into(),
        chain_id: 1337,
        active_guarantee_version: 1,
        accepted_guarantee_versions: vec![1],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
        trusted_validation_registries: vec![],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V1".into(),
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
#[serial_test::serial]
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
#[serial_test::serial]
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
#[serial_test::serial]
async fn rpc_proxy_get_public_params_round_trip_v2_metadata() {
    let params = CorePublicParameters {
        public_key: vec![7, 8, 9],
        contract_address: "0x1234567890abcdef1234567890abcdef12345678".into(),
        ethereum_http_rpc_url: "http://localhost:8545".into(),
        eip712_name: "4mica".into(),
        eip712_version: "1".into(),
        chain_id: 84532,
        active_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        trusted_validation_registries: vec![
            "0x1111111111111111111111111111111111111111".into(),
            "0x2222222222222222222222222222222222222222".into(),
        ],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V1".into(),
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
    assert_eq!(got.active_guarantee_version, 2);
    assert_eq!(
        got.active_guarantee_domain_separator,
        params.active_guarantee_domain_separator
    );
    assert_eq!(
        got.validation_hash_canonicalization_version,
        "4MICA_VALIDATION_REQUEST_V1"
    );
    assert_eq!(
        got.trusted_validation_registries,
        params.trusted_validation_registries
    );

    handle.abort();
}

fn build_test_bls_cert() -> BLSCert {
    let key =
        KeyMaterial::from_str("0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3")
            .expect("valid test key");
    BLSCert::sign(&key, BlsClaims::from_bytes(vec![0x01, 0x02, 0x03])).expect("valid cert")
}

fn build_v2_request() -> PaymentGuaranteeRequest {
    let user = "0x1234567890123456789012345678901234567890";
    let recipient = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let asset = "0x0000000000000000000000000000000000000000";
    let tab_id = U256::from(7u64);
    let req_id = U256::from(3u64);
    let amount = U256::from(100u64);
    let timestamp = 1_736_000_000u64;

    let validation_subject_hash =
        compute_validation_subject_hash(user, recipient, tab_id, req_id, amount, asset, timestamp)
            .expect("subject hash");
    let mut policy = PaymentGuaranteeValidationPolicyV2 {
        validation_registry_address: Address::from_str(
            "0x1111111111111111111111111111111111111111",
        )
        .expect("registry"),
        validation_request_hash: B256::ZERO,
        validation_chain_id: 84532,
        validator_address: Address::from_str("0x2222222222222222222222222222222222222222")
            .expect("validator"),
        validator_agent_id: U256::from(99u64),
        min_validation_score: 80,
        validation_subject_hash: B256::from(validation_subject_hash),
        required_validation_tag: "hard-finality".to_string(),
    };
    policy.validation_request_hash =
        B256::from(compute_validation_request_hash(&policy).expect("request hash"));

    let claims = PaymentGuaranteeRequestClaims::V2(PaymentGuaranteeRequestClaimsV2 {
        user_address: user.to_string(),
        recipient_address: recipient.to_string(),
        tab_id,
        req_id,
        amount,
        asset_address: asset.to_string(),
        timestamp,
        validation_policy: policy,
    });

    PaymentGuaranteeRequest::new(claims, "0x1234".to_string(), SigningScheme::Eip712)
}

#[tokio::test]
#[serial_test::serial]
async fn rpc_proxy_issue_guarantee_round_trip_v2_request() {
    let expected = build_v2_request();
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
                    match body.claims {
                        PaymentGuaranteeRequestClaims::V2(claims) => {
                            let PaymentGuaranteeRequestClaims::V2(expected_claims) =
                                expected.claims.clone()
                            else {
                                panic!("expected v2 claims");
                            };
                            assert_eq!(claims.tab_id, expected_claims.tab_id);
                            assert_eq!(claims.req_id, expected_claims.req_id);
                            assert_eq!(
                                claims.validation_policy.validation_request_hash,
                                expected_claims.validation_policy.validation_request_hash
                            );
                        }
                        PaymentGuaranteeRequestClaims::V1(_) => panic!("expected v2 claims"),
                    }
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
