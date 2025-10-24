use super::*;

#[test(tokio::test)]
#[serial]
async fn core_api_get_tab_and_list_recipient_tabs() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let user_addr = random_address();
    let recipient_addr = random_address();
    common::fixtures::ensure_user(&ctx, &user_addr)
        .await
        .expect("ensure user");

    let create_res = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(600),
        })
        .await
        .expect("create tab");
    let tab_id = create_res.id;

    let fetched = core_client
        .get_tab(tab_id)
        .await
        .expect("get tab")
        .expect("tab exists");
    assert_eq!(fetched.user_address, user_addr);
    assert_eq!(fetched.recipient_address, recipient_addr);
    assert_eq!(fetched.status, "PENDING");
    assert_eq!(fetched.settlement_status, "PENDING");

    let all_tabs = core_client
        .list_recipient_tabs(recipient_addr.clone(), None)
        .await
        .expect("list tabs");
    assert!(all_tabs.iter().any(|t| t.tab_id == tab_id));

    let settled_only = core_client
        .list_recipient_tabs(recipient_addr, Some(vec!["settled".into()]))
        .await
        .expect("filter tabs");
    assert!(settled_only.is_empty());
}

#[test(tokio::test)]
#[serial]
async fn core_api_get_tab_returns_none_for_missing() {
    let (_, core_client, _) = setup_clean_db().await;

    let missing = core_client
        .get_tab(U256::from(999u64))
        .await
        .expect("get missing tab");
    assert!(missing.is_none());
}

#[test(tokio::test)]
#[serial]
async fn core_api_list_recipient_tabs_invalid_status_errors() {
    let (_, core_client, _) = setup_clean_db().await;
    let err = core_client
        .list_recipient_tabs(random_address(), Some(vec!["unknown".into()]))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("invalid settlement status"),
        "unexpected error: {err}"
    );
}

#[test(tokio::test)]
#[serial]
async fn core_api_list_recipient_tabs_case_insensitive_filter() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let user_addr = random_address();
    let recipient_addr = random_address();
    common::fixtures::ensure_user(&ctx, &user_addr)
        .await
        .expect("ensure user");

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(300),
        })
        .await
        .expect("create tab")
        .id;

    let filtered = core_client
        .list_recipient_tabs(
            recipient_addr.clone(),
            Some(vec!["pending".into(), "SETTLED".into()]),
        )
        .await
        .expect("list tabs");
    assert!(filtered.iter().any(|t| t.tab_id == tab_id));

    let empty = core_client
        .list_recipient_tabs(recipient_addr, Some(vec!["failed".into()]))
        .await
        .expect("list tabs failed");
    assert!(empty.is_empty());
}

#[test(tokio::test)]
#[serial]
async fn create_tab_rejects_unregistered_user() {
    let (_, core_client, _) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    let tab_result = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await;
    assert!(tab_result.is_err(), "must reject if user is not registered");
}
