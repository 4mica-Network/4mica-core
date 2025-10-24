use super::*;

#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_future_timestamp() {
    let (_config, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();
    let future_ts = (Utc::now() + Duration::hours(1)).timestamp() as u64;
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(0x7461622d667574757265u128),
        U256::from(0u64),
        U256::from(1u64),
        &wallet,
        Some(future_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject promise with future timestamp");
}

#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_insufficient_collateral() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    insert_user_with_collateral(&ctx, &user_addr, U256::from(1u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        U256::from(0x7461622d6e6f636f6c6c61746572616cu128),
        U256::ZERO,
        U256::from(10u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject when collateral is insufficient");
}

#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_wrong_req_id_sequence() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();

    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await
        .expect("create tab");

    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client.issue_guarantee(req0).await.expect("first ok");

    let req2 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::from(2u64),
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req2).await;
    assert!(result.is_err(), "must reject non-sequential req_id");
}

#[test(tokio::test)]
#[serial]
async fn core_api_guarantee_queries() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    insert_user_with_collateral(&ctx, &user_addr, U256::from(10u64))
        .await;

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(900),
        })
        .await
        .expect("create tab")
        .id;

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        U256::from(5u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    core_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");

    let guarantees = core_client
        .get_tab_guarantees(tab_id)
        .await
        .expect("get tab guarantees");
    assert_eq!(guarantees.len(), 1);
    let guarantee = &guarantees[0];
    assert_eq!(guarantee.tab_id, tab_id);
    assert!(guarantee.certificate.is_some());

    let latest = core_client
        .get_latest_guarantee(tab_id)
        .await
        .expect("latest guarantee")
        .expect("exists");
    assert_eq!(latest.req_id, guarantee.req_id);

    let specific = core_client
        .get_guarantee(tab_id, guarantee.req_id)
        .await
        .expect("specific guarantee")
        .expect("found");
    assert_eq!(specific.amount, guarantee.amount);
}

#[test(tokio::test)]
#[serial]
async fn core_api_guarantee_history_ordering() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    insert_user_with_collateral(&ctx, &user_addr, U256::from(20u64))
        .await;

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(1200),
        })
        .await
        .expect("create tab")
        .id;

    let public_params = core_client.get_public_params().await.unwrap();
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        U256::from(5u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client
        .issue_guarantee(req0)
        .await
        .expect("issue first guarantee");

    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::from(1u64),
        U256::from(7u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client
        .issue_guarantee(req1)
        .await
        .expect("issue second guarantee");

    let guarantees = core_client
        .get_tab_guarantees(tab_id)
        .await
        .expect("get guarantees");
    assert_eq!(guarantees.len(), 2);
    assert_eq!(guarantees[0].req_id, U256::ZERO);
    assert_eq!(guarantees[1].req_id, U256::from(1u64));

    let latest = core_client
        .get_latest_guarantee(tab_id)
        .await
        .expect("latest guarantee")
        .expect("exists");
    assert_eq!(latest.req_id, U256::from(1u64));
    assert_eq!(latest.amount, U256::from(7u64));
}

#[test(tokio::test)]
#[serial]
async fn core_api_guarantee_queries_empty_state() {
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

    let empty_guarantees = core_client
        .get_tab_guarantees(tab_id)
        .await
        .expect("get empty guarantees");
    assert!(empty_guarantees.is_empty());

    let latest = core_client
        .get_latest_guarantee(tab_id)
        .await
        .expect("latest empty");
    assert!(latest.is_none());

    let specific = core_client
        .get_guarantee(tab_id, U256::ZERO)
        .await
        .expect("specific empty");
    assert!(specific.is_none());
}

#[test(tokio::test)]
#[serial]
async fn core_api_pending_remunerations_clear_after_settlement() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    insert_user_with_collateral(&ctx, &user_addr, U256::from(12u64))
        .await;

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(900),
        })
        .await
        .expect("create tab")
        .id;

    let params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        U256::from(3u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");

    let pending = core_client
        .list_pending_remunerations(recipient_addr.clone())
        .await
        .expect("pending rems");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].tab.tab_id, tab_id);

    repo::remunerate_recipient(
        &ctx,
        tab_id,
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(3u64),
    )
    .await
    .expect("remunerate");

    let cleared = core_client
        .list_pending_remunerations(recipient_addr)
        .await
        .expect("pending rems cleared");
    assert!(cleared.is_empty());
}

#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_modified_start_ts() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();
    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await
        .expect("create tab");

    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    let ts0 = req0.claims.timestamp;
    core_client.issue_guarantee(req0).await.expect("first ok");

    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        Some(ts0 + 5),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req1).await;
    assert!(result.is_err(), "must reject modified start timestamp");
}

#[test(tokio::test)]
#[serial]
async fn issue_two_sequential_guarantees_ok() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();
    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(3600),
        })
        .await
        .expect("create tab");
    let tab_id = tab.id;

    let start_ts = chrono::Utc::now().timestamp() as u64;
    let req0 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client.issue_guarantee(req0).await.expect("first ok");

    let req1 = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        Some(start_ts),
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    let cert2 = core_client.issue_guarantee(req1).await.expect("second ok");

    assert!(cert2.verify(&public_params.public_key).unwrap());
    let rows = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(u256_to_string(tab_id)))
        .all(&*ctx.db)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
}

#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_when_tab_not_found() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let public_params = core_client.get_public_params().await.unwrap();
    let tab_id = U256::from_be_bytes(rand::random::<[u8; 32]>());
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject when tab not found");
}

#[test(tokio::test)]
#[serial]
async fn issue_guarantee_should_open_tab() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let tab_result = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await
        .expect("create tab");

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_result.id,
        U256::ZERO,
        U256::ONE,
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    core_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");

    let tab = repo::get_tab_by_id(&ctx, tab_result.id)
        .await
        .expect("get tab")
        .expect("tab exists");
    assert_eq!(tab.status, entities::sea_orm_active_enums::TabStatus::Open);
}

#[test(tokio::test)]
#[serial]
async fn issue_guarantee_accepts_stablecoin_asset() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    insert_user_with_asset_collateral(&ctx, &user_addr, STABLE_ASSET_ADDRESS, U256::from(5u64))
        .await;

    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: Some(STABLE_ASSET_ADDRESS.to_string()),
            ttl: Some(3600),
        })
        .await
        .expect("create tab");

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        STABLE_ASSET_ADDRESS,
    )
    .await;

    let cert = core_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");
    assert!(cert.verify(&public_params.public_key).unwrap());

    let stored = guarantee::Entity::find()
        .filter(guarantee::Column::TabId.eq(u256_to_string(tab.id)))
        .one(&*ctx.db)
        .await
        .expect("query guarantee");
    let guarantee = stored.expect("guarantee stored");
    assert_eq!(guarantee.asset_address, STABLE_ASSET_ADDRESS);
}

#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_mismatched_asset_address() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    insert_user_with_asset_collateral(&ctx, &user_addr, STABLE_ASSET_ADDRESS, U256::from(5u64))
        .await;

    let tab = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: Some(STABLE_ASSET_ADDRESS.to_string()),
            ttl: Some(3600),
        })
        .await
        .expect("create tab");

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab.id,
        U256::ZERO,
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject mismatched asset address");
}

#[test(tokio::test)]
#[serial]
async fn issue_guarantee_rejects_invalid_req_id_when_tab_is_pending() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();
    insert_user_with_collateral(&ctx, &user_addr, U256::from(5u64)).await;

    let tab_result = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: None,
        })
        .await
        .expect("create tab");

    let public_params = core_client.get_public_params().await.unwrap();
    let req = build_signed_req(
        &public_params,
        &user_addr,
        &recipient_addr,
        tab_result.id,
        U256::from(1u64),
        U256::from(1u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;

    let result = core_client.issue_guarantee(req).await;
    assert!(result.is_err(), "must reject if tab is pending");
}
