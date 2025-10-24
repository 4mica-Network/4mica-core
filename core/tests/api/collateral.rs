use super::*;
use entities::sea_orm_active_enums::CollateralEventType;

#[test(tokio::test)]
#[serial]
async fn core_api_collateral_events_multiple_types() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    insert_user_with_collateral(&ctx, &user_addr, U256::from(40u64)).await;

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

    let now = Utc::now().naive_utc();
    let unlock_event = collateral_event::ActiveModel {
        id: sea_orm::ActiveValue::Set(Uuid::new_v4().to_string()),
        user_address: sea_orm::ActiveValue::Set(user_addr.clone()),
        asset_address: sea_orm::ActiveValue::Set(DEFAULT_ASSET_ADDRESS.to_string()),
        amount: sea_orm::ActiveValue::Set(U256::from(5u64).to_string()),
        event_type: sea_orm::ActiveValue::Set(CollateralEventType::Unlock),
        tab_id: sea_orm::ActiveValue::Set(Some(u256_to_string(tab_id))),
        req_id: sea_orm::ActiveValue::Set(None),
        tx_id: sea_orm::ActiveValue::Set(None),
        created_at: sea_orm::ActiveValue::Set(now - Duration::minutes(1)),
    };
    unlock_event.insert(ctx.db.as_ref()).await.expect("insert unlock event");

    let remunerate_event = collateral_event::ActiveModel {
        id: sea_orm::ActiveValue::Set(Uuid::new_v4().to_string()),
        user_address: sea_orm::ActiveValue::Set(user_addr.clone()),
        asset_address: sea_orm::ActiveValue::Set(DEFAULT_ASSET_ADDRESS.to_string()),
        amount: sea_orm::ActiveValue::Set(U256::from(10u64).to_string()),
        event_type: sea_orm::ActiveValue::Set(CollateralEventType::Remunerate),
        tab_id: sea_orm::ActiveValue::Set(Some(u256_to_string(tab_id))),
        req_id: sea_orm::ActiveValue::Set(None),
        tx_id: sea_orm::ActiveValue::Set(None),
        created_at: sea_orm::ActiveValue::Set(now),
    };
    remunerate_event
        .insert(ctx.db.as_ref())
        .await
        .expect("insert remunerate event");

    let events = core_client
        .get_collateral_events_for_tab(tab_id)
        .await
        .expect("events");
    assert!(events.len() >= 2);
    let mut seen = events
        .iter()
        .map(|e| e.event_type.as_str())
        .collect::<Vec<_>>();
    seen.sort();
    assert!(seen.contains(&"REMUNERATE"));
    assert!(seen.contains(&"UNLOCK"));
}

#[test(tokio::test)]
#[serial]
async fn core_api_collateral_events_empty_for_tab_without_events() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let user_addr = random_address();
    let recipient_addr = random_address();
    common::fixtures::ensure_user(&ctx, &user_addr)
        .await
        .expect("ensure user");

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr,
            recipient_address: recipient_addr,
            erc20_token: None,
            ttl: Some(300),
        })
        .await
        .expect("create tab")
        .id;

    let events = core_client
        .get_collateral_events_for_tab(tab_id)
        .await
        .expect("events");
    assert!(events.is_empty());
}

#[test(tokio::test)]
#[serial]
async fn core_api_get_user_asset_balance() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let user_addr = random_address();
    insert_user_with_collateral(&ctx, &user_addr, U256::from(15u64)).await;

    let balance = core_client
        .get_user_asset_balance(user_addr.clone(), DEFAULT_ASSET_ADDRESS.to_string())
        .await
        .expect("get balance")
        .expect("balance exists");
    assert_eq!(balance.user_address, user_addr);
    assert_eq!(balance.total, U256::from(15u64));
    assert_eq!(balance.locked, U256::ZERO);

    let missing = core_client
        .get_user_asset_balance(user_addr, STABLE_ASSET_ADDRESS.to_string())
        .await
        .expect("get missing balance");
    assert!(missing.is_none());

    let unknown_user = core_client
        .get_user_asset_balance(random_address(), DEFAULT_ASSET_ADDRESS.to_string())
        .await
        .expect("unknown user balance");
    assert!(unknown_user.is_none());
}

#[test(tokio::test)]
#[serial]
async fn core_api_get_user_asset_balance_locked_amount() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let wallet = alloy::signers::local::PrivateKeySigner::random();
    let user_addr = wallet.address().to_string();
    let recipient_addr = random_address();

    insert_user_with_collateral(&ctx, &user_addr, U256::from(25u64)).await;

    let tab_id = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(600),
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
        U256::from(12u64),
        &wallet,
        None,
        DEFAULT_ASSET_ADDRESS,
    )
    .await;
    core_client
        .issue_guarantee(req)
        .await
        .expect("issue guarantee");

    let balance = core_client
        .get_user_asset_balance(user_addr.clone(), DEFAULT_ASSET_ADDRESS.to_string())
        .await
        .expect("get balance")
        .expect("balance exists");
    assert_eq!(balance.total, U256::from(25u64));
    assert_eq!(balance.locked, U256::from(12u64));
}
