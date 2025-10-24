use super::*;

#[test(tokio::test)]
#[serial]
async fn core_api_recipient_payments_and_events() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let user_addr = random_address();
    let recipient_addr = random_address();
    insert_user_with_collateral(&ctx, &user_addr, U256::from(20u64)).await;

    let create_res = core_client
        .create_payment_tab(CreatePaymentTabRequest {
            user_address: user_addr.clone(),
            recipient_address: recipient_addr.clone(),
            erc20_token: None,
            ttl: Some(1200),
        })
        .await
        .expect("create tab");
    let tab_id = create_res.id;

    let tx_hash = format!("0x{:032x}", random::<u128>());
    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        tx_hash,
        U256::from(7u64),
    )
    .await
    .expect("submit payment tx");

    repo::remunerate_recipient(
        &ctx,
        tab_id,
        DEFAULT_ASSET_ADDRESS.to_string(),
        U256::from(5u64),
    )
    .await
    .expect("remunerate tab");

    let payments = core_client
        .list_recipient_payments(recipient_addr.clone())
        .await
        .expect("list recipient payments");
    assert_eq!(payments.len(), 1);
    assert_eq!(payments[0].user_address, user_addr);

    let events = core_client
        .get_collateral_events_for_tab(tab_id)
        .await
        .expect("collateral events");
    assert!(!events.is_empty());
    assert_eq!(events[0].event_type, "REMUNERATE");
}

#[test(tokio::test)]
#[serial]
async fn core_api_recipient_payments_flags() {
    let (_, core_client, ctx) = setup_clean_db().await;

    let user_addr = random_address();
    let recipient_addr = random_address();

    insert_user_with_collateral(&ctx, &user_addr, U256::from(30u64)).await;

    repo::submit_payment_transaction(
        &ctx,
        user_addr.clone(),
        recipient_addr.clone(),
        DEFAULT_ASSET_ADDRESS.to_string(),
        "0xdeadbeef".into(),
        U256::from(10u64),
    )
    .await
    .expect("submit payment");

    repo::fail_transaction(&ctx, user_addr.clone(), "0xdeadbeef".into())
        .await
        .expect("mark failed");

    let payments = core_client
        .list_recipient_payments(recipient_addr)
        .await
        .expect("list payments");
    assert_eq!(payments.len(), 1);
    let payment = &payments[0];
    assert!(payment.failed);
    assert!(payment.finalized);
    assert_eq!(payment.amount, U256::from(10u64));
    assert_eq!(payment.user_address, user_addr);
}

#[test(tokio::test)]
#[serial]
async fn core_api_list_recipient_payments_empty() {
    let (_, core_client, _) = setup_clean_db().await;
    let payments = core_client
        .list_recipient_payments(random_address())
        .await
        .expect("list empty payments");
    assert!(payments.is_empty());
}
