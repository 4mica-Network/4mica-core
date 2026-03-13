use sdk_4mica::{
    Address, BLSCert, Client, Config,
    PaymentGuaranteeRequestClaims as PaymentGuaranteeRequestClaimsV1,
    PaymentGuaranteeRequestClaimsV2, SigningScheme, U256, error::RemunerateError,
};

mod common;

use crate::common::{
    ETH_ASSET_ADDRESS, assert_core_contract_deployed, build_authed_recipient_config,
    build_authed_user_config, extract_asset_info, get_chain_timestamp, mine_confirmations,
    wait_for_collateral_increase,
};
use alloy::primitives::B256;
use alloy::signers::Signer;
use crypto::bls::BlsClaims;
use rpc::{
    CorePublicParameters, PaymentGuaranteeValidationPolicyV2, RpcProxy,
    compute_validation_request_hash, compute_validation_subject_hash,
};

async fn fetch_public_params<S>(config: &Config<S>) -> anyhow::Result<CorePublicParameters>
where
    S: Signer + Sync,
{
    let mut rpc_proxy = RpcProxy::new(config.rpc_url.as_str())?;
    if let Some(token) = &config.bearer_token {
        rpc_proxy = rpc_proxy.with_bearer_token(token.clone());
    }
    Ok(rpc_proxy.get_public_params().await?)
}

async fn resolve_next_req_id<S>(
    recipient_client: &sdk_4mica::client::recipient::RecipientClient<S>,
    tab_id: U256,
) -> anyhow::Result<U256>
where
    S: Signer + Sync,
{
    if let Some(latest) = recipient_client.get_latest_guarantee(tab_id).await? {
        return Ok(latest.req_id + U256::from(1u64));
    }
    Ok(U256::ZERO)
}

fn is_expected_v2_remuneration_precondition_error(err: &RemunerateError) -> bool {
    matches!(
        err,
        RemunerateError::TabNotYetOverdue
            | RemunerateError::InvalidMinValidationScore
            | RemunerateError::InvalidValidationChainId
            | RemunerateError::UntrustedValidationRegistry(_)
            | RemunerateError::ValidationSubjectHashMismatch
            | RemunerateError::ValidationRequestHashMismatch
            | RemunerateError::ValidationLookupFailed
            | RemunerateError::ValidationPending
            | RemunerateError::ValidationScoreTooLow
            | RemunerateError::ValidationValidatorMismatch
            | RemunerateError::ValidationAgentMismatch
            | RemunerateError::ValidationTagMismatch
    )
}

#[tokio::test]
#[serial_test::serial]
async fn test_decoding_contract_errors() -> anyhow::Result<()> {
    // These wallet keys are picked from the default accounts in anvil test node

    let user_config = build_authed_user_config(
        "http://localhost:3000",
        "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    )
    .await?;

    let user_address = user_config.signer.address().to_string();
    let user_client = Client::new(user_config.clone()).await?;
    assert_core_contract_deployed(&user_config).await?;

    let recipient_config = build_authed_recipient_config(
        "http://localhost:3000",
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )
    .await?;

    let recipient_address = recipient_config.signer.address().to_string();
    let recipient_client = Client::new(recipient_config.clone()).await?;
    println!(
        "Test setup: core_rpc={}, user={}, recipient={}",
        user_config.rpc_url, user_address, recipient_address
    );

    // Step 1: User deposits collateral (2 ETH)
    let core_total_before = recipient_client
        .recipient
        .get_user_asset_balance(user_address.clone(), ETH_ASSET_ADDRESS.to_string())
        .await?
        .map(|info| info.total)
        .unwrap_or(U256::ZERO);
    println!("Core indexed balance before deposit: {core_total_before}");
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let receipt = user_client.user.deposit(deposit_amount, None).await?;
    println!("Deposit receipt: {receipt:#?}");
    mine_confirmations(&user_config, 1).await?;
    let on_chain_assets_after_deposit = user_client.user.get_user().await?;
    let on_chain_eth_after_deposit =
        extract_asset_info(&on_chain_assets_after_deposit, ETH_ASSET_ADDRESS)
            .map(|info| info.collateral)
            .unwrap_or(U256::ZERO);
    println!("On-chain ETH collateral after deposit: {on_chain_eth_after_deposit}");

    if let Err(err) = wait_for_collateral_increase(
        &recipient_client.recipient,
        &user_address,
        ETH_ASSET_ADDRESS,
        core_total_before,
        deposit_amount,
    )
    .await
    {
        let indexed_balance = recipient_client
            .recipient
            .get_user_asset_balance(user_address.clone(), ETH_ASSET_ADDRESS.to_string())
            .await;
        let on_chain_assets = user_client.user.get_user().await;
        let chain_timestamp = get_chain_timestamp(&user_config).await;
        eprintln!("wait_for_collateral_increase failed: {err}");
        eprintln!("Indexed ETH balance after timeout: {indexed_balance:?}");
        eprintln!("On-chain user assets after timeout: {on_chain_assets:?}");
        eprintln!("Latest chain timestamp: {chain_timestamp:?}");
        return Err(err);
    }

    // Step 2: Recipient creates a payment tab
    let tab_id = recipient_client
        .recipient
        .create_tab(
            user_address.clone(),
            recipient_address.clone(),
            None,
            Some(3600),
        )
        .await?;
    let req_id = resolve_next_req_id(&recipient_client.recipient, tab_id).await?;
    let public_params = fetch_public_params(&recipient_config).await?;

    // Step 3: User signs a payment (1 ETH)
    let claim_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let claim_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    enum IssuedClaims {
        V1(PaymentGuaranteeRequestClaimsV1),
        V2(PaymentGuaranteeRequestClaimsV2),
    }

    let claims = match public_params.active_guarantee_version {
        1 => IssuedClaims::V1(PaymentGuaranteeRequestClaimsV1 {
            user_address: user_address.clone(),
            recipient_address: recipient_address.clone(),
            tab_id,
            req_id,
            amount: claim_amount,
            timestamp: claim_timestamp,
            asset_address: ETH_ASSET_ADDRESS.to_string(),
        }),
        2 => {
            let validation_registry = public_params
                .trusted_validation_registries
                .first()
                .ok_or_else(|| {
                    anyhow::anyhow!("core reported active V2 without trusted validation registries")
                })?
                .parse::<Address>()?;
            let validation_subject_hash = compute_validation_subject_hash(
                &user_address,
                &recipient_address,
                tab_id,
                req_id,
                claim_amount,
                &ETH_ASSET_ADDRESS.to_string(),
                claim_timestamp,
            )?;
            let mut validation_policy = PaymentGuaranteeValidationPolicyV2 {
                validation_registry_address: validation_registry,
                validation_request_hash: B256::ZERO,
                validation_chain_id: public_params.chain_id,
                validator_address: recipient_config.signer.address(),
                validator_agent_id: U256::from(1u64),
                min_validation_score: 80,
                validation_subject_hash: B256::from(validation_subject_hash),
                required_validation_tag: "contract-error-test".to_string(),
            };
            validation_policy.validation_request_hash =
                B256::from(compute_validation_request_hash(&validation_policy)?);

            IssuedClaims::V2(
                PaymentGuaranteeRequestClaimsV2::builder(
                    user_address.clone(),
                    recipient_address.clone(),
                    tab_id,
                    req_id,
                    claim_amount,
                    claim_timestamp,
                )
                .asset_address(ETH_ASSET_ADDRESS.to_string())
                .validation_policy(validation_policy)
                .build()?,
            )
        }
        other => {
            return Err(anyhow::anyhow!(
                "unsupported active guarantee version reported by core: {other}"
            ));
        }
    };

    println!(
        "Signed payment: tab_id={tab_id}, user={user_address}, recipient={recipient_address}, amount={}, asset={}, ts={}",
        claim_amount, ETH_ASSET_ADDRESS, claim_timestamp
    );

    // Step 4: User issues guarantee
    let bls_cert = match claims {
        IssuedClaims::V1(claims) => {
            let payment_sig = user_client
                .user
                .sign_payment(claims.clone(), SigningScheme::Eip712)
                .await?;
            recipient_client
                .recipient
                .issue_payment_guarantee(claims, payment_sig.signature, payment_sig.scheme)
                .await?
        }
        IssuedClaims::V2(claims) => {
            let payment_sig = user_client
                .user
                .sign_payment_v2(claims.clone(), SigningScheme::Eip712)
                .await?;
            recipient_client
                .recipient
                .issue_payment_guarantee_v2(claims, payment_sig.signature, payment_sig.scheme)
                .await?
        }
    };

    println!(
        "Issued BLS certificate: claims_len={}, signature_len={}",
        bls_cert.claims().as_bytes().len(),
        bls_cert.signature().as_bytes().len()
    );

    let mut tampered_hex = bls_cert.claims().to_hex();
    if let Some(last) = tampered_hex.pop() {
        let replacement = match last {
            '0' => '1',
            '1' => '2',
            '2' => '3',
            '3' => '4',
            '4' => '5',
            '5' => '6',
            '6' => '7',
            '7' => '8',
            '8' => '9',
            '9' => 'a',
            'a' => 'b',
            'b' => 'c',
            'c' => 'd',
            'd' => 'e',
            'e' => 'f',
            _ => '0',
        };
        tampered_hex.push(replacement);
    } else {
        panic!("certificate claims unexpectedly empty");
    }

    let mismatched = BLSCert {
        claims: BlsClaims::from_hex(&tampered_hex)?,
        signature: bls_cert.signature().clone(),
    };
    let result = recipient_client.recipient.remunerate(mismatched).await;
    println!("Remunerate with mismatched cert -> {result:?}");
    assert!(matches!(result, Err(RemunerateError::CertificateMismatch)));

    let mut malformed_hex = bls_cert.signature().to_hex();
    malformed_hex.pop();
    assert!(
        crypto::bls::BlsSignature::from_hex(&malformed_hex).is_err(),
        "malformed signature should be rejected"
    );

    // Step 5: Recipient tries to remunerate immediately.
    // V1 reaches the overdue check directly. V2 may fail earlier in decoder-side validation.
    println!(
        "Remunerating with correct cert (claims_len={}, signature_len={})",
        bls_cert.claims().as_bytes().len(),
        bls_cert.signature().as_bytes().len()
    );
    let result = recipient_client.recipient.remunerate(bls_cert).await;
    dbg!(&result);
    match result {
        Err(RemunerateError::TabNotYetOverdue) if public_params.active_guarantee_version == 1 => {}
        Err(err)
            if public_params.active_guarantee_version == 2
                && is_expected_v2_remuneration_precondition_error(&err) => {}
        Err(RemunerateError::Transport(msg))
            if msg.contains("historical state")
                || msg.contains("failed to get account")
                || msg.contains("not available") =>
        {
            eprintln!("Skipping remunerate assertion due to non-archive forked RPC: {msg}");
            return Ok(());
        }
        other => panic!(
            "expected a decoded precondition error for guarantee version {}, got {other:?}",
            public_params.active_guarantee_version
        ),
    }
    Ok(())
}
