//! DB-level tests for the V2 validation lifecycle driver.
//!
//! A `PendingValidation` guarantee is inserted with a real serialized V2 request, then driven
//! through `drive_pending_validations` against a mocked validation registry. Each test asserts
//! both the resulting settlement status and the payer's locked collateral, exercising the DB
//! query, request deserialization, on-chain-mirroring decision, transition, and collateral
//! release that the pure-logic unit tests in `service::validation` do not cover.

use std::collections::HashMap;
use std::sync::Arc;

use alloy::primitives::{Address, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use async_trait::async_trait;
use chrono::Utc;
use entities::sea_orm_active_enums::GuaranteeSettlementStatus;
use rpc::{
    PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV2,
    PaymentGuaranteeValidationPolicyV2, SigningScheme, SupportedTokenInfo,
    compute_validation_request_hash, compute_validation_subject_hash,
};

/// Validator identity the mocked `passing_status()` reports — the seeded policy must match it
/// so a resolved-and-accepted validation finalizes.
const VALIDATOR_AGENT_ID: u64 = 7;
const MIN_SCORE: u8 = 80;
const REQUIRED_TAG: &str = "hard-finality";

fn validator_address() -> Address {
    Address::repeat_byte(0x55)
}

use core_service::config::{AppConfig, DEFAULT_ASSET_ADDRESS, Environment};
use core_service::error::CoreContractApiError;
use core_service::ethereum::{
    ClearingCommitInput, ClearingCycleView, ClearingTxResult, CoreContractApi, CreditorSettlement,
    DebtorSettlement, GuaranteeVersionConfig, ValidationStatus,
};
use core_service::persist::{CycleGuaranteeData, PersistCtx, repo};
use core_service::service::{CoreService, CoreServiceDeps};

#[path = "common/mod.rs"]
mod common;
use common::cycle_fixtures::{create_frozen_cycle, lock_collateral};
use common::db::{clear_all_tables, setup_db_test_env};
use common::fixtures::{normalize_address, random_address, read_locked_collateral};

/// A `CoreContractApi` that only answers `get_validation_status`; every other call is
/// unreachable in the validation sweep and panics if invoked.
struct MockRegistryApi {
    /// `Some(status)` is returned from `get_validation_status`; `None` simulates an unreadable
    /// registry (the call returns an error, which the driver treats as "unresolved").
    status: Option<ValidationStatus>,
}

#[async_trait]
impl CoreContractApi for MockRegistryApi {
    async fn get_chain_id(&self) -> Result<u64, CoreContractApiError> {
        unimplemented!("not used by the validation sweep")
    }
    async fn get_guarantee_version_config(
        &self,
        _version: u64,
    ) -> Result<GuaranteeVersionConfig, CoreContractApiError> {
        unimplemented!("not used by the validation sweep")
    }
    async fn get_withdrawal_grace_period(&self) -> Result<u64, CoreContractApiError> {
        unimplemented!("not used by the validation sweep")
    }
    async fn get_supported_tokens(&self) -> Result<Vec<SupportedTokenInfo>, CoreContractApiError> {
        unimplemented!("not used by the validation sweep")
    }
    async fn commit_clearing_cycle(
        &self,
        _input: ClearingCommitInput,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        unimplemented!("not used by the validation sweep")
    }
    async fn settle_defaults_from_collateral_batch(
        &self,
        _cycle_id: B256,
        _entries: Vec<DebtorSettlement>,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        unimplemented!("not used by the validation sweep")
    }
    async fn fund_creditors_from_pool_batch(
        &self,
        _cycle_id: B256,
        _entries: Vec<CreditorSettlement>,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        unimplemented!("not used by the validation sweep")
    }
    async fn finalize_clearing_cycle(
        &self,
        _cycle_id: B256,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        unimplemented!("not used by the validation sweep")
    }
    async fn mark_cycle_shortfall(
        &self,
        _cycle_id: B256,
    ) -> Result<ClearingTxResult, CoreContractApiError> {
        unimplemented!("not used by the validation sweep")
    }
    async fn get_clearing_cycle(
        &self,
        _cycle_id: B256,
    ) -> Result<ClearingCycleView, CoreContractApiError> {
        unimplemented!("not used by the validation sweep")
    }
    async fn get_validation_status(
        &self,
        _registry: Address,
        _request_hash: B256,
    ) -> Result<ValidationStatus, CoreContractApiError> {
        match &self.status {
            Some(status) => Ok(status.clone()),
            None => Err(CoreContractApiError::ContractCall(
                "mock: registry unreadable".to_string(),
            )),
        }
    }
}

/// A lazy HTTP provider that never connects — the sweep only touches `contract_api` and the DB.
fn dummy_provider() -> DynProvider {
    ProviderBuilder::new()
        .connect_http("http://127.0.0.1:1".parse().unwrap())
        .erased()
}

/// Build a chain-free `CoreService` wired to `MockRegistryApi`, with the V2 lifecycle enabled.
fn build_service(
    ctx: &PersistCtx,
    mut config: AppConfig,
    status: Option<ValidationStatus>,
    validation_timeout_secs: u64,
) -> CoreService {
    config.server_config.environment = Environment::Development;
    config.guarantee.max_accepted_version = 1;
    config.guarantee.accepted_request_versions = String::new();
    config.guarantee.enable_v2_validation_lifecycle = true;
    config.guarantee.validation_timeout_secs = validation_timeout_secs;

    let deps = CoreServiceDeps {
        persist_ctx: ctx.clone(),
        contract_api: Arc::new(MockRegistryApi { status }),
        chain_id: 1,
        read_provider: dummy_provider(),
        guarantee_domains: HashMap::from([(1u64, [0u8; 32])]),
        withdrawal_grace_period: 22 * 24 * 3600,
    };
    CoreService::new_with_dependencies(config, deps).expect("chain-free service builds")
}

/// Build a validation policy whose `validation_subject_hash` / `validation_request_hash` are
/// canonical for the payment fields, so the request round-trips through the validating
/// `Deserialize` exactly as a real issued request would. Validator identity matches
/// `passing_status()`.
fn canonical_policy(
    user: &str,
    recipient: &str,
    req_id: u64,
    amount: u64,
    timestamp: u64,
) -> anyhow::Result<PaymentGuaranteeValidationPolicyV2> {
    let subject = compute_validation_subject_hash(
        user,
        recipient,
        U256::from(req_id),
        U256::from(amount),
        DEFAULT_ASSET_ADDRESS,
        timestamp,
    )?;
    let mut policy = PaymentGuaranteeValidationPolicyV2 {
        validation_registry_address: Address::repeat_byte(0x33),
        validation_request_hash: B256::ZERO,
        validation_chain_id: 84532,
        validator_address: validator_address(),
        validator_agent_id: U256::from(VALIDATOR_AGENT_ID),
        min_validation_score: MIN_SCORE,
        validation_subject_hash: B256::from(subject),
        job_hash: B256::repeat_byte(0x77),
        required_validation_tag: REQUIRED_TAG.to_string(),
    };
    policy.validation_request_hash = B256::from(compute_validation_request_hash(&policy)?);
    Ok(policy)
}

/// A resolved status that satisfies `canonical_policy()` exactly.
fn passing_status() -> ValidationStatus {
    ValidationStatus {
        validator_address: validator_address(),
        agent_id: U256::from(VALIDATOR_AGENT_ID),
        response: MIN_SCORE,
        tag: REQUIRED_TAG.to_string(),
        last_update: U256::from(1_700_000_000u64),
    }
}

/// Insert a `PendingValidation` V2 guarantee for `from -> to` and lock `amount` of the payer's
/// collateral, as at issuance. Returns the (guarantee_id, normalized_from).
async fn seed_pending_v2(
    ctx: &PersistCtx,
    cycle_id: &str,
    amount: u64,
    req_id: u64,
) -> anyhow::Result<(String, String)> {
    let from = normalize_address(&random_address())?;
    let to = normalize_address(&random_address())?;
    lock_collateral(ctx, &from, amount).await?;

    let timestamp = 1_700_000_000u64;
    let validation_policy = canonical_policy(&from, &to, req_id, amount, timestamp)?;
    let claims = PaymentGuaranteeRequestClaims::V2(Box::new(PaymentGuaranteeRequestClaimsV2 {
        user_address: from.clone(),
        recipient_address: to.clone(),
        req_id: U256::from(req_id),
        amount: U256::from(amount),
        asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
        timestamp,
        validation_policy,
    }));
    let request = PaymentGuaranteeRequest {
        claims,
        signature: "0x00".to_string(),
        scheme: SigningScheme::Eip712,
    };

    let guarantee_id = format!("{cycle_id}:{from}:{to}:{req_id}");
    repo::store_cycle_guarantee_on(
        ctx.db.as_ref(),
        CycleGuaranteeData {
            guarantee_id: guarantee_id.clone(),
            cycle_id: cycle_id.to_string(),
            req_id: U256::from(req_id),
            version: 2,
            from: from.clone(),
            to,
            asset: DEFAULT_ASSET_ADDRESS.to_string(),
            value: U256::from(amount),
            start_ts: Utc::now().naive_utc(),
            cert: "{}".to_string(),
            request: Some(serde_json::to_string(&request)?),
            settlement_status: GuaranteeSettlementStatus::PendingValidation,
        },
    )
    .await?;
    Ok((guarantee_id, from))
}

async fn guarantee_status(
    ctx: &PersistCtx,
    guarantee_id: &str,
) -> anyhow::Result<GuaranteeSettlementStatus> {
    let g = repo::get_guarantee_by_id_on(ctx.db.as_ref(), guarantee_id)
        .await?
        .expect("guarantee exists");
    Ok(g.settlement_status)
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn resolved_and_accepted_validation_finalizes_and_keeps_collateral_locked()
-> anyhow::Result<()> {
    let (config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "l02-finalize-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, payer) = seed_pending_v2(&ctx, cycle_id, 10, 1).await?;

    let service = build_service(&ctx, config, Some(passing_status()), 3600);
    let summary = service.drive_pending_validations().await?;

    assert_eq!(summary.finalized, 1, "one guarantee should be finalized");
    assert_eq!(
        guarantee_status(&ctx, &guarantee_id).await?,
        GuaranteeSettlementStatus::FinalizedPayable
    );
    // A finalized guarantee stays backed: the payer's collateral remains locked.
    assert_eq!(
        read_locked_collateral(&ctx, &payer, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(10u64)
    );
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn resolved_but_low_score_disputes_and_releases_collateral() -> anyhow::Result<()> {
    let (config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "l02-dispute-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, payer) = seed_pending_v2(&ctx, cycle_id, 10, 1).await?;

    let mut status = passing_status();
    status.response = 79; // below min_validation_score = 80
    let service = build_service(&ctx, config, Some(status), 3600);
    let summary = service.drive_pending_validations().await?;

    assert_eq!(summary.disputed, 1, "one guarantee should be disputed");
    assert_eq!(
        guarantee_status(&ctx, &guarantee_id).await?,
        GuaranteeSettlementStatus::Disputed
    );
    // A disputed (validation-failed) guarantee never settles: release the payer's collateral.
    assert_eq!(
        read_locked_collateral(&ctx, &payer, DEFAULT_ASSET_ADDRESS).await?,
        U256::ZERO
    );
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn unresolved_past_timeout_cancels_and_releases_collateral() -> anyhow::Result<()> {
    let (config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "l02-cancel-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, payer) = seed_pending_v2(&ctx, cycle_id, 10, 1).await?;

    // Unresolved validation (lastUpdate == 0) with a zero timeout forces an immediate cancel.
    let mut status = passing_status();
    status.last_update = U256::ZERO;
    let service = build_service(&ctx, config, Some(status), 0);
    let summary = service.drive_pending_validations().await?;

    assert_eq!(summary.cancelled, 1, "one guarantee should be cancelled");
    assert_eq!(
        guarantee_status(&ctx, &guarantee_id).await?,
        GuaranteeSettlementStatus::Cancelled
    );
    assert_eq!(
        read_locked_collateral(&ctx, &payer, DEFAULT_ASSET_ADDRESS).await?,
        U256::ZERO
    );
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn unresolved_within_timeout_waits_and_keeps_pending() -> anyhow::Result<()> {
    let (config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "l02-wait-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, payer) = seed_pending_v2(&ctx, cycle_id, 10, 1).await?;

    // Registry unreadable (treated as unresolved) but the timeout has not elapsed: keep waiting.
    let service = build_service(&ctx, config, None, 3600);
    let summary = service.drive_pending_validations().await?;

    assert_eq!(summary.waiting, 1, "the guarantee should still be waiting");
    assert_eq!(
        guarantee_status(&ctx, &guarantee_id).await?,
        GuaranteeSettlementStatus::PendingValidation
    );
    assert_eq!(
        read_locked_collateral(&ctx, &payer, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(10u64)
    );
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn disabled_lifecycle_flag_is_a_noop() -> anyhow::Result<()> {
    let (mut config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "l02-disabled-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, _payer) = seed_pending_v2(&ctx, cycle_id, 10, 1).await?;

    // build_service normally force-enables the flag; here we build one with it left off.
    config.server_config.environment = Environment::Development;
    config.guarantee.max_accepted_version = 1;
    config.guarantee.accepted_request_versions = String::new();
    config.guarantee.enable_v2_validation_lifecycle = false;
    let deps = CoreServiceDeps {
        persist_ctx: ctx.clone(),
        contract_api: Arc::new(MockRegistryApi {
            status: Some(passing_status()),
        }),
        chain_id: 1,
        read_provider: dummy_provider(),
        guarantee_domains: HashMap::from([(1u64, [0u8; 32])]),
        withdrawal_grace_period: 22 * 24 * 3600,
    };
    let service = CoreService::new_with_dependencies(config, deps).expect("service builds");

    let summary = service.drive_pending_validations().await?;
    assert_eq!(summary, Default::default(), "disabled flag must be a no-op");
    assert_eq!(
        guarantee_status(&ctx, &guarantee_id).await?,
        GuaranteeSettlementStatus::PendingValidation
    );
    Ok(())
}
