//! DB-level tests for the validation lifecycle driver, covering the persistence and collateral
//! effects that the pure-logic unit tests in `service::validation` cannot reach.

use std::collections::HashMap;
use std::sync::Arc;

use alloy::primitives::{B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use async_trait::async_trait;
use chrono::{Duration, NaiveDateTime, Utc};
use entities::sea_orm_active_enums::{GuaranteeSettlementStatus, GuaranteeValidationStatus};
use rpc::{
    PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims, SigningScheme, ValidationRequirement,
};
use validators::{ValidatorAdapter, ValidatorRegistry, Verdict, VerdictStatus};

use core_service::config::{AppConfig, DEFAULT_ASSET_ADDRESS, Environment};
use core_service::persist::{CycleGuaranteeData, PersistCtx, repo};
use core_service::service::{CoreService, CoreServiceDeps};

#[path = "common/mod.rs"]
mod common;
use common::cycle_fixtures::{create_frozen_cycle, lock_collateral};
use common::db::{clear_all_tables, setup_db_test_env};
use common::fixtures::{normalize_address, random_address, read_locked_collateral};

const VALIDATOR_URI: &str = "mock:validator";

/// Reports a fixed verdict, so the driver can be exercised without a chain or an HTTP server.
struct MockAdapter {
    status: VerdictStatus,
}

#[async_trait]
impl ValidatorAdapter for MockAdapter {
    fn kind(&self) -> &str {
        "mock"
    }

    fn validate_requirement(&self, _req: &ValidationRequirement) -> anyhow::Result<()> {
        Ok(())
    }

    async fn resolve(&self, req: &ValidationRequirement) -> anyhow::Result<Verdict> {
        Ok(Verdict {
            status: self.status,
            subject: req.subject,
            evidence: vec![0xAB].into(),
            observed_at: Utc::now().timestamp() as u64,
        })
    }
}

fn dummy_provider() -> DynProvider {
    ProviderBuilder::new()
        .connect_http("http://127.0.0.1:1".parse().expect("valid url"))
        .erased()
}

fn build_service(
    ctx: &PersistCtx,
    mut config: AppConfig,
    validators: ValidatorRegistry,
) -> CoreService {
    config.server_config.environment = Environment::Development;

    let deps = CoreServiceDeps {
        persist_ctx: ctx.clone(),
        contract_api: Arc::new(common::chain_stub::UnusedContractApi),
        chain_id: 1,
        read_provider: dummy_provider(),
        guarantee_domains: HashMap::from([(1u64, [0u8; 32])]),
        validators,
        withdrawal_grace_period: 22 * 24 * 3600,
        core_domain_separator: None,
    };
    CoreService::new_with_dependencies(config, deps).expect("chain-free service builds")
}

fn mock_registry(status: VerdictStatus) -> ValidatorRegistry {
    ValidatorRegistry::from_adapters([(
        VALIDATOR_URI.to_string(),
        Arc::new(MockAdapter { status }) as Arc<dyn ValidatorAdapter>,
    )])
}

/// Insert a `PendingValidation` guarantee plus its validation row for `from -> to`, and lock
/// `amount` of the payer's collateral, as at issuance. Returns the (guarantee_id, payer).
async fn seed_pending_validation(
    ctx: &PersistCtx,
    cycle_id: &str,
    amount: u64,
    req_id: u64,
    deadline: NaiveDateTime,
) -> anyhow::Result<(String, String)> {
    let from = normalize_address(&random_address())?;
    let to = normalize_address(&random_address())?;
    lock_collateral(ctx, &from, amount).await?;

    let subject = B256::from(rand::random::<[u8; 32]>());
    let claims = PaymentGuaranteeRequestClaims::new(
        from.clone(),
        to.clone(),
        U256::from(req_id),
        U256::from(amount),
        1_700_000_000,
        Some(DEFAULT_ASSET_ADDRESS.to_string()),
    )
    .with_validation(ValidationRequirement {
        validator: VALIDATOR_URI.to_string(),
        subject,
        deadline: None,
        params: Default::default(),
    });
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
            version: 1,
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

    repo::store_guarantee_validation_on(
        ctx.db.as_ref(),
        repo::StoreGuaranteeValidationInput {
            guarantee_id: guarantee_id.clone(),
            validator: VALIDATOR_URI.to_string(),
            subject: subject.to_string(),
            deadline,
            params: Vec::new(),
        },
    )
    .await?;

    Ok((guarantee_id, from))
}

fn future_deadline() -> NaiveDateTime {
    Utc::now().naive_utc() + Duration::hours(1)
}

fn past_deadline() -> NaiveDateTime {
    Utc::now().naive_utc() - Duration::hours(1)
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

async fn validation_status(
    ctx: &PersistCtx,
    guarantee_id: &str,
) -> anyhow::Result<GuaranteeValidationStatus> {
    let v = repo::get_guarantee_validation_on(ctx.db.as_ref(), guarantee_id)
        .await?
        .expect("validation row exists");
    Ok(v.status)
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn approved_validation_finalizes_and_keeps_collateral_locked() -> anyhow::Result<()> {
    let (config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "validation-finalize-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, payer) =
        seed_pending_validation(&ctx, cycle_id, 10, 1, future_deadline()).await?;

    let service = build_service(&ctx, config, mock_registry(VerdictStatus::Approved));
    let summary = service.validation().drive_pending_validations().await?;

    assert_eq!(summary.finalized, 1, "one guarantee should be finalized");
    assert_eq!(
        guarantee_status(&ctx, &guarantee_id).await?,
        GuaranteeSettlementStatus::FinalizedPayable
    );
    assert_eq!(
        validation_status(&ctx, &guarantee_id).await?,
        GuaranteeValidationStatus::Approved
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
async fn rejected_validation_disputes_and_releases_collateral() -> anyhow::Result<()> {
    let (config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "validation-dispute-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, payer) =
        seed_pending_validation(&ctx, cycle_id, 10, 1, future_deadline()).await?;

    let service = build_service(&ctx, config, mock_registry(VerdictStatus::Rejected));
    let summary = service.validation().drive_pending_validations().await?;

    assert_eq!(summary.disputed, 1, "one guarantee should be disputed");
    assert_eq!(
        guarantee_status(&ctx, &guarantee_id).await?,
        GuaranteeSettlementStatus::Disputed
    );
    assert_eq!(
        validation_status(&ctx, &guarantee_id).await?,
        GuaranteeValidationStatus::Rejected
    );
    // A rejected guarantee never settles: release the payer's collateral.
    assert_eq!(
        read_locked_collateral(&ctx, &payer, DEFAULT_ASSET_ADDRESS).await?,
        U256::ZERO
    );
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn pending_past_deadline_cancels_and_releases_collateral() -> anyhow::Result<()> {
    let (config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "validation-cancel-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, payer) =
        seed_pending_validation(&ctx, cycle_id, 10, 1, past_deadline()).await?;

    let service = build_service(&ctx, config, mock_registry(VerdictStatus::Pending));
    let summary = service.validation().drive_pending_validations().await?;

    assert_eq!(summary.cancelled, 1, "one guarantee should be cancelled");
    assert_eq!(
        guarantee_status(&ctx, &guarantee_id).await?,
        GuaranteeSettlementStatus::Cancelled
    );
    assert_eq!(
        validation_status(&ctx, &guarantee_id).await?,
        GuaranteeValidationStatus::Expired
    );
    assert_eq!(
        read_locked_collateral(&ctx, &payer, DEFAULT_ASSET_ADDRESS).await?,
        U256::ZERO
    );
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn pending_before_deadline_waits() -> anyhow::Result<()> {
    let (config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "validation-wait-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, payer) =
        seed_pending_validation(&ctx, cycle_id, 10, 1, future_deadline()).await?;

    let service = build_service(&ctx, config, mock_registry(VerdictStatus::Pending));
    let summary = service.validation().drive_pending_validations().await?;

    assert_eq!(summary.waiting, 1, "the guarantee should still be waiting");
    assert_eq!(
        guarantee_status(&ctx, &guarantee_id).await?,
        GuaranteeSettlementStatus::PendingValidation
    );
    assert_eq!(
        validation_status(&ctx, &guarantee_id).await?,
        GuaranteeValidationStatus::Pending
    );
    assert_eq!(
        read_locked_collateral(&ctx, &payer, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(10u64)
    );
    Ok(())
}

#[tokio::test]
#[serial_test::file_serial(db)]
async fn approved_validation_into_already_resolved_cycle_cancels_and_releases_collateral()
-> anyhow::Result<()> {
    let (config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "validation-stale-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, payer) =
        seed_pending_validation(&ctx, cycle_id, 10, 1, future_deadline()).await?;

    // The cycle resolves (short-circuits straight to Finalized, as an all-pending cycle does)
    // before the validation lands — e.g. the driver was down across the cycle's resolution
    // window. The guarantee can no longer be included in any netting round.
    assert!(
        repo::short_circuit_frozen_cycle_on(ctx.db.as_ref(), cycle_id, Utc::now().naive_utc())
            .await?
    );

    // Even though the validation now passes, finalizing would strand the payer's collateral in a
    // dead cycle, so the driver cancels and releases.
    let service = build_service(&ctx, config, mock_registry(VerdictStatus::Approved));
    let summary = service.validation().drive_pending_validations().await?;

    assert_eq!(
        summary.cancelled, 1,
        "a would-be finalize into a resolved cycle must cancel"
    );
    assert_eq!(
        summary.finalized, 0,
        "it must not finalize into a dead cycle"
    );
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

/// End-to-end forward link: a validated guarantee the driver finalizes is then picked up by
/// netting exactly like a plain one. This closes the gap between the driver (which stops at
/// `FinalizedPayable`) and settlement.
#[tokio::test]
#[serial_test::file_serial(db)]
async fn finalized_validated_guarantee_is_netted_like_a_plain_one() -> anyhow::Result<()> {
    let (config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "validation-net-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, payer) =
        seed_pending_validation(&ctx, cycle_id, 10, 1, future_deadline()).await?;

    let service = build_service(&ctx, config, mock_registry(VerdictStatus::Approved));
    let summary = service.validation().drive_pending_validations().await?;
    assert_eq!(summary.finalized, 1);
    assert_eq!(
        guarantee_status(&ctx, &guarantee_id).await?,
        GuaranteeSettlementStatus::FinalizedPayable
    );

    service
        .netting()
        .compute_cycle_exposure_edges(cycle_id)
        .await?;
    service
        .netting()
        .compute_cycle_participant_positions(cycle_id)
        .await?;

    let edges = repo::list_exposure_edges_for_cycle_on(ctx.db.as_ref(), cycle_id).await?;
    assert_eq!(
        edges.len(),
        1,
        "the finalized validated guarantee must produce an edge"
    );

    let positions =
        repo::list_participant_positions_for_cycle_on(ctx.db.as_ref(), cycle_id).await?;
    let payer_position = positions
        .iter()
        .find(|p| p.participant == payer)
        .expect("payer must have a net position");
    assert_eq!(payer_position.net_debit, "10");
    Ok(())
}

/// A guarantee whose validator has been de-whitelisted since issuance is no longer gated by
/// anything, so it is finalized in time to take part in its cycle rather than left to expire.
#[tokio::test]
#[serial_test::file_serial(db)]
async fn de_whitelisted_validator_skips_and_finalizes() -> anyhow::Result<()> {
    let (config, ctx) = setup_db_test_env().await?;
    clear_all_tables(&ctx).await?;
    let cycle_id = "validation-skip-cycle";
    create_frozen_cycle(&ctx, cycle_id).await?;
    let (guarantee_id, payer) =
        seed_pending_validation(&ctx, cycle_id, 10, 1, future_deadline()).await?;

    // The registry is not empty, it just no longer carries the validator this guarantee named. The
    // adapter it does carry would reject, so a skip is the only way the guarantee survives.
    let other_validator = ValidatorRegistry::from_adapters([(
        "mock:other".to_string(),
        Arc::new(MockAdapter {
            status: VerdictStatus::Rejected,
        }) as Arc<dyn ValidatorAdapter>,
    )]);
    let service = build_service(&ctx, config, other_validator);
    let summary = service.validation().drive_pending_validations().await?;

    assert_eq!(summary.skipped, 1, "one guarantee should be skipped");
    assert_eq!(
        summary.disputed, 0,
        "an unreachable validator must not dispute"
    );
    assert_eq!(
        guarantee_status(&ctx, &guarantee_id).await?,
        GuaranteeSettlementStatus::FinalizedPayable
    );
    assert_eq!(
        validation_status(&ctx, &guarantee_id).await?,
        GuaranteeValidationStatus::Skipped
    );
    // Like any other finalized guarantee, it stays backed until its cycle settles.
    assert_eq!(
        read_locked_collateral(&ctx, &payer, DEFAULT_ASSET_ADDRESS).await?,
        U256::from(10u64)
    );
    Ok(())
}
