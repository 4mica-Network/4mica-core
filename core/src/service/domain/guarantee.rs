//! Guarantee issuance: validate the request, assign it to the active cycle, lock the payer's
//! collateral, and return the signed BLS certificate.

use crate::persist::canonical::ReqId;
use crate::persist::rows::StoreCycleGuaranteeInput;
use std::str::FromStr;
use std::sync::Arc;

use alloy::primitives::Address;
use anyhow::anyhow;
use chrono::Utc;
use crypto::bls::{BLSCert, BlsClaims};
use entities::sea_orm_active_enums::GuaranteeSettlementStatus;
use log::{info, warn};
use rpc::{
    PaymentGuaranteeClaims, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    ValidationRequirement,
};
use sea_orm::TransactionTrait;

use crate::auth::access::{self, AccessContext};
use crate::auth::constants::SCOPE_GUARANTEE_ISSUE;
use crate::error::{ServiceError, ServiceResult};
use crate::evm::guarantee::{guarantee_id_for_cycle, verify_guarantee_request_signature};
use crate::persist::repo;
use crate::service::ctx::Ctx;
use crate::service::shared::cycle::CycleOps;
use crate::service::shared::map_transaction_error;

#[derive(Clone)]
pub struct GuaranteeService {
    ctx: Arc<Ctx>,
    cycle_ops: Arc<CycleOps>,
}

impl GuaranteeService {
    pub fn new(ctx: Arc<Ctx>, cycle_ops: Arc<CycleOps>) -> Self {
        Self { ctx, cycle_ops }
    }

    pub fn verify_guarantee_request_claims(
        &self,
        claims: &PaymentGuaranteeRequestClaims,
    ) -> ServiceResult<()> {
        let now_i64 = chrono::Utc::now().timestamp();
        if now_i64 < 0 {
            return Err(ServiceError::Other(anyhow!("System time before epoch")));
        }
        let now_secs = now_i64 as u64;

        if now_secs < claims.timestamp() {
            return Err(ServiceError::FutureTimestamp);
        }

        let _claim_user = Address::from_str(claims.user_address())
            .map_err(|_| ServiceError::InvalidParams("Invalid user address".into()))?;
        let _claim_recipient = Address::from_str(claims.recipient_address())
            .map_err(|_| ServiceError::InvalidParams("Invalid recipient address".into()))?;
        let _claim_asset = Address::from_str(claims.asset_address())
            .map_err(|_| ServiceError::InvalidParams("Invalid asset address".into()))?;

        if let Some(validation) = claims.validation() {
            self.verify_validation_requirement(validation, now_secs)?;
        }

        Ok(())
    }

    /// Checks only what core owns: the validator is whitelisted and the deadline leaves it enough
    /// time to answer. Whether `params` make sense is the adapter's call.
    fn verify_validation_requirement(
        &self,
        validation: &ValidationRequirement,
        now_secs: u64,
    ) -> ServiceResult<()> {
        let adapter = self
            .ctx
            .validators
            .get(&validation.validator)
            .ok_or_else(|| {
                ServiceError::InvalidParams(format!(
                    "validator {} is not whitelisted",
                    validation.validator
                ))
            })?;

        adapter
            .validate_requirement(validation)
            .map_err(|err| ServiceError::InvalidParams(err.to_string()))?;

        if let Some(deadline) = validation.deadline
            && deadline <= now_secs
        {
            return Err(ServiceError::InvalidParams(format!(
                "validation deadline {deadline} is already in the past"
            )));
        }

        if let Some(min_validation_window_secs) =
            self.ctx.config.guarantee.min_validation_window_secs
        {
            check_validation_window(validation, now_secs, min_validation_window_secs)?;
        }

        Ok(())
    }

    fn guarantee_domain_for_version(&self, version: u64) -> ServiceResult<[u8; 32]> {
        self.ctx
            .guarantee_domains
            .get(&version)
            .copied()
            .ok_or_else(|| {
                ServiceError::Other(anyhow!(
                    "missing guarantee domain for accepted guarantee version {}",
                    version
                ))
            })
    }

    async fn create_bls_cert(&self, claims: PaymentGuaranteeClaims) -> ServiceResult<BLSCert> {
        let claims_bytes = <PaymentGuaranteeClaims as TryInto<Vec<u8>>>::try_into(claims)
            .map_err(ServiceError::Other)?;
        let claims = BlsClaims::from_bytes(claims_bytes);
        BLSCert::sign(self.ctx.bls_secret_key(), claims)
            .map_err(|err| ServiceError::Other(anyhow!(err)))
    }

    pub async fn issue_payment_guarantee(
        &self,
        auth: &AccessContext,
        req: PaymentGuaranteeRequest,
    ) -> ServiceResult<BLSCert> {
        access::require_scope(auth, SCOPE_GUARANTEE_ISSUE)?;
        access::require_recipient_match_or_facilitator(auth, req.claims.recipient_address())?;

        let amount = req.claims.amount();
        let request_version = req.claims.version();

        info!(
            "Received cycle-native guarantee request v{}; amount={}",
            request_version, amount
        );

        verify_guarantee_request_signature(&self.ctx.public_params, &req)?;
        self.verify_guarantee_request_claims(&req.claims)?;

        let payer = crate::evm::parse_address("user", req.claims.user_address())?;
        let recipient = crate::evm::parse_address("recipient", req.claims.recipient_address())?;
        let asset = crate::evm::parse_address("asset", req.claims.asset_address())?;

        self.ctx
            .check_settlement_timing_invariant()
            .map_err(|e| ServiceError::SettlementTimingHalted(format!("{e:#}")))?;

        let active_cycle = self
            .cycle_ops
            .get_or_create_active_cycle(asset, Utc::now())
            .await?;

        if req.claims.timestamp() < (active_cycle.period_start.and_utc().timestamp() as u64) {
            return Err(ServiceError::StaleTimestamp {
                timestamp: req.claims.timestamp(),
                cycle_start: active_cycle.period_start.and_utc().timestamp(),
            });
        }

        let validation = match req.claims.validation() {
            Some(requirement) => Some((
                requirement,
                enforced_validation_deadline(requirement, active_cycle.resolution_cutoff)?,
            )),
            None => None,
        };

        let cycle_id_hash = crate::evm::clearing::claim_cycle_id(&active_cycle.id);
        let guarantee_id = guarantee_id_for_cycle(&active_cycle.id, &req.claims);

        if repo::get_guarantee_by_id_on(self.ctx.db(), &guarantee_id)
            .await?
            .is_some()
        {
            return Err(ServiceError::DuplicateGuarantee {
                req_id: req.claims.req_id(),
            });
        }

        let guarantee_domain = self.guarantee_domain_for_version(request_version)?;
        let claims =
            PaymentGuaranteeClaims::from_request(&req.claims, guarantee_domain, cycle_id_hash);

        let cert = self.create_bls_cert(claims.clone()).await?;

        let guarantee = StoreCycleGuaranteeInput {
            guarantee_id: guarantee_id.clone(),
            cycle_id: active_cycle.id.clone(),
            req_id: ReqId(claims.req_id),
            version: claims.version,
            from: payer,
            to: recipient,
            asset,
            value: claims.amount,
            start_ts: unix_seconds_to_naive(claims.timestamp)?,
            cert: serde_json::to_string(&cert).map_err(|e| ServiceError::Other(anyhow!(e)))?,
            request: Some(
                serde_json::to_string(&req).map_err(|e| ServiceError::Other(anyhow!(e)))?,
            ),
            settlement_status: settlement_status_for_request(&req.claims),
        };
        let validation =
            validation.map(
                |(requirement, deadline)| repo::StoreGuaranteeValidationInput {
                    guarantee_id: guarantee_id.clone(),
                    validator: requirement.validator.clone(),
                    subject: requirement.subject.to_string(),
                    deadline,
                    params: requirement.params.to_vec(),
                },
            );

        let max_attempts = self
            .ctx
            .config
            .database_config
            .conflict_retries
            .saturating_add(1);
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self
                .issue_payment_guarantee_in_txn(&guarantee, validation.as_ref())
                .await
            {
                Ok(()) => return Ok(cert),
                Err(ServiceError::OptimisticLockConflict) if attempt < max_attempts => {
                    warn!(
                        "guarantee issuance hit balance lock conflict (attempt {attempt}/{max_attempts}); retrying"
                    );
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// Lock the payer's collateral and write the guarantee, plus its validation when one is
    /// required, as one unit. Retried by the caller on optimistic-lock conflicts, so it must stay
    /// free of side effects outside the transaction.
    async fn issue_payment_guarantee_in_txn(
        &self,
        guarantee: &StoreCycleGuaranteeInput,
        validation: Option<&repo::StoreGuaranteeValidationInput>,
    ) -> ServiceResult<()> {
        // Owned up-front: the transaction closure must not borrow from the caller's frame.
        let guarantee = guarantee.clone();
        let validation = validation.cloned();
        self.ctx
            .persist
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let guarantee = guarantee.clone();
                let validation = validation.clone();
                Box::pin(async move {
                    repo::ensure_user_is_active_on(txn, guarantee.from).await?;
                    repo::ensure_user_is_active_if_exists_on(txn, guarantee.to).await?;
                    repo::ensure_user_exists_on(txn, guarantee.to).await?;

                    repo::lock_user_balance_for_guarantee_on(
                        txn,
                        guarantee.from,
                        guarantee.asset,
                        guarantee.value,
                    )
                    .await?;

                    repo::store_cycle_guarantee_on(txn, guarantee).await?;

                    if let Some(validation) = validation {
                        repo::store_guarantee_validation_on(txn, validation).await?;
                    }

                    Ok(())
                })
            })
            .await
            .map_err(map_transaction_error)
    }
}

/// Interpret a claims timestamp, which is unix seconds, as the naive UTC time the row stores.
fn unix_seconds_to_naive(timestamp: u64) -> ServiceResult<chrono::NaiveDateTime> {
    chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .ok_or_else(|| {
            ServiceError::InvalidParams(format!(
                "guarantee timestamp {timestamp} is not a valid time"
            ))
        })
        .map(|dt| dt.naive_utc())
}

/// Refuses a deadline that leaves a validator less time to answer than `min_window` demands.
fn check_validation_window(
    validation: &ValidationRequirement,
    now_secs: u64,
    min_window: u64,
) -> ServiceResult<()> {
    let Some(deadline) = validation.deadline else {
        return Ok(());
    };

    if deadline < now_secs.saturating_add(min_window) {
        return Err(ServiceError::InvalidParams(format!(
            "validation deadline {deadline} leaves less than the required {min_window}s to validate"
        )));
    }
    Ok(())
}

/// `min(payer's deadline, the cycle's resolution cutoff)`, so a pending validation never outlives
/// the cycle that would settle it.
fn enforced_validation_deadline(
    validation: &ValidationRequirement,
    resolution_cutoff: chrono::NaiveDateTime,
) -> ServiceResult<chrono::NaiveDateTime> {
    let Some(deadline) = validation.deadline else {
        return Ok(resolution_cutoff);
    };

    let deadline = chrono::DateTime::from_timestamp(deadline as i64, 0)
        .ok_or_else(|| {
            ServiceError::InvalidParams(format!("invalid validation deadline {deadline}"))
        })?
        .naive_utc();

    Ok(deadline.min(resolution_cutoff))
}

fn settlement_status_for_request(
    claims: &PaymentGuaranteeRequestClaims,
) -> GuaranteeSettlementStatus {
    if claims.validation().is_some() {
        GuaranteeSettlementStatus::PendingValidation
    } else {
        GuaranteeSettlementStatus::FinalizedPayable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{B256, U256};
    use chrono::DateTime;
    use rpc::{GUARANTEE_CLAIMS_VERSION, ValidationRequirement};

    fn claims(req_id: u64) -> PaymentGuaranteeRequestClaims {
        PaymentGuaranteeRequestClaims::new(
            Address::repeat_byte(0x11).to_string(),
            Address::repeat_byte(0x22).to_string(),
            U256::from(req_id),
            U256::from(7u64),
            1_700_000_000,
            Some(Address::ZERO.to_string()),
        )
    }

    fn validation(deadline: Option<u64>) -> ValidationRequirement {
        ValidationRequirement {
            validator: "eip155:84532:0x3333333333333333333333333333333333333333".to_string(),
            subject: B256::repeat_byte(0x66),
            deadline,
            params: Default::default(),
        }
    }

    fn validated_claims(deadline: Option<u64>) -> PaymentGuaranteeRequestClaims {
        claims(1).with_validation(validation(deadline))
    }

    fn naive(unix: i64) -> chrono::NaiveDateTime {
        DateTime::from_timestamp(unix, 0)
            .expect("valid timestamp")
            .naive_utc()
    }

    #[test]
    fn plain_claims_are_payable_and_validated_claims_wait() {
        assert_eq!(claims(1).version(), GUARANTEE_CLAIMS_VERSION);
        assert_eq!(
            settlement_status_for_request(&claims(1)),
            GuaranteeSettlementStatus::FinalizedPayable
        );
        assert_eq!(
            settlement_status_for_request(&validated_claims(None)),
            GuaranteeSettlementStatus::PendingValidation
        );
    }

    const NOW: i64 = 1_700_000_000;

    fn enforced(deadline: Option<u64>, cutoff: i64) -> chrono::NaiveDateTime {
        enforced_validation_deadline(&validation(deadline), naive(cutoff)).expect("deadline")
    }

    #[test]
    fn deadline_defaults_to_the_cycle_resolution_cutoff() {
        assert_eq!(enforced(None, 1_700_010_000), naive(1_700_010_000));
    }

    #[test]
    fn payer_deadline_tightens_but_never_extends_the_cutoff() {
        assert_eq!(
            enforced(Some(1_700_005_000), 1_700_010_000),
            naive(1_700_005_000)
        );
        assert_eq!(
            enforced(Some(1_700_020_000), 1_700_010_000),
            naive(1_700_010_000)
        );
    }

    fn window_check(deadline: Option<u64>, min_window: u64) -> ServiceResult<()> {
        check_validation_window(&validation(deadline), NOW as u64, min_window)
    }

    #[test]
    fn deadline_inside_the_minimum_window_is_rejected() {
        let now = NOW as u64;
        let window = 600;

        assert!(window_check(Some(now + 599), window).is_err());
        assert!(window_check(Some(now - 1), window).is_err());
        assert!(window_check(Some(now + 600), window).is_ok());
        // A payer who names no deadline gets the cycle's, which is core's own to police.
        assert!(window_check(None, window).is_ok());
    }
}
