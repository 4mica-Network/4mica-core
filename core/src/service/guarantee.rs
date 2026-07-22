use crate::error::PersistDbError;
use crate::evm::guarantee::{guarantee_id_for_cycle, verify_guarantee_request_signature};
use crate::service::CoreService;
use crate::{
    auth::{
        access::{self, AccessContext},
        constants::SCOPE_GUARANTEE_ISSUE,
    },
    error::{ServiceError, ServiceResult},
    persist::repo,
};
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
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::str::FromStr;

impl CoreService {
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

    /// Checks only what core owns: the validator is whitelisted and the deadline is still ahead.
    /// Whether `params` make sense is the adapter's call.
    fn verify_validation_requirement(
        &self,
        validation: &ValidationRequirement,
        now_secs: u64,
    ) -> ServiceResult<()> {
        let adapter = self
            .inner
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

        Ok(())
    }

    fn guarantee_domain_for_version(&self, version: u64) -> ServiceResult<[u8; 32]> {
        self.inner
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
        BLSCert::sign(self.bls_secret_key(), claims)
            .map_err(|err| ServiceError::Other(anyhow!(err)))
    }

    async fn process_guarantee_request_claims_on<C: ConnectionTrait>(
        &self,
        conn: &C,
        claims: &PaymentGuaranteeRequestClaims,
    ) -> ServiceResult<()> {
        repo::lock_user_balance_for_guarantee_on(conn, claims)
            .await
            .map_err(Into::into)
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

        verify_guarantee_request_signature(&self.inner.public_params, &req)?;
        self.verify_guarantee_request_claims(&req.claims)?;
        self.check_settlement_timing_invariant()
            .map_err(|e| ServiceError::SettlementTimingHalted(format!("{e:#}")))?;

        repo::ensure_user_is_active(&self.inner.persist_ctx, req.claims.user_address()).await?;
        repo::ensure_user_is_active_if_exists(
            &self.inner.persist_ctx,
            req.claims.recipient_address(),
        )
        .await?;
        let active_cycle = self
            .get_or_create_active_cycle(req.claims.asset_address(), Utc::now())
            .await?;

        if req.claims.timestamp() < (active_cycle.period_start.and_utc().timestamp() as u64) {
            return Err(ServiceError::StaleTimestamp {
                timestamp: req.claims.timestamp(),
                cycle_start: active_cycle.period_start.and_utc().timestamp(),
            });
        }

        let validation_deadline = match req.claims.validation() {
            Some(validation) => Some(enforced_validation_deadline(
                validation,
                active_cycle.resolution_cutoff,
            )?),
            None => None,
        };

        let cycle_id_hash = crate::evm::clearing::claim_cycle_id(&active_cycle.id);
        let guarantee_id = guarantee_id_for_cycle(&active_cycle.id, &req.claims);

        if repo::get_guarantee_by_id_on(self.inner.persist_ctx.db.as_ref(), &guarantee_id)
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

        let max_attempts = self
            .inner
            .config
            .database_config
            .conflict_retries
            .saturating_add(1);
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self
                .issue_payment_guarantee_in_txn(
                    &req,
                    &active_cycle.id,
                    &guarantee_id,
                    &claims,
                    validation_deadline,
                )
                .await
            {
                Ok(cert) => return Ok(cert),
                Err(ServiceError::OptimisticLockConflict) if attempt < max_attempts => {
                    warn!(
                        "guarantee issuance hit balance lock conflict (attempt {attempt}/{max_attempts}); retrying"
                    );
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn issue_payment_guarantee_in_txn(
        &self,
        req: &PaymentGuaranteeRequest,
        cycle_id: &str,
        guarantee_id: &str,
        claims: &PaymentGuaranteeClaims,
        validation_deadline: Option<chrono::NaiveDateTime>,
    ) -> ServiceResult<BLSCert> {
        self.inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let self_clone = self.clone();
                let req = req.clone();
                let cycle_id = cycle_id.to_string();
                let guarantee_id = guarantee_id.to_string();
                let claims = claims.clone();
                Box::pin(async move {
                    self_clone
                        .process_guarantee_request_claims_on(txn, &req.claims)
                        .await?;

                    let cert: BLSCert = self_clone.create_bls_cert(claims.clone()).await?;
                    repo::prepare_and_store_cycle_guarantee_on(
                        txn,
                        repo::PrepareCycleGuaranteeInput {
                            claims: &claims,
                            cert: &cert,
                            request: &req,
                            cycle_id,
                            guarantee_id: guarantee_id.clone(),
                            settlement_status: settlement_status_for_request(&req.claims),
                        },
                    )
                    .await?;

                    if let Some(validation) = req.claims.validation() {
                        let deadline = validation_deadline.ok_or_else(|| {
                            ServiceError::Other(anyhow!(
                                "validated guarantee {guarantee_id} has no enforced deadline"
                            ))
                        })?;
                        repo::store_guarantee_validation_on(
                            txn,
                            repo::StoreGuaranteeValidationInput {
                                guarantee_id,
                                validator: validation.validator.clone(),
                                subject: validation.subject.to_string(),
                                deadline,
                                params: validation.params.to_vec(),
                            },
                        )
                        .await?;
                    }

                    Ok(cert)
                })
            })
            .await
            .map_err(|e| match e {
                sea_orm::TransactionError::Transaction(inner) => inner,
                sea_orm::TransactionError::Connection(err) => {
                    PersistDbError::DatabaseFailure(err).into()
                }
            })
    }

    pub async fn finalize_guarantee_payable_on<C: ConnectionTrait>(
        &self,
        conn: &C,
        guarantee_id: &str,
    ) -> ServiceResult<bool> {
        self.transition_guarantee_lifecycle_on(
            conn,
            guarantee_id,
            &[
                GuaranteeSettlementStatus::Issued,
                GuaranteeSettlementStatus::PendingValidation,
            ],
            GuaranteeSettlementStatus::FinalizedPayable,
            false,
        )
        .await
    }

    pub async fn dispute_guarantee_on<C: ConnectionTrait>(
        &self,
        conn: &C,
        guarantee_id: &str,
    ) -> ServiceResult<bool> {
        self.transition_guarantee_lifecycle_on(
            conn,
            guarantee_id,
            &[
                GuaranteeSettlementStatus::Issued,
                GuaranteeSettlementStatus::PendingValidation,
            ],
            GuaranteeSettlementStatus::Disputed,
            true,
        )
        .await
    }

    pub async fn cancel_guarantee_on<C: ConnectionTrait>(
        &self,
        conn: &C,
        guarantee_id: &str,
    ) -> ServiceResult<bool> {
        self.transition_guarantee_lifecycle_on(
            conn,
            guarantee_id,
            &[
                GuaranteeSettlementStatus::Issued,
                GuaranteeSettlementStatus::PendingValidation,
            ],
            GuaranteeSettlementStatus::Cancelled,
            true,
        )
        .await
    }

    async fn transition_guarantee_lifecycle_on<C: ConnectionTrait>(
        &self,
        conn: &C,
        guarantee_id: &str,
        allowed_from: &[GuaranteeSettlementStatus],
        target: GuaranteeSettlementStatus,
        release_locked_collateral: bool,
    ) -> ServiceResult<bool> {
        let guarantee = repo::get_guarantee_by_id_on(conn, guarantee_id)
            .await?
            .ok_or_else(|| ServiceError::NotFound(format!("Guarantee {guarantee_id}")))?;

        if guarantee.settlement_status == target {
            return Ok(false);
        }
        if !allowed_from.contains(&guarantee.settlement_status) {
            return Err(ServiceError::InvalidParams(format!(
                "guarantee {guarantee_id} is {:?}, cannot transition to {:?}",
                guarantee.settlement_status, target
            )));
        }

        let changed = repo::transition_guarantee_settlement_status_on(
            conn,
            guarantee_id,
            allowed_from,
            target,
            Utc::now().naive_utc(),
        )
        .await?;
        if changed && release_locked_collateral {
            repo::release_locked_collateral_for_guarantee_on(conn, &guarantee).await?;
        }
        Ok(changed)
    }
}

/// The deadline core enforces: `min(payer's cap, the cycle's resolution cutoff)`. Clamping to the
/// cutoff is what keeps a pending validation from outliving the cycle that would settle it.
fn enforced_validation_deadline(
    validation: &ValidationRequirement,
    resolution_cutoff: chrono::NaiveDateTime,
) -> ServiceResult<chrono::NaiveDateTime> {
    let Some(cap) = validation.deadline else {
        return Ok(resolution_cutoff);
    };

    let cap = chrono::DateTime::from_timestamp(cap as i64, 0)
        .ok_or_else(|| ServiceError::InvalidParams(format!("invalid validation deadline {cap}")))?
        .naive_utc();

    Ok(cap.min(resolution_cutoff))
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

    #[test]
    fn deadline_defaults_to_the_cycle_resolution_cutoff() {
        let cutoff = naive(1_700_010_000);
        let deadline = enforced_validation_deadline(&validation(None), cutoff).expect("deadline");
        assert_eq!(deadline, cutoff);
    }

    #[test]
    fn payer_deadline_tightens_but_never_extends_the_cutoff() {
        let cutoff = naive(1_700_010_000);

        let earlier = enforced_validation_deadline(&validation(Some(1_700_005_000)), cutoff)
            .expect("deadline");
        assert_eq!(earlier, naive(1_700_005_000));

        let later = enforced_validation_deadline(&validation(Some(1_700_020_000)), cutoff)
            .expect("deadline");
        assert_eq!(later, cutoff);
    }
}
