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
    PaymentGuaranteeRequestClaimsV1, PaymentGuaranteeRequestClaimsV2,
    PaymentGuaranteeRequestEssentials,
};
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::str::FromStr;

impl CoreService {
    pub fn verify_guarantee_request_claims_v1(
        &self,
        claims: &PaymentGuaranteeRequestClaimsV1,
    ) -> ServiceResult<()> {
        let now_i64 = chrono::Utc::now().timestamp();
        if now_i64 < 0 {
            return Err(ServiceError::Other(anyhow!("System time before epoch")));
        }
        let now_secs = now_i64 as u64;

        if now_secs < claims.timestamp {
            return Err(ServiceError::FutureTimestamp);
        }

        let _claim_user = Address::from_str(&claims.user_address)
            .map_err(|_| ServiceError::InvalidParams("Invalid user address".into()))?;
        let _claim_recipient = Address::from_str(&claims.recipient_address)
            .map_err(|_| ServiceError::InvalidParams("Invalid recipient address".into()))?;
        let _claim_asset = Address::from_str(&claims.asset_address)
            .map_err(|_| ServiceError::InvalidParams("Invalid asset address".into()))?;

        Ok(())
    }

    pub fn verify_guarantee_request_claims_v2(
        &self,
        claims: &PaymentGuaranteeRequestClaimsV2,
    ) -> ServiceResult<()> {
        let base_claims = Self::v2_to_v1_claims(claims);
        self.verify_guarantee_request_claims_v1(&base_claims)?;

        claims
            .validate()
            .map_err(|err| ServiceError::InvalidParams(err.to_string()))?;

        let trusted_registries = &self.inner.trusted_validation_registry_set;
        if !trusted_registries.is_empty() {
            let claim_registry = claims.validation_policy.validation_registry_address;
            if !trusted_registries.contains(&claim_registry) {
                return Err(ServiceError::InvalidParams(format!(
                    "validation registry {} is not trusted",
                    claim_registry
                )));
            }
        }

        if claims.validation_policy.validation_chain_id != self.inner.public_params.chain_id {
            return Err(ServiceError::InvalidParams(format!(
                "validation_chain_id {} must match core chain_id {}",
                claims.validation_policy.validation_chain_id, self.inner.public_params.chain_id
            )));
        }

        Ok(())
    }

    fn v2_to_v1_claims(
        claims: &PaymentGuaranteeRequestClaimsV2,
    ) -> PaymentGuaranteeRequestClaimsV1 {
        PaymentGuaranteeRequestClaimsV1 {
            user_address: claims.user_address.clone(),
            recipient_address: claims.recipient_address.clone(),
            req_id: claims.req_id,
            amount: claims.amount,
            asset_address: claims.asset_address.clone(),
            timestamp: claims.timestamp,
        }
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

    pub fn verify_guarantee_request_claims(
        &self,
        claims: &PaymentGuaranteeRequestClaims,
    ) -> ServiceResult<()> {
        match claims {
            PaymentGuaranteeRequestClaims::V1(claims) => {
                self.verify_guarantee_request_claims_v1(claims)
            }
            PaymentGuaranteeRequestClaims::V2(claims) => {
                self.verify_guarantee_request_claims_v2(claims)
            }
        }
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
        if !self
            .inner
            .accepted_guarantee_versions
            .contains(&request_version)
        {
            let mut sorted: Vec<u64> = self
                .inner
                .accepted_guarantee_versions
                .iter()
                .copied()
                .collect();
            sorted.sort_unstable();
            let accepted_versions = sorted
                .into_iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(ServiceError::InvalidParams(format!(
                "guarantee request version {} is not accepted; accepted versions are [{}]",
                request_version, accepted_versions
            )));
        }

        info!(
            "Received cycle-native guarantee request variant {}; amount={}",
            request_version, amount
        );

        verify_guarantee_request_signature(&self.inner.public_params, &req)?;
        self.verify_guarantee_request_claims(&req.claims)?;

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
                .issue_payment_guarantee_in_txn(&req, &active_cycle.id, &guarantee_id, &claims)
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
                            guarantee_id,
                            settlement_status: settlement_status_for_request(&req.claims),
                        },
                    )
                    .await?;

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

    pub async fn finalize_guarantee_payable(&self, guarantee_id: &str) -> ServiceResult<bool> {
        self.transition_guarantee_lifecycle(
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

    pub async fn dispute_guarantee(&self, guarantee_id: &str) -> ServiceResult<bool> {
        self.transition_guarantee_lifecycle(
            guarantee_id,
            &[
                GuaranteeSettlementStatus::Issued,
                GuaranteeSettlementStatus::PendingValidation,
            ],
            GuaranteeSettlementStatus::Disputed,
            false,
        )
        .await
    }

    pub async fn cancel_guarantee(&self, guarantee_id: &str) -> ServiceResult<bool> {
        self.transition_guarantee_lifecycle(
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

    async fn transition_guarantee_lifecycle(
        &self,
        guarantee_id: &str,
        allowed_from: &[GuaranteeSettlementStatus],
        target: GuaranteeSettlementStatus,
        release_locked_collateral: bool,
    ) -> ServiceResult<bool> {
        let guarantee =
            repo::get_guarantee_by_id_on(self.inner.persist_ctx.db.as_ref(), guarantee_id)
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

        self.inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let allowed_from = allowed_from.to_vec();
                let guarantee = guarantee.clone();
                let guarantee_id = guarantee_id.to_string();
                let target = target.clone();
                Box::pin(async move {
                    let changed = repo::transition_guarantee_settlement_status_on(
                        txn,
                        &guarantee_id,
                        &allowed_from,
                        target,
                        Utc::now().naive_utc(),
                    )
                    .await?;
                    if changed && release_locked_collateral {
                        repo::release_locked_collateral_for_guarantee_on(txn, &guarantee).await?;
                    }
                    Ok(changed)
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
}

fn settlement_status_for_request(
    claims: &PaymentGuaranteeRequestClaims,
) -> GuaranteeSettlementStatus {
    if claims.validation_policy().is_some() {
        GuaranteeSettlementStatus::PendingValidation
    } else {
        GuaranteeSettlementStatus::FinalizedPayable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{B256, U256};
    use rpc::{GUARANTEE_CLAIMS_VERSION, PaymentGuaranteeValidationPolicyV2};

    fn v1_claims(req_id: u64) -> PaymentGuaranteeRequestClaims {
        PaymentGuaranteeRequestClaims::V1(PaymentGuaranteeRequestClaimsV1 {
            user_address: Address::repeat_byte(0x11).to_string(),
            recipient_address: Address::repeat_byte(0x22).to_string(),
            req_id: U256::from(req_id),
            amount: U256::from(7u64),
            asset_address: Address::ZERO.to_string(),
            timestamp: 1_700_000_000,
        })
    }

    fn v2_claims() -> PaymentGuaranteeRequestClaims {
        PaymentGuaranteeRequestClaims::V2(Box::new(PaymentGuaranteeRequestClaimsV2 {
            user_address: Address::repeat_byte(0x11).to_string(),
            recipient_address: Address::repeat_byte(0x22).to_string(),
            req_id: U256::from(1u64),
            amount: U256::from(7u64),
            asset_address: Address::ZERO.to_string(),
            timestamp: 1_700_000_000,
            validation_policy: PaymentGuaranteeValidationPolicyV2 {
                validation_registry_address: Address::repeat_byte(0x33),
                validation_request_hash: B256::repeat_byte(0x44),
                validation_chain_id: 84532,
                validator_address: Address::repeat_byte(0x55),
                validator_agent_id: U256::from(1u64),
                min_validation_score: 80,
                validation_subject_hash: B256::repeat_byte(0x66),
                job_hash: B256::repeat_byte(0x77),
                required_validation_tag: "hard-finality".to_string(),
            },
        }))
    }

    #[test]
    fn immediate_claims_are_payable_and_validation_claims_wait() {
        assert_eq!(
            v1_claims(1).version(),
            GUARANTEE_CLAIMS_VERSION,
            "test fixture should exercise the immediate-finality version"
        );
        assert_eq!(
            settlement_status_for_request(&v1_claims(1)),
            GuaranteeSettlementStatus::FinalizedPayable
        );
        assert_eq!(
            settlement_status_for_request(&v2_claims()),
            GuaranteeSettlementStatus::PendingValidation
        );
    }
}
