use crate::error::PersistDbError;
use crate::service::CoreService;
use crate::{
    auth::{
        access::{self, AccessContext},
        constants::SCOPE_GUARANTEE_ISSUE,
        verify_guarantee_request_signature,
    },
    error::{ServiceError, ServiceResult},
    persist::repo,
};
use alloy::primitives::{Address, B256, U256, keccak256};
use anyhow::anyhow;
use chrono::Utc;
use crypto::bls::{BLSCert, BlsClaims};
use entities::sea_orm_active_enums::GuaranteeSettlementStatus;
use log::info;
use rpc::{
    GUARANTEE_CLAIMS_VERSION_V2, PaymentGuaranteeClaims, PaymentGuaranteeRequest,
    PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1,
    PaymentGuaranteeRequestClaimsV2, PaymentGuaranteeRequestEssentials,
};
use sea_orm::{ConnectionTrait, TransactionTrait};
use std::str::FromStr;

impl CoreService {
    pub async fn verify_guarantee_request_claims_v1(
        &self,
        claims: &PaymentGuaranteeRequestClaimsV1,
        _claims_version: u64,
    ) -> ServiceResult<()> {
        let now_i64 = chrono::Utc::now().timestamp();
        if now_i64 < 0 {
            return Err(ServiceError::Other(anyhow!("System time before epoch")));
        }
        let now_secs = now_i64 as u64;

        if now_secs < claims.timestamp {
            return Err(ServiceError::FutureTimestamp);
        }

        let claim_user = Address::from_str(&claims.user_address)
            .map_err(|_| ServiceError::InvalidParams("Invalid user address".into()))?;
        let claim_recipient = Address::from_str(&claims.recipient_address)
            .map_err(|_| ServiceError::InvalidParams("Invalid recipient address".into()))?;
        let claim_asset = Address::from_str(&claims.asset_address)
            .map_err(|_| ServiceError::InvalidParams("Invalid asset address".into()))?;
        let _ = (claim_user, claim_recipient, claim_asset);

        Ok(())
    }

    pub async fn verify_guarantee_request_claims_v2(
        &self,
        claims: &PaymentGuaranteeRequestClaimsV2,
    ) -> ServiceResult<()> {
        let base_claims = Self::v2_to_v1_claims(claims);
        self.verify_guarantee_request_claims_v1(&base_claims, GUARANTEE_CLAIMS_VERSION_V2)
            .await?;

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

    pub async fn verify_guarantee_request_claims(
        &self,
        claims: &PaymentGuaranteeRequestClaims,
    ) -> ServiceResult<()> {
        let version = claims.version();
        match claims {
            PaymentGuaranteeRequestClaims::V1(claims) => {
                self.verify_guarantee_request_claims_v1(claims, version)
                    .await
            }
            PaymentGuaranteeRequestClaims::V2(claims) => {
                self.verify_guarantee_request_claims_v2(claims).await
            }
        }
    }

    async fn process_guarantee_request_claims_on<C: ConnectionTrait>(
        &self,
        conn: &C,
        claims: &PaymentGuaranteeRequestClaims,
    ) -> ServiceResult<()> {
        self.verify_guarantee_request_claims(claims).await?;
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
            "Received cycle-native guarantee request {}; amount={}",
            request_version, amount
        );

        verify_guarantee_request_signature(&self.inner.public_params, &req)?;

        repo::ensure_user_is_active(&self.inner.persist_ctx, req.claims.user_address()).await?;
        repo::ensure_user_is_active_if_exists(
            &self.inner.persist_ctx,
            req.claims.recipient_address(),
        )
        .await?;
        let active_cycle = self
            .get_or_create_active_cycle(req.claims.asset_address(), Utc::now())
            .await?;
        let signed_cycle_id = cycle_claim_id(&active_cycle.id);
        let guarantee_id = guarantee_id_for(&active_cycle.id, &req.claims);
        let legacy_storage_id = legacy_storage_id_for(&guarantee_id);

        if repo::get_guarantee_by_id_on(self.inner.persist_ctx.db.as_ref(), &guarantee_id)
            .await?
            .is_some()
        {
            return Err(ServiceError::DuplicateGuarantee {
                req_id: req.claims.req_id(),
            });
        }

        let cert = self
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let self_clone = self.clone();
                let cycle_id = active_cycle.id.clone();
                let guarantee_id = guarantee_id.clone();
                Box::pin(async move {
                    if repo::get_guarantee_by_id_on(txn, &guarantee_id)
                        .await?
                        .is_some()
                    {
                        return Err(ServiceError::DuplicateGuarantee {
                            req_id: req.claims.req_id(),
                        });
                    }
                    self_clone
                        .process_guarantee_request_claims_on(txn, &req.claims)
                        .await?;
                    let guarantee_domain =
                        self_clone.guarantee_domain_for_version(request_version)?;

                    let claims = PaymentGuaranteeClaims::from_request(
                        &req.claims,
                        guarantee_domain,
                        signed_cycle_id,
                    );
                    let cert: BLSCert = self_clone.create_bls_cert(claims.clone()).await?;
                    repo::prepare_and_store_cycle_guarantee_on(
                        txn,
                        repo::PrepareCycleGuaranteeInput {
                            claims: &claims,
                            cert: &cert,
                            request: &req,
                            cycle_id,
                            guarantee_id,
                            legacy_storage_id,
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
            })?;

        Ok(cert)
    }
}

fn cycle_claim_id(cycle_id: &str) -> U256 {
    U256::from_be_bytes(keccak256(cycle_id.as_bytes()).into())
}

fn legacy_storage_id_for(guarantee_id: &str) -> U256 {
    U256::from_be_bytes(keccak256(guarantee_id.as_bytes()).into())
}

fn guarantee_id_for(cycle_id: &str, claims: &PaymentGuaranteeRequestClaims) -> String {
    let digest = guarantee_digest(cycle_id, claims);
    format!("0x{}", hex::encode(digest.as_slice()))
}

fn guarantee_digest(cycle_id: &str, claims: &PaymentGuaranteeRequestClaims) -> B256 {
    let mut encoded = Vec::new();
    for part in [
        b"4MICA_CYCLE_GUARANTEE_V1".as_slice(),
        cycle_id.as_bytes(),
        claims.user_address().as_bytes(),
        claims.recipient_address().as_bytes(),
        claims.asset_address().as_bytes(),
        claims.req_id().to_string().as_bytes(),
        claims.version().to_string().as_bytes(),
    ] {
        encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
        encoded.extend_from_slice(part);
    }
    keccak256(encoded)
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
    use alloy::primitives::B256;
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
    fn cycle_claim_id_is_stable_and_cycle_scoped() {
        let first = cycle_claim_id("0x0000000000000000000000000000000000000000:1777248000");
        let second = cycle_claim_id("0x0000000000000000000000000000000000000000:1777248000");
        let other = cycle_claim_id("0x0000000000000000000000000000000000000000:1777334400");

        assert_eq!(first, second);
        assert_ne!(first, U256::ZERO);
        assert_ne!(first, other);
    }

    #[test]
    fn guarantee_id_is_stable_and_microtransaction_scoped() {
        let cycle_id = "0x0000000000000000000000000000000000000000:1777248000";
        let first = guarantee_id_for(cycle_id, &v1_claims(1));
        let second = guarantee_id_for(cycle_id, &v1_claims(1));
        let other = guarantee_id_for(cycle_id, &v1_claims(2));

        assert_eq!(first, second);
        assert_ne!(first, other);
        assert!(first.starts_with("0x"));
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
