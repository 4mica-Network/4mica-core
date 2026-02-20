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
    util::u256_to_string,
};
use alloy::primitives::Address;
use anyhow::anyhow;
use chrono::TimeZone;
use crypto::bls::{BLSCert, BlsClaims};
use entities::sea_orm_active_enums::{SettlementStatus, TabStatus};
use log::info;
use rpc::{
    PaymentGuaranteeClaims, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestClaimsV1, PaymentGuaranteeRequestEssentials,
};
use sea_orm::TransactionTrait;
use std::str::FromStr;

impl CoreService {
    pub async fn verify_guarantee_request_claims_v1(
        &self,
        claims: &PaymentGuaranteeRequestClaimsV1,
    ) -> ServiceResult<()> {
        let existing_guarantee =
            repo::get_guarantee(&self.inner.persist_ctx, claims.tab_id, claims.req_id).await?;
        if existing_guarantee.is_some() {
            return Err(ServiceError::DuplicateGuarantee {
                req_id: claims.req_id,
            });
        }

        let now_i64 = chrono::Utc::now().timestamp();
        if now_i64 < 0 {
            return Err(ServiceError::Other(anyhow!("System time before epoch")));
        }
        let now_secs = now_i64 as u64;

        if now_secs < claims.timestamp {
            return Err(ServiceError::FutureTimestamp);
        }

        let Some(tab) = repo::get_tab_by_id(&self.inner.persist_ctx, claims.tab_id).await? else {
            return Err(ServiceError::NotFound(u256_to_string(claims.tab_id)));
        };

        if tab.status == TabStatus::Closed || tab.settlement_status != SettlementStatus::Pending {
            return Err(ServiceError::TabClosed);
        }

        let tab_user = Address::from_str(&tab.user_address)
            .map_err(|_| ServiceError::Other(anyhow!("Invalid tab user address")))?;
        let claim_user = Address::from_str(&claims.user_address)
            .map_err(|_| ServiceError::InvalidParams("Invalid user address".into()))?;
        if tab_user != claim_user {
            return Err(ServiceError::InvalidParams(
                "User address does not match tab".into(),
            ));
        }
        let tab_recipient = Address::from_str(&tab.server_address)
            .map_err(|_| ServiceError::Other(anyhow!("Invalid tab recipient address")))?;
        let claim_recipient = Address::from_str(&claims.recipient_address)
            .map_err(|_| ServiceError::InvalidParams("Invalid recipient address".into()))?;
        if tab_recipient != claim_recipient {
            return Err(ServiceError::InvalidParams(
                "Recipient address does not match tab".into(),
            ));
        }

        if tab.asset_address != claims.asset_address {
            return Err(ServiceError::InvalidParams("Invalid asset address".into()));
        }

        if tab.ttl <= 0 {
            return Err(ServiceError::InvalidParams("Invalid tab TTL".into()));
        }
        let max_ttl = self.tab_expiration_time();
        if tab.ttl as u64 > max_ttl {
            return Err(ServiceError::InvalidParams(format!(
                "tab ttl exceeds tab expiration time (ttl={}, max={})",
                tab.ttl, max_ttl
            )));
        }

        let (tab_start_ts_i64, tab_ttl) = if tab.status == TabStatus::Pending {
            let start_ts = chrono::Utc
                .timestamp_opt(claims.timestamp as i64, 0)
                .single()
                .ok_or_else(|| ServiceError::InvalidParams("Invalid timestamp".into()))?
                .naive_utc();

            (start_ts.and_utc().timestamp(), tab.ttl)
        } else {
            (tab.start_ts.and_utc().timestamp(), tab.ttl)
        };

        if tab_start_ts_i64 < 0 {
            return Err(ServiceError::Other(anyhow!("Negative tab start_ts")));
        }

        let tab_start_ts = tab_start_ts_i64 as u64;
        let tab_expiry = tab_start_ts.saturating_add(tab_ttl as u64);

        // Always validate the claimed timestamp against the stored tab window.
        if claims.timestamp < tab_start_ts || claims.timestamp > tab_expiry {
            return Err(ServiceError::ModifiedStartTs);
        }

        if tab_expiry < now_secs {
            return Err(ServiceError::TabClosed);
        }

        Ok(())
    }

    async fn create_bls_cert(&self, claims: PaymentGuaranteeClaims) -> ServiceResult<BLSCert> {
        let claims_bytes = <PaymentGuaranteeClaims as TryInto<Vec<u8>>>::try_into(claims)
            .map_err(ServiceError::Other)?;
        let claims = BlsClaims::from_bytes(claims_bytes);
        BLSCert::sign(self.bls_secret_key(), claims)
            .map_err(|err| ServiceError::Other(anyhow!(err)))
    }

    pub async fn issue_payment_guarantee(
        &self,
        auth: &AccessContext,
        req: PaymentGuaranteeRequest,
    ) -> ServiceResult<BLSCert> {
        access::require_scope(auth, SCOPE_GUARANTEE_ISSUE)?;
        access::require_recipient_match_or_facilitator(auth, req.claims.recipient_address())?;

        let tab_id = req.claims.tab_id();
        let amount = req.claims.amount();

        info!(
            "Received guarantee request v1; tab_id={}, amount={}",
            tab_id, amount
        );

        verify_guarantee_request_signature(&self.inner.public_params, &req)?;

        repo::ensure_user_is_active(&self.inner.persist_ctx, req.claims.user_address()).await?;
        repo::ensure_user_is_active_if_exists(
            &self.inner.persist_ctx,
            req.claims.recipient_address(),
        )
        .await?;

        let cert = self
            .inner
            .persist_ctx
            .db
            .transaction::<_, _, ServiceError>(|txn| {
                let self_clone = self.clone();
                Box::pin(async move {
                    let total_amount = match &req.claims {
                        PaymentGuaranteeRequestClaims::V1(claims) => {
                            self_clone
                                .verify_guarantee_request_claims_v1(claims)
                                .await?;
                            repo::update_user_balance_and_tab_for_guarantee_on(txn, claims).await?
                        }
                    };

                    let claims = PaymentGuaranteeClaims::from_request(
                        &req.claims,
                        self_clone.inner.guarantee_domain,
                        total_amount,
                    );
                    let cert: BLSCert = self_clone.create_bls_cert(claims.clone()).await?;
                    repo::prepare_and_store_guarantee_on(txn, &claims, &cert, &req).await?;

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
