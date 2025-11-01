use crate::service::CoreService;
use crate::{
    auth::verify_guarantee_request_signature,
    error::{ServiceError, ServiceResult},
    persist::repo,
    util::u256_to_string,
};
use alloy::primitives::U256;
use anyhow::anyhow;
use chrono::TimeZone;
use crypto::bls::BLSCert;
use entities::sea_orm_active_enums::TabStatus;
use log::info;
use rpc::{
    PaymentGuaranteeClaims, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims,
    PaymentGuaranteeRequestClaimsV1, PaymentGuaranteeRequestEssentials,
};
use std::str::FromStr;

impl CoreService {
    async fn verify_guarantee_request_claims_v1(
        &self,
        claims: &PaymentGuaranteeRequestClaimsV1,
    ) -> ServiceResult<()> {
        let last_opt = repo::get_last_guarantee_for_tab(&self.inner.persist_ctx, claims.tab_id)
            .await
            .map_err(ServiceError::from)?;

        let cur_req_id = claims.req_id;
        match last_opt {
            Some(ref last) => {
                let prev_req_id = U256::from_str(&last.req_id).map_err(|e| {
                    ServiceError::InvalidParams(format!("Invalid prev_req_id: {}", e))
                })?;

                if cur_req_id.wrapping_sub(prev_req_id) != U256::from(1u8) {
                    info!(
                        "Invalid req_id: current={}, previous={}",
                        cur_req_id, prev_req_id
                    );
                    return Err(ServiceError::InvalidRequestID);
                }

                let prev_ts_i64 = last.start_ts.and_utc().timestamp();
                if prev_ts_i64 < 0 {
                    return Err(ServiceError::Other(anyhow!("Negative previous start_ts")));
                }

                let prev_start_ts = prev_ts_i64 as u64;
                if claims.timestamp != prev_start_ts {
                    return Err(ServiceError::ModifiedStartTs);
                }
            }
            None => {
                info!(
                    "No previous guarantee found for tab_id={}. This must be the first request. req_id = {}",
                    claims.tab_id, claims.req_id
                );
                if claims.req_id != U256::ZERO {
                    return Err(ServiceError::InvalidRequestID);
                }
            }
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

        if (tab.status == TabStatus::Pending) != (claims.req_id == U256::ZERO) {
            return Err(ServiceError::InvalidRequestID);
        }

        if tab.status == TabStatus::Pending {
            let start_ts = chrono::Utc
                .timestamp_opt(claims.timestamp as i64, 0)
                .single()
                .ok_or_else(|| ServiceError::InvalidParams("Invalid timestamp".into()))?
                .naive_utc();
            repo::open_tab(&self.inner.persist_ctx, claims.tab_id, start_ts).await?;
        }

        if tab.asset_address != claims.asset_address {
            return Err(ServiceError::InvalidParams("Invalid asset address".into()));
        }

        if tab.ttl <= 0 {
            return Err(ServiceError::InvalidParams("Invalid tab TTL".into()));
        }

        let expiry = claims.timestamp.saturating_add(tab.ttl as u64);
        if expiry < now_secs {
            return Err(ServiceError::TabClosed);
        }

        Ok(())
    }

    async fn create_bls_cert(&self, claims: PaymentGuaranteeClaims) -> ServiceResult<BLSCert> {
        BLSCert::new(&self.bls_private_key(), claims)
            .map_err(|err| ServiceError::Other(anyhow!(err)))
    }

    pub async fn issue_payment_guarantee(
        &self,
        req: PaymentGuaranteeRequest,
    ) -> ServiceResult<BLSCert> {
        let tab_id = req.claims.tab_id();
        let req_id = req.claims.req_id();
        let amount = req.claims.amount();

        info!(
            "Received guarantee request v1; tab_id={}, req_id={}, amount={}",
            tab_id, req_id, amount
        );

        verify_guarantee_request_signature(&self.inner.public_params, &req)?;

        match &req.claims {
            PaymentGuaranteeRequestClaims::V1(claims) => {
                self.verify_guarantee_request_claims_v1(claims).await?;
            }
        }

        let total_amount = {
            let tab_guarantees =
                repo::get_guarantees_for_tab(&self.inner.persist_ctx, tab_id).await?;
            let total_until_now: U256 = tab_guarantees
                .into_iter()
                .map(|g| U256::from_str(&g.value))
                .collect::<Result<Vec<U256>, _>>()
                .map_err(|e| ServiceError::Other(anyhow!(e)))?
                .iter()
                .sum();

            total_until_now
                .checked_add(amount)
                .ok_or_else(|| ServiceError::Other(anyhow!("Total amount overflow")))?
        };

        let guarantee_claims = PaymentGuaranteeClaims::from_request(
            &req.claims,
            self.inner.guarantee_domain,
            total_amount,
        );
        let cert: BLSCert = self.create_bls_cert(guarantee_claims.clone()).await?;

        repo::lock_and_store_guarantee(&self.inner.persist_ctx, &guarantee_claims, &cert)
            .await
            .map_err(ServiceError::from)?;
        Ok(cert)
    }
}
