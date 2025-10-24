use crate::service::CoreService;
use crate::{
    auth::verify_promise_signature,
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
use rpc::common::*;
use std::str::FromStr;

impl CoreService {
    async fn preflight_promise_checks(&self, req: &PaymentGuaranteeRequest) -> ServiceResult<()> {
        verify_promise_signature(&self.inner.public_params, req)?;

        let promise = &req.claims;
        let last_opt = repo::get_last_guarantee_for_tab(&self.inner.persist_ctx, promise.tab_id)
            .await
            .map_err(ServiceError::from)?;

        let cur_req_id = promise.req_id;
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
                if promise.timestamp != prev_start_ts {
                    return Err(ServiceError::ModifiedStartTs);
                }
            }
            None => {
                info!(
                    "No previous guarantee found for tab_id={}. This must be the first request. req_id = {}",
                    promise.tab_id, promise.req_id
                );
                if promise.req_id != U256::ZERO {
                    return Err(ServiceError::InvalidRequestID);
                }
            }
        }

        let now_i64 = chrono::Utc::now().timestamp();
        if now_i64 < 0 {
            return Err(ServiceError::Other(anyhow!("System time before epoch")));
        }
        let now_secs = now_i64 as u64;

        if now_secs < promise.timestamp {
            return Err(ServiceError::FutureTimestamp);
        }

        let Some(tab) = repo::get_tab_by_id(&self.inner.persist_ctx, promise.tab_id).await? else {
            return Err(ServiceError::NotFound(u256_to_string(promise.tab_id)));
        };

        if (tab.status == TabStatus::Pending) != (promise.req_id == U256::ZERO) {
            return Err(ServiceError::InvalidRequestID);
        }

        if tab.status == TabStatus::Pending {
            let start_ts = chrono::Utc
                .timestamp_opt(promise.timestamp as i64, 0)
                .single()
                .ok_or_else(|| ServiceError::InvalidParams("Invalid timestamp".into()))?
                .naive_utc();
            repo::open_tab(&self.inner.persist_ctx, promise.tab_id, start_ts).await?;
        }

        if tab.asset_address != promise.asset_address {
            return Err(ServiceError::InvalidParams("Invalid asset address".into()));
        }

        if tab.ttl <= 0 {
            return Err(ServiceError::InvalidParams("Invalid tab TTL".into()));
        }

        let expiry = promise.timestamp.saturating_add(tab.ttl as u64);
        if expiry < now_secs {
            return Err(ServiceError::TabClosed);
        }

        Ok(())
    }

    async fn create_bls_cert(&self, promise: PaymentGuaranteeClaims) -> ServiceResult<BLSCert> {
        BLSCert::new(&self.bls_private_key(), promise)
            .map_err(|err| ServiceError::Other(anyhow!(err)))
    }

    pub async fn handle_promise(&self, req: PaymentGuaranteeRequest) -> ServiceResult<BLSCert> {
        let promise = req.claims.clone();

        info!(
            "Received guarantee request; tab_id={}, req_id={}, amount={}",
            promise.tab_id, promise.req_id, promise.amount
        );
        self.preflight_promise_checks(&req).await?;
        let cert: BLSCert = self.create_bls_cert(promise.clone()).await?;

        repo::lock_and_store_guarantee(&self.inner.persist_ctx, &promise, &cert)
            .await
            .map_err(ServiceError::from)?;
        Ok(cert)
    }
}
