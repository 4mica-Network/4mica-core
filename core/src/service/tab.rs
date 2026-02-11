use crate::auth::access::{self, AccessContext};
use crate::auth::constants::SCOPE_TAB_CREATE;
use crate::{
    config::{DEFAULT_ASSET_ADDRESS, DEFAULT_TTL_SECS},
    error::{ServiceError, ServiceResult},
    persist::repo,
};
use alloy::primitives::U256;
use anyhow::anyhow;
use rpc::{CreatePaymentTabRequest, CreatePaymentTabResult};

use super::CoreService;

impl CoreService {
    pub async fn create_payment_tab(
        &self,
        auth: &AccessContext,
        req: CreatePaymentTabRequest,
    ) -> ServiceResult<CreatePaymentTabResult> {
        access::require_scope(auth, SCOPE_TAB_CREATE)?;
        access::require_recipient_match_or_facilitator(auth, &req.recipient_address)?;

        let ttl = req.ttl.unwrap_or(DEFAULT_TTL_SECS);
        let max_ttl = self.tab_expiration_time();
        let now = crate::util::now_naive();
        let now_ts = now.and_utc().timestamp();
        if now_ts < 0 {
            return Err(anyhow!("System time before epoch").into());
        }

        let asset_address = req
            .erc20_token
            .clone()
            .unwrap_or(DEFAULT_ASSET_ADDRESS.to_string());

        if let Some(existing) = repo::find_active_tab_by_triplet(
            &self.inner.persist_ctx,
            &req.user_address,
            &req.recipient_address,
            &asset_address,
        )
        .await?
        {
            let start_ts = existing.start_ts.and_utc().timestamp();
            let expiry_ts = start_ts.saturating_add(existing.ttl);
            let expired = existing.ttl <= 0 || expiry_ts < now_ts;

            if expired {
                let id = crate::util::parse_tab_id(&existing.id)?;
                repo::close_tab(&self.inner.persist_ctx, id).await?;
            } else {
                if existing.ttl <= 0 || existing.ttl as u64 > max_ttl {
                    return Err(ServiceError::InvalidParams(format!(
                        "tab ttl exceeds tab expiration time (ttl={}, max={})",
                        existing.ttl, max_ttl
                    )));
                }
                let id = crate::util::parse_tab_id(&existing.id)?;
                let next_req_id = repo::increment_and_get_last_req_id(
                    &self.inner.persist_ctx,
                    id,
                    self.inner.config.database_config.conflict_retries,
                )
                .await?;
                return Ok(CreatePaymentTabResult {
                    id,
                    user_address: existing.user_address,
                    recipient_address: existing.server_address,
                    erc20_token: Some(asset_address),
                    next_req_id,
                });
            }
        }

        if ttl > max_ttl {
            return Err(ServiceError::InvalidParams(format!(
                "tab ttl exceeds tab expiration time (ttl={}, max={})",
                ttl, max_ttl
            )));
        }

        let tab_id = crate::util::generate_tab_id(&req.user_address, &req.recipient_address, ttl);

        repo::create_pending_tab(
            &self.inner.persist_ctx,
            tab_id,
            &req.user_address,
            &req.recipient_address,
            &asset_address,
            now,
            ttl as i64,
        )
        .await?;

        Ok(CreatePaymentTabResult {
            id: tab_id,
            user_address: req.user_address,
            recipient_address: req.recipient_address,
            erc20_token: req.erc20_token,
            next_req_id: U256::ZERO,
        })
    }
}
