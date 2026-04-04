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
        if now.and_utc().timestamp() < 0 {
            return Err(anyhow!("System time before epoch").into());
        }

        let asset_address = req
            .erc20_token
            .clone()
            .unwrap_or(DEFAULT_ASSET_ADDRESS.to_string());
        if !self
            .inner
            .accepted_guarantee_versions
            .contains(&req.guarantee_version)
        {
            return Err(ServiceError::InvalidParams(format!(
                "guarantee version {} is not accepted by core",
                req.guarantee_version
            )));
        }

        if ttl > max_ttl {
            return Err(ServiceError::InvalidParams(format!(
                "tab ttl exceeds tab expiration time (ttl={}, max={})",
                ttl, max_ttl
            )));
        }

        let tab_id = crate::util::generate_tab_id(&req.user_address, &req.recipient_address, ttl);
        let user_address = repo::Address::parse(&req.user_address)?;
        let recipient_address = repo::Address::parse(&req.recipient_address)?;
        let repo_asset_address = repo::Address::parse(&asset_address)?;

        match repo::create_or_get_active_tab(
            &self.inner.persist_ctx,
            repo::CreatePendingTabInput {
                tab_id,
                user_address,
                server_address: recipient_address,
                asset_address: repo_asset_address,
                guarantee_version: req.guarantee_version,
                start_ts: now,
                ttl: ttl as i64,
            },
            max_ttl,
            self.inner.config.database_config.conflict_retries,
        )
        .await?
        {
            repo::CreateOrGetActiveTab::Existing(existing) => {
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
                    asset_address: existing.asset_address,
                    guarantee_version: existing.accepted_guarantee_version.ok_or_else(|| {
                        ServiceError::Other(anyhow!("existing tab missing guarantee version"))
                    })? as u64,
                    next_req_id,
                });
            }
            repo::CreateOrGetActiveTab::Created(_) => {}
        }

        Ok(CreatePaymentTabResult {
            id: tab_id,
            user_address: req.user_address,
            recipient_address: req.recipient_address,
            erc20_token: req.erc20_token,
            asset_address,
            guarantee_version: req.guarantee_version,
            next_req_id: U256::ZERO,
        })
    }
}
