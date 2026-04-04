use crate::auth::access::{self, AccessContext};
use crate::auth::constants::SCOPE_TAB_CREATE;
use crate::{
    config::{DEFAULT_ASSET_ADDRESS, DEFAULT_TTL_SECS},
    error::{PersistDbError, ServiceError, ServiceResult},
    persist::repo,
};
use alloy::primitives::U256;
use anyhow::anyhow;
use rpc::{CreatePaymentTabRequest, CreatePaymentTabResult};

use super::CoreService;

const UNIQUE_ACTIVE_TAB_IDENTITY_INDEX: &str = "uniq_active_tab_identity";

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

        if let Some(existing) = repo::find_active_tab_by_key(
            &self.inner.persist_ctx,
            &req.user_address,
            &req.recipient_address,
            &asset_address,
            req.guarantee_version,
        )
        .await?
        {
            let start_ts = existing.start_ts.and_utc().timestamp();
            let expiry_ts = start_ts.saturating_add(existing.ttl);
            let expired = existing.ttl <= 0 || expiry_ts < now_ts;

            let id = crate::util::parse_tab_id(&existing.id)?;
            if expired {
                repo::close_tab(&self.inner.persist_ctx, id).await?;
            } else {
                // We should close the tab if the ttl is not valid.
                // Otherwise, the user won't be able to get a tab with the same triplet.
                if existing.ttl <= 0 || existing.ttl as u64 > max_ttl {
                    repo::close_tab(&self.inner.persist_ctx, id).await?;
                } else {
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
            }
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

        match repo::create_pending_tab(
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
        )
        .await
        {
            Ok(()) => {}
            Err(PersistDbError::DatabaseFailure(db_err))
                if repo::common::constraint_name(&db_err).as_deref()
                    == Some(UNIQUE_ACTIVE_TAB_IDENTITY_INDEX) =>
            {
                let existing = repo::find_active_tab_by_key(
                    &self.inner.persist_ctx,
                    &req.user_address,
                    &req.recipient_address,
                    &asset_address,
                    req.guarantee_version,
                )
                .await?
                .ok_or_else(|| {
                    ServiceError::Other(anyhow!(
                        "active tab uniqueness conflict without a refetchable tab"
                    ))
                })?;

                let next_req_id = repo::increment_and_get_last_req_id(
                    &self.inner.persist_ctx,
                    crate::util::parse_tab_id(&existing.id)?,
                    self.inner.config.database_config.conflict_retries,
                )
                .await?;

                return Ok(CreatePaymentTabResult {
                    id: crate::util::parse_tab_id(&existing.id)?,
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
            Err(err) => return Err(err.into()),
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
