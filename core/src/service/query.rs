use crate::auth::access::{self, AccessContext};
use crate::auth::constants::SCOPE_TAB_READ;
use crate::persist::mapper;
use crate::{
    error::ServiceResult,
    persist::{IntoUserTxInfo, repo},
    util::u256_to_string,
};
use alloy::primitives::U256;
use entities::{sea_orm_active_enums::SettlementStatus, tabs};
use rpc::{
    AssetBalanceInfo, CollateralEventInfo, GuaranteeInfo, PendingRemunerationInfo, TabInfo,
    UserTransactionInfo,
};

use super::CoreService;

impl CoreService {
    pub async fn list_tabs_for_recipient(
        &self,
        auth: &AccessContext,
        recipient_address: String,
        settlement_statuses: &[SettlementStatus],
    ) -> ServiceResult<Vec<TabInfo>> {
        access::require_scope(auth, SCOPE_TAB_READ)?;
        access::require_recipient_match_or_facilitator(auth, &recipient_address)?;

        let tabs = repo::get_tabs_for_recipient(
            &self.inner.persist_ctx,
            &recipient_address,
            settlement_statuses,
        )
        .await?;

        tabs.into_iter()
            .map(mapper::tab_model_to_info)
            .collect::<ServiceResult<Vec<_>>>()
    }

    pub async fn list_pending_remunerations(
        &self,
        auth: &AccessContext,
        recipient_address: String,
    ) -> ServiceResult<Vec<PendingRemunerationInfo>> {
        access::require_scope(auth, SCOPE_TAB_READ)?;
        access::require_recipient_match_or_facilitator(auth, &recipient_address)?;

        let tabs = repo::get_tabs_for_recipient(
            &self.inner.persist_ctx,
            &recipient_address,
            &[SettlementStatus::Pending],
        )
        .await?;

        let mut items = Vec::with_capacity(tabs.len());
        for tab in tabs {
            let tab_info = mapper::tab_model_to_info(tab)?;
            let latest_guarantee =
                repo::get_last_guarantee_for_tab(&self.inner.persist_ctx, tab_info.tab_id)
                    .await?
                    .map(mapper::guarantee_model_to_info)
                    .transpose()?;

            items.push(PendingRemunerationInfo {
                tab: tab_info,
                latest_guarantee,
            });
        }

        Ok(items)
    }

    pub async fn get_tab(
        &self,
        auth: &AccessContext,
        tab_id: U256,
    ) -> ServiceResult<Option<TabInfo>> {
        access::require_scope(auth, SCOPE_TAB_READ)?;

        let Some(tab) = repo::get_tab_by_id(&self.inner.persist_ctx, tab_id).await? else {
            return Ok(None);
        };
        access::require_tab_owner_or_facilitator(auth, &tab)?;

        Some(mapper::tab_model_to_info(tab)).transpose()
    }

    async fn load_tab_for_read(
        &self,
        auth: &AccessContext,
        tab_id: U256,
    ) -> ServiceResult<tabs::Model> {
        access::require_scope(auth, SCOPE_TAB_READ)?;

        let tab = repo::get_tab_by_id(&self.inner.persist_ctx, tab_id)
            .await?
            .ok_or_else(|| crate::error::ServiceError::NotFound(u256_to_string(tab_id)))?;
        access::require_tab_owner_or_facilitator(auth, &tab)?;

        Ok(tab)
    }

    pub async fn get_tab_guarantees(
        &self,
        auth: &AccessContext,
        tab_id: U256,
    ) -> ServiceResult<Vec<GuaranteeInfo>> {
        self.load_tab_for_read(auth, tab_id).await?;

        let rows = repo::get_guarantees_for_tab(&self.inner.persist_ctx, tab_id).await?;
        rows.into_iter()
            .map(mapper::guarantee_model_to_info)
            .collect::<ServiceResult<Vec<_>>>()
    }

    pub async fn get_latest_guarantee(
        &self,
        auth: &AccessContext,
        tab_id: U256,
    ) -> ServiceResult<Option<GuaranteeInfo>> {
        self.load_tab_for_read(auth, tab_id).await?;

        let maybe = repo::get_last_guarantee_for_tab(&self.inner.persist_ctx, tab_id).await?;
        maybe.map(mapper::guarantee_model_to_info).transpose()
    }

    pub async fn get_guarantee(
        &self,
        auth: &AccessContext,
        tab_id: U256,
        req_id: U256,
    ) -> ServiceResult<Option<GuaranteeInfo>> {
        self.load_tab_for_read(auth, tab_id).await?;

        let maybe = repo::get_guarantee(&self.inner.persist_ctx, tab_id, req_id).await?;
        maybe.map(mapper::guarantee_model_to_info).transpose()
    }

    pub async fn list_recipient_payments(
        &self,
        auth: &AccessContext,
        recipient_address: String,
    ) -> ServiceResult<Vec<UserTransactionInfo>> {
        access::require_scope(auth, SCOPE_TAB_READ)?;
        access::require_recipient_match(auth, &recipient_address)?;

        let rows =
            repo::get_recipient_transactions(&self.inner.persist_ctx, &recipient_address).await?;
        rows.into_iter()
            .map(|row| row.into_user_tx_info())
            .collect::<ServiceResult<Vec<_>>>()
    }

    pub async fn get_collateral_events_for_tab(
        &self,
        auth: &AccessContext,
        tab_id: U256,
    ) -> ServiceResult<Vec<CollateralEventInfo>> {
        self.load_tab_for_read(auth, tab_id).await?;

        let rows = repo::get_collateral_events_for_tab(&self.inner.persist_ctx, tab_id).await?;
        rows.into_iter()
            .map(mapper::collateral_event_model_to_info)
            .collect::<ServiceResult<Vec<_>>>()
    }

    pub async fn get_user_asset_balance(
        &self,
        auth: &AccessContext,
        user_address: String,
        asset_address: String,
    ) -> ServiceResult<Option<AssetBalanceInfo>> {
        access::require_scope(auth, SCOPE_TAB_READ)?;

        let Some(balance) =
            repo::get_user_asset_balance(&self.inner.persist_ctx, &user_address, &asset_address)
                .await?
        else {
            return Ok(None);
        };

        Some(mapper::asset_balance_model_to_info(balance)).transpose()
    }
}
