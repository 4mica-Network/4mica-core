use crate::auth::access::{self, AccessContext};
use crate::auth::constants::SCOPE_TAB_READ;
use crate::persist::mapper;
use crate::{
    error::ServiceResult,
    persist::{IntoUserTxInfo, repo},
};
use rpc::{AssetBalanceInfo, UserTransactionInfo};

use super::CoreService;

impl CoreService {
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
