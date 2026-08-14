//! Reading the signer's own positions.

use alloy::{primitives::U256, signers::Signer};

use crate::{
    client::{
        ClientCtx,
        model::{AssetBalanceInfo, StablecoinPosition, UserInfo},
    },
    error::{GetUserError, RecipientQueryError},
    validators::validate_address,
};

pub struct AccountClient<S> {
    ctx: ClientCtx<S>,
}

impl<S> Clone for AccountClient<S> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
        }
    }
}

impl<S> AccountClient<S> {
    pub(super) fn new(ctx: ClientCtx<S>) -> Self {
        Self { ctx }
    }
}

impl<S> AccountClient<S>
where
    S: Signer,
{
    /// Every asset the signer holds collateral in, with any pending withdrawal request.
    pub async fn assets(&self) -> Result<Vec<UserInfo>, GetUserError> {
        let assets = self
            .ctx
            .get_contract()
            .await?
            .getUserAllAssets(self.ctx.signer_address())
            .call()
            .await
            .map_err(GetUserError::from)?;

        Ok(assets.into_iter().map(|asset| asset.into()).collect())
    }

    /// Collateral deposited in `asset`, before any yield.
    pub async fn principal_balance(&self, asset: String) -> Result<U256, GetUserError> {
        let asset = self.parse_asset(&asset)?;

        self.ctx
            .get_contract()
            .await?
            .principalBalance(self.ctx.signer_address(), asset)
            .call()
            .await
            .map_err(GetUserError::from)
    }

    /// What the signer could withdraw from `asset` right now.
    pub async fn withdrawable_balance(&self, asset: String) -> Result<U256, GetUserError> {
        let asset = self.parse_asset(&asset)?;

        self.ctx
            .get_contract()
            .await?
            .withdrawableBalance(self.ctx.signer_address(), asset)
            .call()
            .await
            .map_err(GetUserError::from)
    }

    /// The signer's full position in a yield-bearing stablecoin: principal, yield and how it is
    /// split, plus the pool-level totals the split is derived from.
    pub async fn stablecoin_position(
        &self,
        asset: String,
    ) -> Result<StablecoinPosition, GetUserError> {
        let asset_address = self.parse_asset(&asset)?;
        let signer_address = self.ctx.signer_address();
        let contract = self.ctx.get_contract().await?;

        let principal = contract
            .principalBalance(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let guarantee_capacity = contract
            .guaranteeCapacity(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let gross_yield = contract
            .grossYield(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let protocol_yield_share = contract
            .protocolYieldShare(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let user_net_yield = contract
            .userNetYield(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let withdrawable_balance = contract
            .withdrawableBalance(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let total_user_scaled_balance = contract
            .totalUserScaledBalance(asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let protocol_scaled_balance = contract
            .protocolScaledBalance(asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let surplus_scaled_balance = contract
            .surplusScaledBalance(asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let contract_scaled_a_token_balance = contract
            .contractScaledATokenBalance(asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let stablecoin_a_token = contract
            .stablecoinAToken(asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;

        Ok(StablecoinPosition {
            asset,
            principal,
            guarantee_capacity,
            gross_yield,
            protocol_yield_share,
            user_net_yield,
            withdrawable_balance,
            total_user_scaled_balance,
            protocol_scaled_balance,
            surplus_scaled_balance,
            contract_scaled_a_token_balance,
            stablecoin_a_token: stablecoin_a_token.to_string(),
        })
    }

    fn parse_asset(&self, asset: &str) -> Result<alloy::primitives::Address, GetUserError> {
        validate_address(asset)
            .map_err(|_| GetUserError::Transport(format!("invalid ERC20 token address: {asset}")))
    }
}

impl<S> AccountClient<S>
where
    S: Signer + Sync,
{
    /// The signer's balance in `asset` as guarantees are accounted against it, including how much
    /// is currently locked. `None` when the signer holds nothing in that asset.
    ///
    /// Lags the chain: a fresh deposit appears once it has been observed and confirmed.
    pub async fn asset_balance(
        &self,
        asset_address: String,
    ) -> Result<Option<AssetBalanceInfo>, RecipientQueryError> {
        let user_address = self.ctx.signer_address().to_string();
        let balance = self
            .ctx
            .rpc_proxy()
            .await?
            .get_user_asset_balance(user_address, asset_address)
            .await?
            .map(Into::into);
        Ok(balance)
    }
}
