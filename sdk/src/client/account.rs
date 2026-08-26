//! Reading the signer's own balances and positions.

use alloy::{
    primitives::{Address, U256},
    signers::Signer,
};

use crate::{
    client::{
        ClientCtx,
        model::{Asset, AssetBalanceInfo, AssetPosition, StablecoinPosition},
    },
    error::AccountError,
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
    /// The signer's position in every asset the contract knows them by.
    pub async fn assets(&self) -> Result<Vec<AssetPosition>, AccountError> {
        let assets = self
            .ctx
            .get_contract()
            .await?
            .getUserAllAssets(self.ctx.signer_address())
            .call()
            .await
            .map_err(AccountError::from)?;

        Ok(assets.into_iter().map(|asset| asset.into()).collect())
    }

    /// Collateral deposited in `asset`, before any yield.
    pub async fn principal_balance(&self, asset: Asset) -> Result<U256, AccountError> {
        self.ctx
            .get_contract()
            .await?
            .principalBalance(self.ctx.signer_address(), asset.address())
            .call()
            .await
            .map_err(AccountError::from)
    }

    /// What the signer could withdraw from `asset` right now.
    pub async fn withdrawable_balance(&self, asset: Asset) -> Result<U256, AccountError> {
        self.ctx
            .get_contract()
            .await?
            .withdrawableBalance(self.ctx.signer_address(), asset.address())
            .call()
            .await
            .map_err(AccountError::from)
    }

    /// The signer's full position in a yield-bearing stablecoin: principal, yield and how it is
    /// split, plus the pool-level totals the split is derived from.
    pub async fn stablecoin_position(
        &self,
        token: Address,
    ) -> Result<StablecoinPosition, AccountError> {
        let signer_address = self.ctx.signer_address();
        let contract = self.ctx.get_contract().await?;

        let principal = contract
            .principalBalance(signer_address, token)
            .call()
            .await
            .map_err(AccountError::from)?;
        let guarantee_capacity = contract
            .guaranteeCapacity(signer_address, token)
            .call()
            .await
            .map_err(AccountError::from)?;
        let gross_yield = contract
            .grossYield(signer_address, token)
            .call()
            .await
            .map_err(AccountError::from)?;
        let protocol_yield_share = contract
            .protocolYieldShare(signer_address, token)
            .call()
            .await
            .map_err(AccountError::from)?;
        let user_net_yield = contract
            .userNetYield(signer_address, token)
            .call()
            .await
            .map_err(AccountError::from)?;
        let withdrawable_balance = contract
            .withdrawableBalance(signer_address, token)
            .call()
            .await
            .map_err(AccountError::from)?;
        let total_user_scaled_balance = contract
            .totalUserScaledBalance(token)
            .call()
            .await
            .map_err(AccountError::from)?;
        let protocol_scaled_balance = contract
            .protocolScaledBalance(token)
            .call()
            .await
            .map_err(AccountError::from)?;
        let surplus_scaled_balance = contract
            .surplusScaledBalance(token)
            .call()
            .await
            .map_err(AccountError::from)?;
        let contract_scaled_a_token_balance = contract
            .contractScaledATokenBalance(token)
            .call()
            .await
            .map_err(AccountError::from)?;
        let stablecoin_a_token = contract
            .stablecoinAToken(token)
            .call()
            .await
            .map_err(AccountError::from)?;

        Ok(StablecoinPosition {
            asset: token,
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
            stablecoin_a_token,
        })
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
        asset: Asset,
    ) -> Result<Option<AssetBalanceInfo>, AccountError> {
        let user_address = self.ctx.signer_address().to_string();
        self.ctx
            .rpc_proxy()
            .await?
            .get_user_asset_balance(user_address, asset.address().to_string())
            .await?
            .map(|balance| AssetBalanceInfo::try_from(balance).map_err(AccountError::Decode))
            .transpose()
    }
}
