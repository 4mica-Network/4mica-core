use std::sync::Arc;

use crate::{
    config::Config,
    contract::Core4Mica::{self, Core4MicaInstance},
    error::Error4Mica,
};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use rpc::proxy::RpcProxy;

use self::{recipient::RecipientClient, user::UserClient};

pub mod recipient;
pub mod user;

struct Inner {
    cfg: Config,
    rpc_proxy: RpcProxy,
    provider: DynProvider,
}

#[derive(Clone)]
struct ClientCtx(Arc<Inner>);

impl ClientCtx {
    async fn new(cfg: Config) -> Result<Self, Error4Mica> {
        let rpc_proxy = RpcProxy::new(&cfg.rpc_url.to_string())?;

        let provider = ProviderBuilder::new()
            .wallet(cfg.wallet_private_key.clone())
            .connect(&cfg.ethereum_http_rpc_url.to_string())
            .await
            .map_err(|e| Error4Mica::Other(e.into()))?
            .erased();

        Ok(Self(Arc::new(Inner {
            cfg,
            rpc_proxy,
            provider,
        })))
    }

    fn get_contract(&self) -> Core4MicaInstance<DynProvider> {
        Core4Mica::new(self.0.cfg.contract_address, self.0.provider.clone())
    }

    fn rpc_proxy(&self) -> &RpcProxy {
        &self.0.rpc_proxy
    }
}

#[derive(Clone)]
pub struct Client {
    pub recipient: RecipientClient,
    pub user: UserClient,
}

impl Client {
    pub async fn new(cfg: Config) -> Result<Self, Error4Mica> {
        let ctx = ClientCtx::new(cfg).await?;

        Ok(Self {
            recipient: RecipientClient::new(ctx.clone()),
            user: UserClient::new(ctx.clone()),
        })
    }
}
