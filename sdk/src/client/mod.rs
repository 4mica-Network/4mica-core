use std::sync::Arc;

use crate::{
    config::Config,
    contract::Core4Mica::{self, Core4MicaInstance},
    error::Error4Mica,
};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use rpc::proxy::RpcProxy;

pub struct Inner {
    cfg: Config,
    rpc_proxy: RpcProxy,
    provider: DynProvider,
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    pub async fn new(cfg: Config) -> Result<Self, Error4Mica> {
        let rpc_proxy = RpcProxy::new(&cfg.rpc_url.to_string()).map_err(Error4Mica::Rpc)?;

        let provider = ProviderBuilder::new()
            .wallet(cfg.wallet_private_key.clone())
            .connect(&cfg.ethereum_http_rpc_url.to_string())
            .await
            .map_err(|e| Error4Mica::Rpc(e.into()))?
            .erased();

        Ok(Self {
            inner: Arc::new(Inner {
                cfg,
                rpc_proxy,
                provider,
            }),
        })
    }

    fn get_contract(&self) -> Core4MicaInstance<DynProvider> {
        Core4Mica::new(self.inner.cfg.contract_address, self.inner.provider.clone())
    }
}
