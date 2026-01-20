use std::sync::Arc;

use crate::{
    config::Config,
    contract::{
        Core4Mica::{self, Core4MicaInstance},
        ERC20::{self, ERC20Instance},
    },
    error::ClientError,
    validators::{validate_address, validate_url},
};
use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use rpc::{CorePublicParameters, RpcProxy};

use self::{recipient::RecipientClient, user::UserClient};

pub mod model;
pub mod recipient;
pub mod user;

struct Inner {
    cfg: Config,
    rpc_proxy: RpcProxy,
    provider: DynProvider,
    contract_address: Address,
    operator_public_key: [u8; 48],
    guarantee_domain: [u8; 32],
}

#[derive(Clone)]
struct ClientCtx(Arc<Inner>);

impl ClientCtx {
    async fn new(cfg: Config) -> Result<Self, ClientError> {
        let rpc_proxy = Self::build_rpc_proxy(&cfg)?;
        let public_params = rpc_proxy
            .get_public_params()
            .await
            .map_err(|e| ClientError::Rpc(e.to_string()))?;

        let provider = Self::build_provider(&cfg, &public_params).await?;
        let operator_public_key = Self::parse_operator_public_key(&public_params.public_key)?;
        let contract_address = Self::resolve_contract_address(&cfg, &public_params)?;

        let contract = Core4Mica::new(contract_address, provider.clone());
        let on_chain_domain = Self::fetch_guarantee_domain(&contract).await?;

        Ok(Self(Arc::new(Inner {
            cfg,
            rpc_proxy,
            provider,
            contract_address,
            operator_public_key,
            guarantee_domain: on_chain_domain,
        })))
    }

    fn build_rpc_proxy(cfg: &Config) -> Result<RpcProxy, ClientError> {
        let mut proxy =
            RpcProxy::new(cfg.rpc_url.as_ref()).map_err(|e| ClientError::Rpc(e.to_string()))?;
        if let Some(token) = &cfg.bearer_token {
            proxy = proxy.with_bearer_token(token.clone());
        }
        Ok(proxy)
    }

    async fn build_provider(
        cfg: &Config,
        public_params: &CorePublicParameters,
    ) -> Result<DynProvider, ClientError> {
        let ethereum_http_rpc_url = match &cfg.ethereum_http_rpc_url {
            Some(url) => url.clone(),
            None => validate_url(&public_params.ethereum_http_rpc_url)
                .map_err(|e| ClientError::Initialization(e.to_string()))?,
        };

        let provider = ProviderBuilder::new()
            .wallet(cfg.wallet_private_key.clone())
            .connect(ethereum_http_rpc_url.as_ref())
            .await
            .map_err(|e| ClientError::Provider(e.to_string()))?
            .erased();

        let provider_chain_id = provider
            .get_chain_id()
            .await
            .map_err(|e| ClientError::Initialization(e.to_string()))?;

        if provider_chain_id != public_params.chain_id {
            return Err(ClientError::Initialization(format!(
                "chain id mismatch between core service ({}) and Ethereum provider ({})",
                public_params.chain_id, provider_chain_id
            )));
        }

        Ok(provider)
    }

    fn parse_operator_public_key(bytes: &[u8]) -> Result<[u8; 48], ClientError> {
        if bytes.len() != 48 {
            return Err(ClientError::Initialization(format!(
                "invalid operator public key length: expected 48 bytes, got {}",
                bytes.len()
            )));
        }

        let mut pk = [0u8; 48];
        pk.copy_from_slice(bytes);
        Ok(pk)
    }

    fn resolve_contract_address(
        cfg: &Config,
        public_params: &CorePublicParameters,
    ) -> Result<Address, ClientError> {
        match cfg.contract_address {
            Some(address) => Ok(address),
            None => validate_address(&public_params.contract_address)
                .map_err(|e| ClientError::Initialization(e.to_string())),
        }
    }

    async fn fetch_guarantee_domain(
        contract: &Core4MicaInstance<DynProvider>,
    ) -> Result<[u8; 32], ClientError> {
        contract
            .guaranteeDomainSeparator()
            .call()
            .await
            .map(Into::into)
            .map_err(|e| ClientError::Initialization(e.to_string()))
    }

    fn contract_address(&self) -> Address {
        self.0.contract_address
    }

    fn get_contract(&self) -> Core4MicaInstance<DynProvider> {
        Core4Mica::new(self.0.contract_address, self.0.provider.clone())
    }

    fn get_erc20_contract(&self, token_address: Address) -> ERC20Instance<DynProvider> {
        ERC20::new(token_address, self.0.provider.clone())
    }

    fn provider(&self) -> &DynProvider {
        &self.0.provider
    }

    fn rpc_proxy(&self) -> &RpcProxy {
        &self.0.rpc_proxy
    }

    fn signer(&self) -> &PrivateKeySigner {
        &self.0.cfg.wallet_private_key
    }

    fn operator_public_key(&self) -> &[u8; 48] {
        &self.0.operator_public_key
    }

    fn guarantee_domain(&self) -> &[u8; 32] {
        &self.0.guarantee_domain
    }
}

#[derive(Clone)]
pub struct Client {
    pub recipient: RecipientClient,
    pub user: UserClient,
}

impl Client {
    pub async fn new(cfg: Config) -> Result<Self, ClientError> {
        let ctx = ClientCtx::new(cfg).await?;

        Ok(Self {
            recipient: RecipientClient::new(ctx.clone()),
            user: UserClient::new(ctx.clone()),
        })
    }
}
