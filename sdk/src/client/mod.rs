use std::sync::Arc;

use crate::{
    auth::{AuthSession, AuthTokens},
    config::Config,
    contract::{
        Core4Mica::{self, Core4MicaInstance},
        ERC20::{self, ERC20Instance},
    },
    error::{AuthError, ClientError},
    validators::{validate_address, validate_url},
};
use alloy::{
    network::{EthereumWallet, TxSigner},
    primitives::Address,
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::{Signature, Signer},
};
use rpc::{ApiClientError, CorePublicParameters, RpcProxy};
use tokio::sync::Mutex;
use url::Url;

use self::{recipient::RecipientClient, user::UserClient};

pub mod model;
pub mod recipient;
pub mod user;

struct Inner<S> {
    cfg: Config<S>,
    rpc_proxy: RpcProxy,
    ethereum_http_rpc_url: Url,
    provider: DynProvider,
    wallet_provider: Mutex<Option<DynProvider>>,
    contract_address: Address,
    operator_public_key: [u8; 48],
    guarantee_domain: [u8; 32],
    auth_session: Option<AuthSession<S>>,
}

#[derive(Clone)]
struct ClientCtx<S>(Arc<Inner<S>>);

impl<S> ClientCtx<S> {
    async fn new(cfg: Config<S>) -> Result<Self, ClientError>
    where
        S: Signer + Sync + Clone,
    {
        let rpc_proxy = Self::build_rpc_proxy(&cfg)?;
        let auth_session = cfg.auth.as_ref().and_then(|auth_cfg| {
            if cfg.bearer_token.is_some() {
                None
            } else {
                Some(AuthSession::new(auth_cfg.clone(), cfg.signer.clone()))
            }
        });
        let public_params = rpc_proxy
            .get_public_params()
            .await
            .map_err(|e| ClientError::Rpc(e.to_string()))?;

        let ethereum_http_rpc_url = match &cfg.ethereum_http_rpc_url {
            Some(url) => url.clone(),
            None => validate_url(&public_params.ethereum_http_rpc_url)
                .map_err(|e| ClientError::Initialization(e.to_string()))?,
        };

        let provider = Self::build_provider(&public_params, &ethereum_http_rpc_url).await?;
        let operator_public_key = Self::parse_operator_public_key(&public_params.public_key)?;
        let contract_address = Self::resolve_contract_address(&cfg, &public_params)?;

        let contract = Core4Mica::new(contract_address, provider.clone());
        let on_chain_domain = Self::fetch_guarantee_domain(&contract).await?;

        Ok(Self(Arc::new(Inner {
            cfg,
            rpc_proxy,
            ethereum_http_rpc_url,
            provider,
            wallet_provider: Mutex::new(None),
            contract_address,
            operator_public_key,
            guarantee_domain: on_chain_domain,
            auth_session,
        })))
    }

    fn build_rpc_proxy(cfg: &Config<S>) -> Result<RpcProxy, ClientError> {
        let mut proxy =
            RpcProxy::new(cfg.rpc_url.as_ref()).map_err(|e| ClientError::Rpc(e.to_string()))?;
        if let Some(token) = &cfg.bearer_token {
            proxy = proxy.with_bearer_token(token.clone());
        }
        Ok(proxy)
    }

    async fn build_provider(
        public_params: &CorePublicParameters,
        ethereum_http_rpc_url: &Url,
    ) -> Result<DynProvider, ClientError> {
        let provider = ProviderBuilder::new()
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
        cfg: &Config<S>,
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

    fn operator_public_key(&self) -> &[u8; 48] {
        &self.0.operator_public_key
    }

    fn guarantee_domain(&self) -> &[u8; 32] {
        &self.0.guarantee_domain
    }

    fn signer(&self) -> &S {
        &self.0.cfg.signer
    }

    fn signer_address(&self) -> Address
    where
        S: Signer,
    {
        self.0.cfg.signer.address()
    }

    async fn rpc_proxy(&self) -> Result<RpcProxy, ApiClientError>
    where
        S: Signer + Sync,
    {
        let mut proxy = self.0.rpc_proxy.clone();
        if let Some(auth) = &self.0.auth_session {
            let token = auth
                .access_token()
                .await
                .map_err(Into::<ApiClientError>::into)?;
            proxy = proxy.with_bearer_token(token);
        }
        Ok(proxy)
    }

    async fn login(&self) -> Result<AuthTokens, AuthError>
    where
        S: Signer + Sync,
    {
        let session = self
            .0
            .auth_session
            .as_ref()
            .ok_or(AuthError::MissingConfig)?;
        session.login().await
    }

    async fn get_wallet_provider(&self) -> Result<DynProvider, ClientError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let mut wallet_provider = self.0.wallet_provider.lock().await;
        if let Some(wallet_provider) = wallet_provider.as_ref() {
            return Ok(wallet_provider.clone());
        }

        let wallet = EthereumWallet::new(self.0.cfg.signer.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect(self.0.ethereum_http_rpc_url.as_ref())
            .await
            .map_err(|e| ClientError::Provider(e.to_string()))?
            .erased();

        wallet_provider.replace(provider.clone());
        Ok(provider.clone())
    }

    async fn get_write_contract(&self) -> Result<Core4MicaInstance<DynProvider>, ClientError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let provider = self.get_wallet_provider().await?;
        Ok(Core4Mica::new(self.0.contract_address, provider))
    }

    async fn get_erc20_write_contract(
        &self,
        token_address: Address,
    ) -> Result<ERC20Instance<DynProvider>, ClientError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let provider = self.get_wallet_provider().await?;
        Ok(ERC20::new(token_address, provider))
    }
}

pub struct Client<S> {
    ctx: ClientCtx<S>,
    pub recipient: RecipientClient<S>,
    pub user: UserClient<S>,
}

impl<S: Clone> Clone for Client<S> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            recipient: self.recipient.clone(),
            user: self.user.clone(),
        }
    }
}

impl<S> Client<S> {
    pub async fn new(cfg: Config<S>) -> Result<Self, ClientError>
    where
        S: Signer + Sync + Clone,
    {
        let ctx = ClientCtx::new(cfg).await?;

        Ok(Self {
            ctx: ctx.clone(),
            recipient: RecipientClient::new(ctx.clone()),
            user: UserClient::new(ctx),
        })
    }

    pub async fn login(&self) -> Result<AuthTokens, AuthError>
    where
        S: Signer + Sync,
    {
        self.ctx.login().await
    }
}
