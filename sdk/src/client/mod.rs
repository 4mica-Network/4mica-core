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
    primitives::{Address, B256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::{Signature, Signer},
};
use rpc::{ApiClientError, CorePublicParameters, RpcProxy, SupportedTokensResponse};
use tokio::sync::OnceCell;
use url::Url;

use self::{recipient::RecipientClient, user::UserClient};
use crypto::bls::BlsPublicKey;
use std::collections::HashMap;

pub mod model;
pub mod recipient;
pub mod user;

struct Inner<S> {
    cfg: Config<S>,
    rpc_proxy: RpcProxy,
    ethereum_http_rpc_url: Url,
    provider: DynProvider,
    wallet_provider: OnceCell<DynProvider>,
    contract_address: Address,
    operator_public_key: BlsPublicKey,
    max_accepted_guarantee_version: u64,
    active_guarantee_domain: [u8; 32],
    guarantee_domains: HashMap<u64, [u8; 32]>,
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
        let (max_accepted_guarantee_version, active_guarantee_domain, guarantee_domains) =
            Self::fetch_guarantee_metadata(&public_params, &contract).await?;

        Ok(Self(Arc::new(Inner {
            cfg,
            rpc_proxy,
            ethereum_http_rpc_url,
            provider,
            wallet_provider: OnceCell::new(),
            contract_address,
            operator_public_key,
            max_accepted_guarantee_version,
            active_guarantee_domain,
            guarantee_domains,
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

    fn parse_operator_public_key(bytes: &[u8]) -> Result<BlsPublicKey, ClientError> {
        BlsPublicKey::from_bytes(bytes)
            .map_err(|e| ClientError::Initialization(format!("invalid operator public key: {e}")))
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

    async fn fetch_guarantee_metadata(
        public_params: &CorePublicParameters,
        contract: &Core4MicaInstance<DynProvider>,
    ) -> Result<(u64, [u8; 32], HashMap<u64, [u8; 32]>), ClientError> {
        let max_version = public_params.max_accepted_guarantee_version;
        let mut guarantee_domains = HashMap::new();
        // Iterate over whichever versions the core reports as accepted, rather than a hardcoded
        // list. Adding V3 in the rpc crate is the only change required.
        for version in public_params.accepted_guarantee_versions_or_default() {
            let version_config = contract
                .getGuaranteeVersionConfig(version)
                .call()
                .await
                .map_err(|e| ClientError::Initialization(e.to_string()))?;
            if version_config.enabled {
                guarantee_domains.insert(version, version_config.domainSeparator.into());
            }

            if version == max_version {
                if !version_config.enabled {
                    return Err(ClientError::Initialization(format!(
                        "max accepted guarantee version {} is disabled on-chain",
                        max_version
                    )));
                }

                if !public_params.active_guarantee_domain_separator.is_empty() {
                    let expected_domain = public_params
                        .active_guarantee_domain_separator
                        .parse::<B256>()
                        .map_err(|e| {
                            ClientError::Initialization(format!(
                                "invalid active guarantee domain separator from core: {e}"
                            ))
                        })?;

                    if expected_domain != version_config.domainSeparator {
                        return Err(ClientError::Initialization(format!(
                            "guarantee domain mismatch between core metadata and contract for version {}",
                            max_version
                        )));
                    }
                }
            }
        }

        let active_guarantee_domain =
            guarantee_domains
                .get(&max_version)
                .copied()
                .ok_or_else(|| {
                    ClientError::Initialization(format!(
                        "missing guarantee domain metadata for max accepted version {}",
                        max_version
                    ))
                })?;

        Ok((max_version, active_guarantee_domain, guarantee_domains))
    }

    fn contract_address(&self) -> Address {
        self.0.contract_address
    }

    fn get_contract(&self) -> Core4MicaInstance<DynProvider> {
        Core4Mica::new(self.0.contract_address, self.0.provider.clone())
    }

    fn operator_public_key(&self) -> &BlsPublicKey {
        &self.0.operator_public_key
    }

    fn active_guarantee_version(&self) -> u64 {
        self.0.max_accepted_guarantee_version
    }

    fn active_guarantee_domain(&self) -> &[u8; 32] {
        &self.0.active_guarantee_domain
    }

    fn guarantee_domain_for_version(&self, version: u64) -> Option<&[u8; 32]> {
        self.0.guarantee_domains.get(&version)
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
        let provider = self
            .0
            .wallet_provider
            .get_or_try_init(|| async {
                let wallet = EthereumWallet::new(self.0.cfg.signer.clone());
                ProviderBuilder::new()
                    .wallet(wallet)
                    .connect(self.0.ethereum_http_rpc_url.as_ref())
                    .await
                    .map_err(|e| ClientError::Provider(e.to_string()))
                    .map(|p| p.erased())
            })
            .await?;
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

    pub async fn get_supported_tokens(&self) -> Result<SupportedTokensResponse, ApiClientError> {
        self.ctx.0.rpc_proxy.get_supported_tokens().await
    }
}
