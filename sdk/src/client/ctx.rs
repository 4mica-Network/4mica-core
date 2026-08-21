use std::collections::HashMap;
use std::sync::Arc;

use alloy::{
    network::{EthereumWallet, TxSigner},
    primitives::{Address, B256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::{Signature, Signer},
};
use crypto::bls::BlsPublicKey;
use rpc::{
    ApiClientError, CorePublicParameters, GUARANTEE_CLAIMS_VERSION, RpcProxy,
    SupportedTokensResponse,
};
use tokio::sync::{OnceCell, RwLock};
use url::Url;

use crate::{
    auth::{AuthSession, AuthTokens},
    client::facilitator::Facilitator,
    config::Config,
    contract::{
        ClearingHouse::{self, ClearingHouseInstance},
        Core4Mica::{self, Core4MicaInstance},
        ERC20::{self, ERC20Instance},
    },
    error::{AuthError, ClientError},
    validators::{validate_address, validate_url},
};

struct Inner<S> {
    cfg: Config<S>,
    rpc_proxy: RpcProxy,
    facilitator: Facilitator,
    /// `None` when neither config nor core names one. Only the paths that read chain state or
    /// transact need it, so its absence is not fatal until one of them is called.
    ethereum_http_rpc_url: Option<Url>,
    provider: OnceCell<DynProvider>,
    wallet_provider: OnceCell<DynProvider>,
    contract_address: Address,
    operator_public_key: BlsPublicKey,
    guarantee_domain: [u8; 32],
    guarantee_domains: HashMap<u64, [u8; 32]>,
    auth_session: Option<AuthSession<S>>,
    chain_id: u64,
    /// Token EIP-712 domain separators, memoised. Immutable per token per chain, so a hit never
    /// goes stale; a miss refetches in case a new asset has been registered.
    token_domain_separators: RwLock<HashMap<Address, B256>>,
    /// Core4Mica's own EIP-712 domain separator, resolved at startup. Fixed for the lifetime of a
    /// deployment.
    core_domain_separator: B256,
}

/// Everything the sub-clients share: configuration, connections, and the metadata resolved once at
/// startup.
pub(crate) struct ClientCtx<S>(Arc<Inner<S>>);

/// Hand-written rather than derived: `#[derive(Clone)]` would add an `S: Clone` bound, which the
/// `Arc` makes unnecessary — the signer is shared, never copied.
impl<S> Clone for ClientCtx<S> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<S> ClientCtx<S> {
    pub(super) async fn new(cfg: Config<S>) -> Result<Self, ClientError>
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

        let ethereum_http_rpc_url = Self::resolve_chain_rpc_url(&cfg, &public_params)?;
        let operator_public_key = Self::parse_operator_public_key(&public_params.public_key)?;
        let contract_address = Self::resolve_contract_address(&cfg, &public_params)?;

        let (guarantee_domain, guarantee_domains) = Self::fetch_guarantee_metadata(
            &public_params,
            contract_address,
            ethereum_http_rpc_url.as_ref(),
        )
        .await?;
        let core_domain_separator =
            Self::resolve_core_domain_separator(&public_params, contract_address);

        let facilitator = Facilitator::new(cfg.facilitator_url.clone());

        Ok(Self(Arc::new(Inner {
            cfg,
            rpc_proxy,
            facilitator,
            ethereum_http_rpc_url,
            provider: OnceCell::new(),
            wallet_provider: OnceCell::new(),
            contract_address,
            operator_public_key,
            guarantee_domain,
            guarantee_domains,
            auth_session,
            chain_id: public_params.chain_id,
            token_domain_separators: RwLock::new(HashMap::new()),
            core_domain_separator,
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

    /// The Ethereum endpoint to talk to, if there is one. An explicit config wins over what core
    /// advertises, and neither is required.
    fn resolve_chain_rpc_url(
        cfg: &Config<S>,
        public_params: &CorePublicParameters,
    ) -> Result<Option<Url>, ClientError> {
        if let Some(url) = &cfg.ethereum_http_rpc_url {
            return Ok(Some(url.clone()));
        }
        if public_params.ethereum_http_rpc_url.is_empty() {
            return Ok(None);
        }
        validate_url(&public_params.ethereum_http_rpc_url)
            .map(Some)
            .map_err(|e| ClientError::Initialization(e.to_string()))
    }

    async fn connect(url: &Url) -> Result<DynProvider, ClientError> {
        ProviderBuilder::new()
            .connect(url.as_ref())
            .await
            .map_err(|e| ClientError::Provider(e.to_string()))
            .map(|provider| provider.erased())
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

    /// The domain separator for every guarantee version this deployment supports, so certs can be
    /// verified whichever version issued them. Requests are always signed at
    /// [`GUARANTEE_CLAIMS_VERSION`], so that one must be supported and enabled.
    ///
    /// Takes what core publishes and reads the contract only when core publishes nothing, which is
    /// all a core too old to do so leaves. That fallback is the one thing here that needs an
    /// Ethereum endpoint.
    async fn fetch_guarantee_metadata(
        public_params: &CorePublicParameters,
        contract_address: Address,
        chain_rpc_url: Option<&Url>,
    ) -> Result<([u8; 32], HashMap<u64, [u8; 32]>), ClientError> {
        if !public_params
            .supported_guarantee_versions
            .contains(&GUARANTEE_CLAIMS_VERSION)
        {
            return Err(ClientError::Initialization(format!(
                "this client signs guarantee v{GUARANTEE_CLAIMS_VERSION}, which core does not \
                 support (core supports {:?}); upgrade core or downgrade the SDK",
                public_params.supported_guarantee_versions
            )));
        }

        let guarantee_domains = match Self::published_guarantee_domains(public_params)? {
            Some(domains) => domains,
            None => {
                Self::read_guarantee_domains(public_params, contract_address, chain_rpc_url).await?
            }
        };

        let guarantee_domain = guarantee_domains
            .get(&GUARANTEE_CLAIMS_VERSION)
            .copied()
            .ok_or_else(|| {
                ClientError::Initialization(format!(
                    "missing guarantee domain metadata for v{GUARANTEE_CLAIMS_VERSION}"
                ))
            })?;

        Ok((guarantee_domain, guarantee_domains))
    }

    /// The domains core published, or `None` from a core that publishes none.
    fn published_guarantee_domains(
        public_params: &CorePublicParameters,
    ) -> Result<Option<HashMap<u64, [u8; 32]>>, ClientError> {
        if public_params.guarantee_domains.is_empty() {
            return Ok(None);
        }

        public_params
            .guarantee_domains
            .iter()
            .map(|entry| {
                let separator = entry.domain_separator.parse::<B256>().map_err(|e| {
                    ClientError::Initialization(format!(
                        "invalid guarantee domain separator for v{} from core: {e}",
                        entry.version
                    ))
                })?;
                Ok((entry.version, separator.into()))
            })
            .collect::<Result<HashMap<_, _>, _>>()
            .map(Some)
    }

    /// Reads each supported version's domain off the contract, one call apiece.
    async fn read_guarantee_domains(
        public_params: &CorePublicParameters,
        contract_address: Address,
        chain_rpc_url: Option<&Url>,
    ) -> Result<HashMap<u64, [u8; 32]>, ClientError> {
        let url = chain_rpc_url.ok_or(ClientError::ChainRpcUnavailable)?;
        let contract = Core4Mica::new(contract_address, Self::connect(url).await?);

        let mut guarantee_domains = HashMap::new();
        for &version in &public_params.supported_guarantee_versions {
            let version_config = contract
                .getGuaranteeVersionConfig(version)
                .call()
                .await
                .map_err(|e| ClientError::Initialization(e.to_string()))?;

            if !version_config.enabled {
                if version == GUARANTEE_CLAIMS_VERSION {
                    return Err(ClientError::Initialization(format!(
                        "guarantee v{GUARANTEE_CLAIMS_VERSION} is disabled on-chain"
                    )));
                }
                continue;
            }
            guarantee_domains.insert(version, version_config.domainSeparator.into());

            if version == GUARANTEE_CLAIMS_VERSION
                && !public_params.guarantee_domain_separator.is_empty()
            {
                let expected_domain = public_params
                    .guarantee_domain_separator
                    .parse::<B256>()
                    .map_err(|e| {
                        ClientError::Initialization(format!(
                            "invalid guarantee domain separator from core: {e}"
                        ))
                    })?;

                if expected_domain != version_config.domainSeparator {
                    return Err(ClientError::Initialization(format!(
                        "guarantee domain mismatch between core metadata and contract for \
                         version {version}"
                    )));
                }
            }
        }

        Ok(guarantee_domains)
    }

    /// Core4Mica's EIP-712 domain separator.
    ///
    /// Prefers what core publishes, since core reads it from the contract and so stays right across
    /// a domain change. Falls back to deriving it, which is sound because the contract fixes its
    /// domain as `EIP712("Core4Mica", "1")` — so a core too old to publish one costs nothing beyond
    /// that guarantee.
    fn resolve_core_domain_separator(
        public_params: &CorePublicParameters,
        contract_address: Address,
    ) -> B256 {
        public_params
            .core_domain_separator
            .parse::<B256>()
            .unwrap_or_else(|_| {
                crate::digest::core_domain_separator(public_params.chain_id, contract_address)
            })
    }

    pub(crate) fn contract_address(&self) -> Address {
        self.0.contract_address
    }

    fn chain_rpc_url(&self) -> Result<&Url, ClientError> {
        self.0
            .ethereum_http_rpc_url
            .as_ref()
            .ok_or(ClientError::ChainRpcUnavailable)
    }

    /// The read provider, connected on first use.
    ///
    /// Deferred so a client that only ever takes sponsored paths never needs an Ethereum endpoint —
    /// everything resolved at construction comes from core. The chain id is checked here rather than
    /// at construction, which keeps the check without paying for it up front.
    async fn provider(&self) -> Result<&DynProvider, ClientError> {
        self.0
            .provider
            .get_or_try_init(|| async {
                let provider = Self::connect(self.chain_rpc_url()?).await?;
                let chain_id = provider
                    .get_chain_id()
                    .await
                    .map_err(|e| ClientError::Provider(e.to_string()))?;

                if chain_id != self.0.chain_id {
                    return Err(ClientError::Initialization(format!(
                        "chain id mismatch between core service ({}) and Ethereum provider \
                         ({chain_id})",
                        self.0.chain_id
                    )));
                }
                Ok(provider)
            })
            .await
    }

    pub(crate) async fn get_contract(&self) -> Result<Core4MicaInstance<DynProvider>, ClientError> {
        Ok(Core4Mica::new(
            self.0.contract_address,
            self.provider().await?.clone(),
        ))
    }

    /// A read-only handle on `token`, for view calls that need no signer.
    pub(crate) async fn get_erc20_contract(
        &self,
        token: Address,
    ) -> Result<ERC20Instance<DynProvider>, ClientError> {
        Ok(ERC20::new(token, self.provider().await?.clone()))
    }

    /// A token's EIP-712 domain separator.
    ///
    /// Deliberately not an `eth_call`: signing a gasless deposit must not require the caller to
    /// hold an Ethereum RPC endpoint of its own.
    pub(crate) async fn token_domain_separator(&self, token: Address) -> Result<B256, ClientError> {
        if let Some(cached) = self.0.token_domain_separators.read().await.get(&token) {
            return Ok(*cached);
        }

        let tokens = self
            .0
            .rpc_proxy
            .get_supported_tokens()
            .await
            .map_err(|e| ClientError::Rpc(e.to_string()))?;

        let mut cache = self.0.token_domain_separators.write().await;
        let mut found = None;
        for info in &tokens.tokens {
            let Ok(address) = validate_address(&info.address) else {
                continue;
            };
            let Some(raw) = &info.domain_separator else {
                continue;
            };
            let Ok(separator) = raw.parse::<B256>() else {
                continue;
            };
            cache.insert(address, separator);
            if address == token {
                found = Some(separator);
            }
        }

        found.ok_or(ClientError::MissingTokenDomainSeparator { token })
    }

    /// Core4Mica's EIP-712 domain separator, resolved at startup.
    pub(crate) fn core_domain_separator(&self) -> B256 {
        self.0.core_domain_separator
    }

    /// Permit2's domain separator, derived locally from the chain id.
    ///
    /// Permit2 is deployed at one canonical address on every chain and its domain has a fixed name
    /// and no version, so this needs no lookup at all.
    pub(crate) fn permit2_domain_separator(&self) -> B256 {
        crate::digest::permit2_domain_separator(self.0.chain_id)
    }

    pub(super) fn facilitator(&self) -> &Facilitator {
        &self.0.facilitator
    }

    pub(crate) fn operator_public_key(&self) -> &BlsPublicKey {
        &self.0.operator_public_key
    }

    pub(crate) fn guarantee_domain(&self) -> &[u8; 32] {
        &self.0.guarantee_domain
    }

    pub(crate) fn guarantee_domain_for_version(&self, version: u64) -> Option<&[u8; 32]> {
        self.0.guarantee_domains.get(&version)
    }

    pub(crate) fn signer(&self) -> &S {
        &self.0.cfg.signer
    }

    pub(crate) fn signer_address(&self) -> Address
    where
        S: Signer,
    {
        self.0.cfg.signer.address()
    }

    pub(crate) async fn supported_tokens(&self) -> Result<SupportedTokensResponse, ApiClientError> {
        self.0.rpc_proxy.get_supported_tokens().await
    }

    pub(crate) async fn rpc_proxy(&self) -> Result<RpcProxy, ApiClientError>
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

    pub(super) async fn login(&self) -> Result<AuthTokens, AuthError>
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
                    .connect(self.chain_rpc_url()?.as_ref())
                    .await
                    .map_err(|e| ClientError::Provider(e.to_string()))
                    .map(|p| p.erased())
            })
            .await?;
        Ok(provider.clone())
    }

    pub(crate) async fn get_write_contract(
        &self,
    ) -> Result<Core4MicaInstance<DynProvider>, ClientError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let provider = self.get_wallet_provider().await?;
        Ok(Core4Mica::new(self.0.contract_address, provider))
    }

    pub(crate) async fn get_erc20_write_contract(
        &self,
        token_address: Address,
    ) -> Result<ERC20Instance<DynProvider>, ClientError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let provider = self.get_wallet_provider().await?;
        Ok(ERC20::new(token_address, provider))
    }

    pub(crate) async fn get_clearing_house_write_contract(
        &self,
        clearing_house_address: Address,
    ) -> Result<ClearingHouseInstance<DynProvider>, ClientError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let provider = self.get_wallet_provider().await?;
        Ok(ClearingHouse::new(clearing_house_address, provider))
    }
}
