use std::sync::Arc;

use crate::{
    auth::{AuthSession, AuthTokens},
    config::Config,
    contract::{
        ClearingHouse::{self, ClearingHouseInstance},
        Core4Mica::{self, Core4MicaInstance},
        ERC20::{self, ERC20Instance},
    },
    error::{AuthError, ClientError, DepositError},
    validators::{validate_address, validate_url},
};
use alloy::{
    network::{EthereumWallet, TxSigner},
    primitives::{Address, B256, U256},
    providers::{DynProvider, Provider, ProviderBuilder},
    signers::{Signature, Signer},
};
use rpc::{
    ApiClientError, CorePublicParameters, GUARANTEE_CLAIMS_VERSION, RpcProxy,
    SupportedTokensResponse,
};
use tokio::sync::{OnceCell, RwLock};
use url::Url;

use self::{facilitator::FacilitatorClient, recipient::RecipientClient, user::UserClient};
use crypto::bls::BlsPublicKey;
use std::collections::HashMap;

pub mod facilitator;
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
    guarantee_domain: [u8; 32],
    guarantee_domains: HashMap<u64, [u8; 32]>,
    auth_session: Option<AuthSession<S>>,
    chain_id: u64,
    /// Token EIP-712 domain separators as served by core, memoised. Immutable per token per chain,
    /// so a hit never goes stale; a miss refetches in case core has registered a new asset.
    token_domain_separators: RwLock<HashMap<Address, B256>>,
}

struct ClientCtx<S>(Arc<Inner<S>>);

/// Hand-written rather than derived: `#[derive(Clone)]` would add an `S: Clone` bound, which the
/// `Arc` makes unnecessary — the signer is shared, never copied.
impl<S> Clone for ClientCtx<S> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

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
        let (guarantee_domain, guarantee_domains) =
            Self::fetch_guarantee_metadata(&public_params, &contract).await?;

        Ok(Self(Arc::new(Inner {
            cfg,
            rpc_proxy,
            ethereum_http_rpc_url,
            provider,
            wallet_provider: OnceCell::new(),
            contract_address,
            operator_public_key,
            guarantee_domain,
            guarantee_domains,
            auth_session,
            chain_id: public_params.chain_id,
            token_domain_separators: RwLock::new(HashMap::new()),
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

    /// Loads the on-chain domain separator for every guarantee version this core supports, so
    /// certs can be verified whichever version issued them. Requests are always signed at
    /// [`GUARANTEE_CLAIMS_VERSION`], so that one must be supported and enabled.
    async fn fetch_guarantee_metadata(
        public_params: &CorePublicParameters,
        contract: &Core4MicaInstance<DynProvider>,
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

    fn contract_address(&self) -> Address {
        self.0.contract_address
    }

    fn get_contract(&self) -> Core4MicaInstance<DynProvider> {
        Core4Mica::new(self.0.contract_address, self.0.provider.clone())
    }

    /// A token's EIP-712 domain separator, as read from the token by core and relayed over HTTP.
    ///
    /// Deliberately not an `eth_call`: signing a gasless deposit must not require the client to
    /// hold an Ethereum RPC endpoint. Core reads the real value from the token, so this keeps the
    /// correctness of an on-chain read without the dependency.
    async fn token_domain_separator(&self, token: Address) -> Result<B256, ClientError> {
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

        found.ok_or_else(|| {
            ClientError::Initialization(format!(
                "core did not advertise an EIP-712 domain separator for {token}; the token is \
                 either unsupported or does not implement EIP-3009"
            ))
        })
    }

    /// Permit2's domain separator, derived locally from the chain id.
    ///
    /// Permit2 is deployed at one canonical address on every chain and its domain has a fixed name
    /// and no version, so this needs neither a chain read nor anything from core.
    fn permit2_domain_separator(&self) -> B256 {
        crate::digest::permit2_domain_separator(self.0.chain_id)
    }

    fn operator_public_key(&self) -> &BlsPublicKey {
        &self.0.operator_public_key
    }

    fn guarantee_domain(&self) -> &[u8; 32] {
        &self.0.guarantee_domain
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

    async fn get_clearing_house_write_contract(
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

/// What to deposit. Native ETH has no gasless path — no authorization scheme covers it — so it is
/// always self-funded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asset {
    Native,
    Erc20(Address),
}

/// How a deposit reached the contract. Carried on [`DepositReceipt`] because "it worked" hides the
/// one thing a caller cares about: whether they paid for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositPath {
    /// EIP-3009 `receiveWithAuthorization`, submitted by the facilitator. One transaction, none of
    /// it the payer's.
    Eip3009,
    /// Permit2, submitted by the facilitator. Gasless only because the payer already approved
    /// Permit2 in some earlier transaction.
    Permit2,
    /// Permit2 with the approval signed rather than transacted, both submitted by the facilitator.
    SponsoredPermit2,
    /// The payer's own transaction, paying their own gas.
    SelfFunded,
}

impl DepositPath {
    /// Whether the payer's own funds paid for the transaction.
    pub fn costs_the_payer_gas(&self) -> bool {
        matches!(self, Self::SelfFunded)
    }
}

/// Whether a rejection means "this token cannot take an EIP-3009 authorization" rather than "this
/// deposit is bad".
///
/// A token without `receiveWithAuthorization` reverts opaquely from inside Core4Mica, which the
/// facilitator reports as a failed simulation — indistinguishable, from here, from any other
/// revert. Retrying over Permit2 is therefore a guess, but a cheap one: the simulation spent no
/// gas, and a genuinely bad deposit fails again on the second route with its own error.
fn refuses_the_authorization(error: &DepositError) -> bool {
    matches!(
        error,
        DepositError::Facilitator { code, .. }
            if code == "SIMULATION_REVERTED" || code == "UNSUPPORTED_TRANSFER_METHOD"
    )
}

pub struct Client<S> {
    ctx: ClientCtx<S>,
    pub recipient: RecipientClient<S>,
    pub user: UserClient<S>,
    /// Gasless deposits. Present even when no facilitator is configured — every call then returns
    /// [`DepositError::FacilitatorNotConfigured`](crate::error::DepositError::FacilitatorNotConfigured),
    /// which is clearer than making the whole field optional at every call site.
    pub facilitator: FacilitatorClient<S>,
}

impl<S: Clone> Clone for Client<S> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            recipient: self.recipient.clone(),
            user: self.user.clone(),
            facilitator: self.facilitator.clone(),
        }
    }
}

impl<S> Client<S> {
    /// The address this client signs as, and therefore the account every deposit credits.
    ///
    /// Saves callers from keeping the signer alongside the client just to recover its address.
    pub fn signer_address(&self) -> Address
    where
        S: Signer,
    {
        self.ctx.signer_address()
    }

    /// Deposits `amount` of `asset`, taking the cheapest route available.
    ///
    /// Prefers routes the facilitator pays for, in order: EIP-3009 (one sponsored transaction),
    /// then Permit2 with the approval sponsored when the token allows it. Falls back to the payer's
    /// own transaction when no gasless route applies — native ETH, no facilitator configured, or a
    /// token whose Permit2 approval cannot be sponsored. Check
    /// [`DepositReceipt::path`](facilitator::DepositReceipt::path) to see which ran; call
    /// [`Self::deposit_via`] to force one, or the
    /// [`FacilitatorClient`](facilitator::FacilitatorClient) methods directly to rule out ever
    /// spending your own gas.
    pub async fn deposit(
        &self,
        asset: Asset,
        amount: U256,
    ) -> Result<facilitator::DepositReceipt, DepositError>
    where
        S: TxSigner<Signature> + Signer + Send + Sync + Clone + 'static,
    {
        let Asset::Erc20(token) = asset else {
            return self
                .deposit_via(DepositPath::SelfFunded, asset, amount)
                .await;
        };
        if !self.facilitator.is_configured() {
            return self
                .deposit_via(DepositPath::SelfFunded, asset, amount)
                .await;
        }

        // EIP-3009 is the cheapest route, but nothing core advertises says whether a token
        // implements it — a domain separator only proves EIP-712, which EIP-2612 has too. So ask,
        // and read the answer off the facilitator's simulation, which costs no gas.
        let rejection = match self.deposit_via(DepositPath::Eip3009, asset, amount).await {
            Ok(receipt) => return Ok(receipt),
            Err(err) => err,
        };
        if !refuses_the_authorization(&rejection) {
            return Err(rejection);
        }

        match self
            .deposit_via(DepositPath::SponsoredPermit2, asset, amount)
            .await
        {
            // The approval cannot be sponsored, so gaslessness is off the table either way; paying
            // for the deposit directly is one transaction rather than an approval plus a deposit.
            Err(DepositError::Permit2AllowanceRequired { .. }) => {
                self.deposit_via(DepositPath::SelfFunded, Asset::Erc20(token), amount)
                    .await
            }
            outcome => outcome,
        }
    }

    /// Deposits over one specific route, failing rather than choosing another.
    ///
    /// For callers with a policy — and for tests, which need to exercise a route rather than
    /// whichever one happens to be cheapest.
    pub async fn deposit_via(
        &self,
        path: DepositPath,
        asset: Asset,
        amount: U256,
    ) -> Result<facilitator::DepositReceipt, DepositError>
    where
        S: TxSigner<Signature> + Signer + Send + Sync + Clone + 'static,
    {
        let token = match (path, asset) {
            (DepositPath::SelfFunded, asset) => {
                return self.deposit_self_funded(asset, amount).await;
            }
            (_, Asset::Erc20(token)) => token.to_string(),
            (_, Asset::Native) => {
                return Err(DepositError::InvalidParams(
                    "native ETH has no gasless route; deposit it with DepositPath::SelfFunded"
                        .into(),
                ));
            }
        };

        match path {
            DepositPath::Eip3009 => {
                self.facilitator
                    .deposit_with_authorization(token, amount)
                    .await
            }
            DepositPath::Permit2 => self.facilitator.deposit_with_permit2(token, amount).await,
            DepositPath::SponsoredPermit2 => {
                self.facilitator
                    .deposit_with_sponsored_permit2(token, amount)
                    .await
            }
            DepositPath::SelfFunded => unreachable!("handled above"),
        }
    }

    /// The payer's own transaction, reported in the same shape as a sponsored one.
    async fn deposit_self_funded(
        &self,
        asset: Asset,
        amount: U256,
    ) -> Result<facilitator::DepositReceipt, DepositError>
    where
        S: TxSigner<Signature> + Signer + Send + Sync + Clone + 'static,
    {
        let token = match asset {
            Asset::Erc20(token) => Some(token.to_string()),
            Asset::Native => None,
        };
        let receipt = self.user.deposit(amount, token).await?;

        Ok(facilitator::DepositReceipt {
            tx_hash: receipt.transaction_hash,
            path: DepositPath::SelfFunded,
            from: self.signer_address(),
            asset: match asset {
                Asset::Erc20(token) => token,
                Asset::Native => Address::ZERO,
            },
            amount,
            network: None,
        })
    }

    pub async fn new(cfg: Config<S>) -> Result<Self, ClientError>
    where
        S: Signer + Sync + Clone,
    {
        let facilitator_url = cfg.facilitator_url.clone();
        let ctx = ClientCtx::new(cfg).await?;

        Ok(Self {
            ctx: ctx.clone(),
            recipient: RecipientClient::new(ctx.clone()),
            user: UserClient::new(ctx.clone()),
            facilitator: FacilitatorClient::new(ctx, facilitator_url),
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
