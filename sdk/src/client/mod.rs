use std::{convert::TryInto, sync::Arc};

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
use rpc::{core::CoreApiClient, proxy::RpcProxy};

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
}

#[derive(Clone)]
struct ClientCtx(Arc<Inner>);

impl ClientCtx {
    async fn new(cfg: Config) -> Result<Self, ClientError> {
        let rpc_proxy =
            RpcProxy::new(cfg.rpc_url.as_ref()).map_err(|e| ClientError::Rpc(e.to_string()))?;

        let public_params = rpc_proxy
            .get_public_params()
            .await
            .map_err(|e| ClientError::Rpc(e.to_string()))?;

        let expected_chain_id = public_params.chain_id;

        let ethereum_http_rpc_url = cfg.ethereum_http_rpc_url.clone().unwrap_or(
            validate_url(&public_params.ethereum_http_rpc_url)
                .expect("Invalid Ethereum HTTP RPC URL received from server"),
        );

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

        if provider_chain_id != expected_chain_id {
            return Err(ClientError::Initialization(format!(
                "chain id mismatch between core service ({}) and Ethereum provider ({})",
                expected_chain_id, provider_chain_id
            )));
        }

        let operator_public_key: [u8; 48] =
            public_params
                .public_key
                .clone()
                .try_into()
                .map_err(|pk: Vec<u8>| {
                    ClientError::Initialization(format!(
                        "invalid operator public key length: expected 48 bytes, got {}",
                        pk.len()
                    ))
                })?;

        let contract_address = cfg.contract_address.unwrap_or(
            validate_address(&public_params.contract_address)
                .expect("Invalid contract address received from server"),
        );

        let contract = Core4Mica::new(contract_address, provider.clone());
        let on_chain_domain = contract
            .guaranteeDomainSeparator()
            .call()
            .await
            .map_err(|e| ClientError::Initialization(e.to_string()))?;
        let domain_bytes: [u8; 32] = on_chain_domain.into();
        crypto::guarantee::set_guarantee_domain_separator(domain_bytes)
            .map_err(|e| ClientError::Initialization(e.to_string()))?;

        Ok(Self(Arc::new(Inner {
            cfg,
            rpc_proxy,
            provider,
            contract_address,
            operator_public_key,
        })))
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
