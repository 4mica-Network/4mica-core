use std::{str::FromStr, sync::Arc};

use alloy::{
    consensus::SignableTransaction,
    primitives::{Address, B256},
    signers::{Signature, Signer},
};
use async_trait::async_trait;
use cdp_sdk::{
    CDP_BASE_URL, Client as CdpClient,
    auth::WalletAuth,
    types::{CreateEvmAccountBody, CreateEvmAccountBodyName, EvmAccount, SignEvmHashBody},
};
use reqwest_middleware::ClientBuilder;
use thiserror::Error;

/// Configuration for creating or loading a Coinbase Developer Platform EVM account.
#[derive(Clone, Debug)]
pub struct CdpAccountConfig {
    pub api_key_id: String,
    pub api_key_secret: String,
    pub wallet_secret: String,
    pub name: String,
}

/// Errors returned while creating or using a CDP-backed signer.
#[derive(Debug, Error)]
pub enum CdpWalletError {
    #[error("invalid CDP account name: {0}")]
    InvalidAccountName(String),
    #[error("invalid CDP account address: {0}")]
    InvalidAddress(String),
    #[error("failed to configure CDP wallet auth: {0}")]
    Auth(String),
    #[error("CDP request failed: {0}")]
    Request(String),
    #[error("invalid CDP signature: {0}")]
    InvalidSignature(String),
}

/// Alloy-compatible signer backed by a Coinbase Developer Platform EVM account.
#[derive(Clone)]
pub struct CdpSigner {
    client: Arc<CdpClient>,
    account_address: String,
    address: Address,
    chain_id: Option<u64>,
}

/// Create or load a named CDP account and return it as an Alloy-compatible signer.
pub async fn create_cdp_account(config: CdpAccountConfig) -> Result<CdpSigner, CdpWalletError> {
    CdpSigner::new(config).await
}

impl CdpSigner {
    /// Create or load a named CDP account.
    pub async fn new(config: CdpAccountConfig) -> Result<Self, CdpWalletError> {
        Self::new_with_chain_id(config, None).await
    }

    /// Create or load a named CDP account and set the transaction signing chain ID.
    pub async fn new_with_chain_id(
        config: CdpAccountConfig,
        chain_id: Option<u64>,
    ) -> Result<Self, CdpWalletError> {
        let client = Arc::new(build_cdp_client(&config)?);
        let account = get_or_create_account(&client, &config.name).await?;
        Self::from_account(client, account, chain_id)
    }

    /// Build a signer from an existing CDP client and account response.
    pub fn from_account(
        client: Arc<CdpClient>,
        account: EvmAccount,
        chain_id: Option<u64>,
    ) -> Result<Self, CdpWalletError> {
        let account_address = account.address.to_string();
        let address = Address::from_str(&account_address)
            .map_err(|err| CdpWalletError::InvalidAddress(err.to_string()))?;

        Ok(Self {
            client,
            account_address,
            address,
            chain_id,
        })
    }

    /// Return the 0x-prefixed CDP account address string.
    pub fn account_address(&self) -> &str {
        &self.account_address
    }
}

fn build_cdp_client(config: &CdpAccountConfig) -> Result<CdpClient, CdpWalletError> {
    let wallet_auth = WalletAuth::builder()
        .api_key_id(config.api_key_id.clone())
        .api_key_secret(config.api_key_secret.clone())
        .wallet_secret(config.wallet_secret.clone())
        .build()
        .map_err(|err| CdpWalletError::Auth(err.to_string()))?;

    let http_client = ClientBuilder::new(reqwest_012::Client::new())
        .with(wallet_auth)
        .build();

    Ok(CdpClient::new_with_client(CDP_BASE_URL, http_client))
}

async fn get_or_create_account(
    client: &CdpClient,
    name: &str,
) -> Result<EvmAccount, CdpWalletError> {
    match client.get_evm_account_by_name().name(name).send().await {
        Ok(response) => Ok(response.into_inner()),
        Err(_) => {
            let name = CreateEvmAccountBodyName::from_str(name)
                .map_err(|err| CdpWalletError::InvalidAccountName(err.to_string()))?;
            let body = CreateEvmAccountBody::builder().name(Some(name));
            client
                .create_evm_account()
                .x_wallet_auth("")
                .body(body)
                .send()
                .await
                .map(|response| response.into_inner())
                .map_err(|err| CdpWalletError::Request(err.to_string()))
        }
    }
}

fn signature_from_hex(signature: &str) -> Result<Signature, CdpWalletError> {
    Signature::from_str(signature).map_err(|err| CdpWalletError::InvalidSignature(err.to_string()))
}

#[async_trait]
impl Signer for CdpSigner {
    async fn sign_hash(&self, hash: &B256) -> alloy::signers::Result<Signature> {
        let body = SignEvmHashBody {
            hash: hash.to_string(),
        };

        let response = self
            .client
            .sign_evm_hash()
            .address(&self.account_address)
            .x_wallet_auth("")
            .body(body)
            .send()
            .await
            .map_err(alloy::signers::Error::other)?;

        signature_from_hex(&response.into_inner().signature).map_err(alloy::signers::Error::other)
    }

    fn address(&self) -> Address {
        self.address
    }

    fn chain_id(&self) -> Option<u64> {
        self.chain_id
    }

    fn set_chain_id(&mut self, chain_id: Option<u64>) {
        self.chain_id = chain_id;
    }
}

#[async_trait]
impl alloy::network::TxSigner<Signature> for CdpSigner {
    fn address(&self) -> Address {
        self.address
    }

    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> alloy::signers::Result<Signature> {
        if let Some(chain_id) = self.chain_id
            && !tx.set_chain_id_checked(chain_id)
        {
            return Err(alloy::signers::Error::TransactionChainIdMismatch {
                signer: chain_id,
                tx: tx.chain_id().expect("checked transaction chain ID exists"),
            });
        }

        self.sign_hash(&tx.signature_hash()).await
    }
}

#[cfg(test)]
mod tests {
    use cdp_sdk::types::EvmAccountAddress;

    use super::*;

    #[test]
    fn signer_from_account_keeps_address_and_chain_id() {
        let account = EvmAccount {
            address: EvmAccountAddress::from_str("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
                .unwrap(),
            created_at: None,
            name: None,
            policies: Vec::new(),
            updated_at: None,
        };

        let signer =
            CdpSigner::from_account(Arc::new(CdpClient::new(CDP_BASE_URL)), account, Some(8453))
                .unwrap();

        assert_eq!(
            signer.address(),
            Address::from_str("0x742d35Cc6634C0532925a3b844Bc454e4438f44e").unwrap()
        );
        assert_eq!(signer.chain_id(), Some(8453));
        assert_eq!(
            signer.account_address(),
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
        );
    }
}
