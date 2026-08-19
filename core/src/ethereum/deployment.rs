//! Startup handshake with the deployed contracts.
//!
//! Reads the on-chain facts core needs before it can serve anything, and refuses to start against
//! a deployment that does not match its configuration.

use std::collections::HashMap;

use anyhow::anyhow;
use log::{info, warn};
use rpc::SUPPORTED_GUARANTEE_VERSIONS;

use crate::ethereum::CoreContractApi;

/// What the chain reported about the deployment core is running against.
pub struct ChainDeployment {
    pub chain_id: u64,
    /// Domain separator per supported guarantee version.
    pub guarantee_domains: HashMap<u64, [u8; 32]>,
    pub withdrawal_grace_period: u64,
    /// `None` when the contract predates `DOMAIN_SEPARATOR()`.
    pub core_domain_separator: Option<[u8; 32]>,
}

impl ChainDeployment {
    /// Load and validate the deployment, failing if the node's chain id disagrees with
    /// `expected_chain_id` or a supported guarantee version is disabled on-chain.
    pub async fn load(api: &dyn CoreContractApi, expected_chain_id: u64) -> anyhow::Result<Self> {
        let chain_id = api
            .get_chain_id()
            .await
            .map_err(|e| anyhow!("failed to get chain id: {e}"))?;
        if chain_id != expected_chain_id {
            anyhow::bail!(
                "ETHEREUM_CHAIN_ID ({expected_chain_id}) does not match node-reported chain id ({chain_id}).",
            );
        }

        let guarantee_domains = Self::load_guarantee_domains(api).await?;

        let withdrawal_grace_period = api.get_withdrawal_grace_period().await?;
        info!(
            "on-chain withdrawal grace period: {}s",
            withdrawal_grace_period
        );

        Ok(Self {
            chain_id,
            guarantee_domains,
            withdrawal_grace_period,
            core_domain_separator: Self::load_core_domain_separator(api).await,
        })
    }

    async fn load_guarantee_domains(
        api: &dyn CoreContractApi,
    ) -> anyhow::Result<HashMap<u64, [u8; 32]>> {
        let mut domains = HashMap::new();
        for &version in SUPPORTED_GUARANTEE_VERSIONS {
            let version_config = api.get_guarantee_version_config(version).await?;
            if !version_config.enabled {
                anyhow::bail!("supported guarantee version {version} is disabled on-chain");
            }
            info!(
                "on-chain guarantee v{} domain separator: {} (decoder: {})",
                version_config.version,
                crypto::hex::encode_hex(&version_config.domain_separator),
                version_config.decoder
            );
            domains.insert(version, version_config.domain_separator);
        }
        Ok(domains)
    }

    /// A deployment old enough to lack `DOMAIN_SEPARATOR()` also lacks the gasless
    /// entrypoints, so leaving the separator unpublished disables a feature that contract could
    /// not serve anyway. Everything else core does is unaffected, so this must not be fatal.
    async fn load_core_domain_separator(api: &dyn CoreContractApi) -> Option<[u8; 32]> {
        match api.get_core_domain_separator().await {
            Ok(separator) => {
                info!(
                    "on-chain core domain separator: {}",
                    crypto::hex::encode_hex(&separator)
                );
                Some(separator)
            }
            Err(e) => {
                warn!(
                    "contract does not expose DOMAIN_SEPARATOR() ({e}); gas sponsorship is \
                     unavailable until it is redeployed"
                );
                None
            }
        }
    }
}
