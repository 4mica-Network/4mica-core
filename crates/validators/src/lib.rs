//! Resolving a [`ValidationRequirement`] into a [`Verdict`].
//!
//! Each kind of validator is driven by a [`ValidatorAdapter`], which owns everything specific to
//! it: how to reach it, how to read its `params`, and how to verify whatever it returns. Callers
//! see only the three-state verdict.

use std::sync::Arc;
use std::time::UNIX_EPOCH;
use std::{collections::HashMap, time::SystemTime};

use alloy::providers::DynProvider;
use alloy_primitives::{B256, Bytes};
use anyhow::{Context, bail};
use async_trait::async_trait;
use rpc::ValidationRequirement;
use serde::{Deserialize, Serialize};

pub mod erc8004;

pub use erc8004::Erc8004Adapter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    Pending,
    Approved,
    Rejected,
}

/// A validator's answer for one requirement, normalized across every adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub status: VerdictStatus,
    /// What this verdict is about. Callers must discard a verdict whose subject differs from
    /// the requirement it was fetched for.
    pub subject: B256,
    /// Payload the adapter observed, verbatim. Not normalized: any attestation covers the
    /// validator's own bytes and only stays verifiable intact.
    pub evidence: Bytes,
    /// Unix seconds at which the adapter observed this verdict.
    pub observed_at: u64,
}

/// Drives one kind of validator.
///
/// Implementations must fail closed: anything short of the validator explicitly refusing —
/// unreachable endpoint, malformed response, failed attestation check — is
/// [`VerdictStatus::Pending`], never [`VerdictStatus::Rejected`]. Only the validator itself may
/// reject; a broken transport must not be able to.
#[async_trait]
pub trait ValidatorAdapter: Send + Sync {
    /// Adapter kind, matched against [`ValidatorEntry::kind`].
    fn kind(&self) -> &str;

    /// Reject a requirement this adapter could never satisfy, so a malformed `params` fails up
    /// front rather than at the deadline.
    fn validate_requirement(&self, req: &ValidationRequirement) -> anyhow::Result<()>;

    async fn resolve(&self, req: &ValidationRequirement) -> anyhow::Result<Verdict>;
}

/// One configured validator: its identity, the adapter that drives it, and that adapter's
/// settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEntry {
    /// Validator identity, matched verbatim against [`ValidationRequirement::validator`].
    /// Only its adapter interprets it (a URL, a CAIP-10 account id, …).
    pub uri: String,
    /// Which adapter implementation drives this validator. Not derivable from `uri`: two
    /// validators can share a transport yet answer in entirely different ways.
    pub kind: String,
    /// Settings for this validator, shaped by its adapter.
    #[serde(default)]
    pub config: serde_json::Value,
}

/// Adapters bound to the validators that were configured. A validator absent from the registry
/// cannot be resolved at all, which makes this the allowlist.
#[derive(Clone, Default)]
pub struct ValidatorRegistry {
    adapters: HashMap<String, Arc<dyn ValidatorAdapter>>,
}

impl ValidatorRegistry {
    /// Construct each entry's adapter from its `kind` and `config`. `provider` is handed to
    /// adapters that read chain state.
    pub async fn build(
        entries: &[ValidatorEntry],
        provider: Option<DynProvider>,
    ) -> anyhow::Result<Self> {
        let mut adapters: HashMap<String, Arc<dyn ValidatorAdapter>> = HashMap::new();

        for entry in entries {
            let adapter: Arc<dyn ValidatorAdapter> = match entry.kind.as_str() {
                erc8004::KIND => {
                    let provider = provider.clone().context(
                        "erc8004 validators need a chain provider, but none is configured",
                    )?;
                    Arc::new(Erc8004Adapter::new(&entry.uri, &entry.config, provider).await?)
                }
                unknown => bail!(
                    "unknown validator kind '{unknown}' for validator '{}'",
                    entry.uri
                ),
            };

            if adapters.insert(entry.uri.clone(), adapter).is_some() {
                bail!("duplicate validator '{}' in the whitelist", entry.uri);
            }
        }

        Ok(Self { adapters })
    }

    /// Bind adapters directly, bypassing `kind`/config resolution. For tests and for embedding
    /// a bespoke adapter that is not constructible from configuration.
    pub fn from_adapters(
        adapters: impl IntoIterator<Item = (String, Arc<dyn ValidatorAdapter>)>,
    ) -> Self {
        Self {
            adapters: adapters.into_iter().collect(),
        }
    }

    pub fn get(&self, validator: &str) -> Option<&Arc<dyn ValidatorAdapter>> {
        self.adapters.get(validator)
    }

    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }

    /// Configured validator identities, sorted.
    pub fn validators(&self) -> Vec<String> {
        let mut uris: Vec<String> = self.adapters.keys().cloned().collect();
        uris.sort();
        uris
    }
}

/// Parse an adapter's `config` blob, defaulting when it is absent.
pub(crate) fn parse_config<T: serde::de::DeserializeOwned + Default>(
    kind: &str,
    config: &serde_json::Value,
) -> anyhow::Result<T> {
    if config.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(config.clone())
        .with_context(|| format!("invalid config for '{kind}' validator"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
