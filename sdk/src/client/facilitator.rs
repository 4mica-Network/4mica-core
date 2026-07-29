//! Gasless deposits through a facilitator.
//!
//! A payer holding stablecoins but no native gas cannot call `deposit` themselves. This client
//! signs the authorization and hands it to a facilitator, which submits the transaction and pays
//! the gas. Collateral is credited to the signer either way.
//!
//! # Why this is HTTP, not a chain call
//!
//! Everything here is `reqwest` — there is no provider and no transaction. The signing it wraps
//! ([`UserClient::sign_deposit_authorization`](crate::client::user::UserClient::sign_deposit_authorization)
//! and its Permit2 sibling) needs only `S: Signer`, and the token's EIP-712 domain comes from core
//! over HTTP rather than an `eth_call`. So a client using this path never needs an Ethereum RPC
//! endpoint of its own — that is the entire point of the facilitator.
//!
//! # Trust
//!
//! The signed digest binds the destination (the Core4Mica contract) and the amount, and the
//! contract credits the *signer*, never the submitter. A facilitator therefore cannot redirect the
//! funds or change the amount — the worst it can do is decline to submit, in which case fall back
//! to [`UserClient::deposit`](crate::client::user::UserClient::deposit) and pay the gas yourself.

use alloy::primitives::{B256, U256};
use alloy::signers::Signer;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::client::{ClientCtx, user::UserClient};
use crate::contract::Core4Mica::{Permit2Authorization, ReceiveAuthorization};
use crate::error::DepositError;

/// `assetTransferMethod` values, matching x402's `scheme_exact_evm`.
const METHOD_EIP3009: &str = "eip3009";
const METHOD_PERMIT2: &str = "permit2";

#[derive(Clone)]
pub struct FacilitatorClient<S> {
    user: UserClient<S>,
    http: reqwest::Client,
    /// `None` when no facilitator was configured; every call then fails with
    /// [`DepositError::FacilitatorNotConfigured`] rather than silently doing nothing.
    base_url: Option<Url>,
}

/// Outcome of a sponsored deposit.
#[derive(Debug, Clone)]
pub struct DepositReceipt {
    pub tx_hash: B256,
    /// The account credited — always the signer, never the facilitator.
    pub from: String,
    pub asset: String,
    pub amount: U256,
    pub network: Option<String>,
}

impl<S> FacilitatorClient<S> {
    pub(super) fn new(ctx: ClientCtx<S>, base_url: Option<Url>) -> Self {
        Self {
            user: UserClient::new(ctx),
            http: reqwest::Client::new(),
            base_url,
        }
    }

    /// Whether a facilitator is configured. Callers that want to fall back to a self-funded
    /// [`UserClient::deposit`](crate::client::user::UserClient::deposit) can branch on this rather
    /// than on an error.
    pub fn is_configured(&self) -> bool {
        self.base_url.is_some()
    }

    fn endpoint(&self, path: &str) -> Result<Url, DepositError> {
        let base = self
            .base_url
            .as_ref()
            .ok_or(DepositError::FacilitatorNotConfigured)?;
        base.join(path).map_err(|err| {
            DepositError::InvalidParams(format!("invalid facilitator URL for {path}: {err}"))
        })
    }
}

impl<S> FacilitatorClient<S>
where
    S: Signer + Send + Sync,
{
    /// Signs an EIP-3009 authorization and has the facilitator submit it. Truly gasless: the payer
    /// needs no native balance and makes no transaction.
    ///
    /// Requires a token implementing EIP-3009 (USDC and similar). For anything else see
    /// [`Self::deposit_with_permit2`].
    pub async fn deposit_with_authorization(
        &self,
        token: String,
        amount: U256,
    ) -> Result<DepositReceipt, DepositError> {
        let authorization = self
            .user
            .sign_deposit_authorization(token.clone(), amount)
            .await?;
        self.submit_deposit_authorization(token, amount, authorization)
            .await
    }

    /// Signs a Permit2 authorization and has the facilitator submit it.
    ///
    /// Works for any ERC-20, but **is not gasless on its own**: Permit2 requires a one-time
    /// on-chain `approve(PERMIT2, …)` from the payer. Without it the facilitator returns
    /// [`DepositError::Permit2AllowanceRequired`].
    pub async fn deposit_with_permit2(
        &self,
        token: String,
        amount: U256,
    ) -> Result<DepositReceipt, DepositError> {
        let authorization = self.user.sign_deposit_permit2(token.clone(), amount).await?;
        self.submit_permit2(token, amount, authorization).await
    }

    /// Submits an EIP-3009 authorization signed elsewhere — a hardware wallet, another process, or
    /// an earlier session. The authorization is self-contained, so it need not be signed here.
    pub async fn submit_deposit_authorization(
        &self,
        token: String,
        amount: U256,
        authorization: ReceiveAuthorization,
    ) -> Result<DepositReceipt, DepositError> {
        let request = DepositRequest {
            network: None,
            asset: token,
            amount: amount.to_string(),
            asset_transfer_method: Some(METHOD_EIP3009.into()),
            authorization: Some(authorization),
            permit2_authorization: None,
        };
        self.post_deposit(&request).await
    }

    /// Submits a Permit2 authorization signed elsewhere.
    pub async fn submit_permit2(
        &self,
        token: String,
        amount: U256,
        authorization: Permit2Authorization,
    ) -> Result<DepositReceipt, DepositError> {
        let request = DepositRequest {
            network: None,
            asset: token,
            amount: amount.to_string(),
            asset_transfer_method: Some(METHOD_PERMIT2.into()),
            authorization: None,
            permit2_authorization: Some(authorization),
        };
        self.post_deposit(&request).await
    }

    /// Preflight: runs every check the facilitator would run, without spending anyone's gas.
    ///
    /// Useful before handing an authorization to a user-facing flow, since it distinguishes a
    /// permanently unusable authorization from a transient failure.
    pub async fn verify_deposit_authorization(
        &self,
        token: String,
        amount: U256,
        authorization: ReceiveAuthorization,
    ) -> Result<(), DepositError> {
        let request = DepositRequest {
            network: None,
            asset: token,
            amount: amount.to_string(),
            asset_transfer_method: Some(METHOD_EIP3009.into()),
            authorization: Some(authorization),
            permit2_authorization: None,
        };

        let url = self.endpoint("deposit/verify")?;
        let response: DepositVerifyResponse = self.post(url, &request).await?;
        if response.is_valid {
            return Ok(());
        }
        Err(DepositError::from_facilitator(
            response.error_code,
            response.invalid_reason,
            response.retryable.unwrap_or(false),
        ))
    }

    async fn post_deposit(&self, request: &DepositRequest) -> Result<DepositReceipt, DepositError> {
        let url = self.endpoint("deposit")?;
        let response: DepositResponse = self.post(url, request).await?;

        if !response.success {
            return Err(DepositError::from_facilitator(
                response.error_code,
                response.error,
                response.retryable.unwrap_or(false),
            ));
        }

        let tx_hash = response
            .tx_hash
            .as_deref()
            .and_then(|raw| raw.parse::<B256>().ok())
            .ok_or_else(|| {
                DepositError::Transport("facilitator reported success without a txHash".into())
            })?;

        Ok(DepositReceipt {
            tx_hash,
            from: response.from.unwrap_or_default(),
            asset: response.asset.unwrap_or_else(|| request.asset.clone()),
            // Echoed back by the facilitator; fall back to what we asked for.
            amount: response
                .amount
                .as_deref()
                .and_then(|raw| raw.parse::<U256>().ok())
                .unwrap_or_default(),
            network: response.network,
        })
    }

    async fn post<Req, Resp>(&self, url: Url, body: &Req) -> Result<Resp, DepositError>
    where
        Req: Serialize + ?Sized,
        Resp: serde::de::DeserializeOwned,
    {
        let response = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|err| DepositError::Transport(format!("facilitator request failed: {err}")))?;

        let status = response.status();
        let bytes = response.bytes().await.map_err(|err| {
            DepositError::Transport(format!("failed to read facilitator response: {err}"))
        })?;

        // The facilitator reports deposit failures in the body with a 200, so a non-success status
        // is a transport or routing problem rather than a rejected deposit.
        if !status.is_success() {
            return Err(DepositError::Transport(format!(
                "facilitator returned {status}: {}",
                String::from_utf8_lossy(&bytes)
            )));
        }

        serde_json::from_slice(&bytes).map_err(|err| {
            DepositError::Transport(format!("malformed facilitator response: {err}"))
        })
    }
}

/// Wire format for `POST /deposit` and `POST /deposit/verify`.
///
/// Exactly one authorization is sent, tagged the way x402's `exact` scheme tags them — sibling
/// fields rather than one overloaded field.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DepositRequest {
    /// Omitted to use the facilitator's default network, which is the single-network case.
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    asset: String,
    amount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    asset_transfer_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization: Option<ReceiveAuthorization>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permit2_authorization: Option<Permit2Authorization>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositResponse {
    success: bool,
    tx_hash: Option<String>,
    network: Option<String>,
    from: Option<String>,
    asset: Option<String>,
    amount: Option<String>,
    error: Option<String>,
    error_code: Option<String>,
    retryable: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositVerifyResponse {
    is_valid: bool,
    invalid_reason: Option<String>,
    error_code: Option<String>,
    retryable: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The facilitator deserialises `ReceiveAuthorization` straight from this body, so the field
    /// names and hex encoding must match what `sdk-4mica` emits. Guards against drift between the
    /// two crates.
    #[test]
    fn deposit_request_serialises_an_eip3009_authorization() {
        let request = DepositRequest {
            network: None,
            asset: "0x2222222222222222222222222222222222222222".into(),
            amount: "1000".into(),
            asset_transfer_method: Some(METHOD_EIP3009.into()),
            authorization: Some(ReceiveAuthorization {
                from: alloy::primitives::Address::repeat_byte(0xbb),
                validAfter: U256::ZERO,
                validBefore: U256::from(2_000_000_000u64),
                nonce: B256::repeat_byte(0x42),
                v: 28,
                r: B256::repeat_byte(0x11),
                s: B256::repeat_byte(0x22),
            }),
            permit2_authorization: None,
        };

        let value = serde_json::to_value(&request).expect("serialize");
        assert_eq!(value["assetTransferMethod"], "eip3009");
        assert_eq!(value["authorization"]["v"], 28);
        assert!(
            value.get("permit2Authorization").is_none(),
            "the unused authorization must be omitted, not sent as null"
        );
        assert!(value.get("network").is_none());
    }

    #[test]
    fn deposit_request_serialises_a_permit2_authorization() {
        let request = DepositRequest {
            network: None,
            asset: "0x2222222222222222222222222222222222222222".into(),
            amount: "1000".into(),
            asset_transfer_method: Some(METHOD_PERMIT2.into()),
            authorization: None,
            permit2_authorization: Some(Permit2Authorization {
                from: alloy::primitives::Address::repeat_byte(0xbb),
                nonce: U256::from(7u64),
                deadline: U256::from(2_000_000_000u64),
                signature: vec![0u8; 65].into(),
            }),
        };

        let value = serde_json::to_value(&request).expect("serialize");
        assert_eq!(value["assetTransferMethod"], "permit2");
        assert!(value["permit2Authorization"]["signature"].is_string());
        assert!(value.get("authorization").is_none());
    }

    /// Codes must map to typed variants; a client should never have to match on prose.
    #[test]
    fn facilitator_error_codes_map_to_typed_variants() {
        let allowance = DepositError::from_facilitator(
            Some("PERMIT2_ALLOWANCE_REQUIRED".into()),
            Some("approve first".into()),
            false,
        );
        assert!(matches!(
            allowance,
            DepositError::Permit2AllowanceRequired { .. }
        ));

        let unknown = DepositError::from_facilitator(
            Some("SOMETHING_NEW".into()),
            Some("future code".into()),
            true,
        );
        match unknown {
            DepositError::Facilitator {
                code, retryable, ..
            } => {
                assert_eq!(code, "SOMETHING_NEW");
                assert!(retryable, "retryability must survive an unrecognised code");
            }
            other => panic!("expected a passthrough Facilitator error, got {other:?}"),
        }
    }
}
