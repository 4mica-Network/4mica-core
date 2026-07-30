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

use alloy::primitives::{Address, B256, U256};
use alloy::signers::Signer;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::client::{ClientCtx, DepositPath, user::UserClient};
use crate::contract::{
    Core4Mica::{Permit2Authorization, ReceiveAuthorization},
    PERMIT2_ADDRESS,
};
use crate::digest::eip712_digest_for_permit;
use crate::error::DepositError;

/// `assetTransferMethod` values, matching x402's `scheme_exact_evm`.
const METHOD_EIP3009: &str = "eip3009";
const METHOD_PERMIT2: &str = "permit2";

/// Validity window for a sponsored EIP-2612 permit, from signing time.
const PERMIT_TTL_SECS: u64 = 3600;

pub struct FacilitatorClient<S> {
    ctx: ClientCtx<S>,
    user: UserClient<S>,
    http: reqwest::Client,
    /// `None` when no facilitator was configured; every call then fails with
    /// [`DepositError::FacilitatorNotConfigured`] rather than silently doing nothing.
    base_url: Option<Url>,
}

/// Hand-written for the same reason as [`ClientCtx`]'s: everything held is shared, so an `S: Clone`
/// bound would be gratuitous.
impl<S> Clone for FacilitatorClient<S> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            user: self.user.clone(),
            http: self.http.clone(),
            base_url: self.base_url.clone(),
        }
    }
}

/// Outcome of a sponsored deposit.
#[derive(Debug, Clone)]
pub struct DepositReceipt {
    pub tx_hash: B256,
    /// Which route delivered the deposit — in particular, whether the payer paid gas.
    pub path: DepositPath,
    /// The account credited — always the signer, never the facilitator. Zero when the facilitator
    /// reported no `from`, which is worth treating as a failed check rather than a match.
    pub from: Address,
    pub asset: Address,
    pub amount: U256,
    pub network: Option<String>,
}

impl<S> FacilitatorClient<S> {
    pub(super) fn new(ctx: ClientCtx<S>, base_url: Option<Url>) -> Self {
        Self {
            user: UserClient::new(ctx.clone()),
            ctx,
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
        let authorization = self
            .user
            .sign_deposit_permit2(token.clone(), amount)
            .await?;
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
        self.post_deposit(
            &DepositRequest::eip3009(token, amount, authorization),
            DepositPath::Eip3009,
        )
        .await
    }

    /// Deposits through Permit2, signing the missing approval instead of transacting for it.
    ///
    /// Permit2 normally needs a one-time on-chain `approve(PERMIT2, …)`, which costs the payer gas
    /// and breaks the gasless promise. This attempts the deposit, and if the facilitator reports
    /// the allowance missing *and* the token supports EIP-2612, signs a permit and retries — the
    /// facilitator then submits both. This is x402's `eip2612GasSponsoring` extension.
    ///
    /// Still chain-free: the token's domain separator comes from core, and the owner's EIP-2612
    /// nonce comes from the facilitator's rejection. Nothing here reads the chain.
    ///
    /// Falls through with [`DepositError::Permit2AllowanceRequired`] when the token has no
    /// EIP-2612 surface — the approval cannot be sponsored, so the payer must send it themselves.
    pub async fn deposit_with_sponsored_permit2(
        &self,
        token: String,
        amount: U256,
    ) -> Result<DepositReceipt, DepositError> {
        // Try the plain path first: the payer may already have approved, in which case a permit is
        // pointless and the facilitator would only pay to submit a no-op.
        let authorization = self
            .user
            .sign_deposit_permit2(token.clone(), amount)
            .await?;
        let rejection = match self
            .submit_permit2(token.clone(), amount, authorization.clone())
            .await
        {
            Ok(receipt) => return Ok(receipt),
            Err(err) => err,
        };

        let DepositError::Permit2AllowanceRequired {
            eip2612_nonce: Some(nonce),
            ..
        } = &rejection
        else {
            // Either a different failure, or a token that cannot have its approval sponsored.
            return Err(rejection);
        };

        let permit = self.sign_permit_for_permit2(&token, *nonce).await?;
        self.post_deposit(
            &DepositRequest::permit2(token, amount, authorization, Some(permit)),
            DepositPath::SponsoredPermit2,
        )
        .await
    }

    /// Signs an EIP-2612 permit granting Permit2 an unlimited allowance for `token`.
    ///
    /// Unlimited deliberately: the allowance only lets Permit2 act, and Permit2 still requires a
    /// signed `PermitTransferFrom` per transfer. A tight allowance would just force another
    /// sponsored permit on the next deposit, at the facilitator's expense.
    async fn sign_permit_for_permit2(
        &self,
        token: &str,
        nonce: U256,
    ) -> Result<Eip2612PermitRequest, DepositError> {
        let token_address = crate::validators::validate_address(token).map_err(|_| {
            DepositError::InvalidParams(format!("invalid ERC20 token address: {token}"))
        })?;
        let owner = self.ctx.signer_address();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let deadline = U256::from(now.saturating_add(PERMIT_TTL_SECS));
        let value = U256::MAX;

        let domain_separator = self.ctx.token_domain_separator(token_address).await?;
        let digest = eip712_digest_for_permit(
            domain_separator,
            owner,
            PERMIT2_ADDRESS,
            value,
            nonce,
            deadline,
        );

        let signature = self
            .ctx
            .signer()
            .sign_hash(&digest)
            .await
            .map_err(|err| DepositError::Transport(err.to_string()))?;
        let bytes = signature.as_bytes();

        Ok(Eip2612PermitRequest {
            value: value.to_string(),
            deadline: deadline.to_string(),
            // Already Electrum notation, which is what the token's `ecrecover` expects — adding 27
            // here would invert the parity rather than fix it.
            v: bytes[64],
            r: B256::from_slice(&bytes[0..32]),
            s: B256::from_slice(&bytes[32..64]),
        })
    }

    /// Submits a Permit2 authorization signed elsewhere.
    pub async fn submit_permit2(
        &self,
        token: String,
        amount: U256,
        authorization: Permit2Authorization,
    ) -> Result<DepositReceipt, DepositError> {
        self.post_deposit(
            &DepositRequest::permit2(token, amount, authorization, None),
            DepositPath::Permit2,
        )
        .await
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
        let request = DepositRequest::eip3009(token, amount, authorization);
        let url = self.endpoint("deposit/verify")?;
        let response: DepositVerifyResponse = self.post(url, &request).await?;
        if response.is_valid {
            return Ok(());
        }
        Err(response.failure.into_error(response.invalid_reason))
    }

    async fn post_deposit(
        &self,
        request: &DepositRequest,
        path: DepositPath,
    ) -> Result<DepositReceipt, DepositError> {
        let url = self.endpoint("deposit")?;
        let response: DepositResponse = self.post(url, request).await?;

        if !response.success {
            return Err(response.failure.into_error(response.error));
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
            path,
            from: response
                .from
                .as_deref()
                .and_then(|raw| raw.parse().ok())
                .unwrap_or_default(),
            // Echoed back by the facilitator; fall back to what we asked for.
            asset: response
                .asset
                .as_deref()
                .and_then(|raw| raw.parse().ok())
                .or_else(|| request.asset.parse().ok())
                .unwrap_or_default(),
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
        let response =
            self.http.post(url).json(body).send().await.map_err(|err| {
                DepositError::Transport(format!("facilitator request failed: {err}"))
            })?;

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
    /// Sponsored EIP-2612 approval, so the payer never transacts. Only meaningful alongside
    /// `permit2Authorization`.
    #[serde(skip_serializing_if = "Option::is_none")]
    eip2612_permit: Option<Eip2612PermitRequest>,
}

impl DepositRequest {
    fn eip3009(asset: String, amount: U256, authorization: ReceiveAuthorization) -> Self {
        Self {
            network: None,
            asset,
            amount: amount.to_string(),
            asset_transfer_method: Some(METHOD_EIP3009.into()),
            authorization: Some(authorization),
            permit2_authorization: None,
            eip2612_permit: None,
        }
    }

    fn permit2(
        asset: String,
        amount: U256,
        authorization: Permit2Authorization,
        eip2612_permit: Option<Eip2612PermitRequest>,
    ) -> Self {
        Self {
            network: None,
            asset,
            amount: amount.to_string(),
            asset_transfer_method: Some(METHOD_PERMIT2.into()),
            authorization: None,
            permit2_authorization: Some(authorization),
            eip2612_permit,
        }
    }
}

/// Wire form of an EIP-2612 permit. `owner` and `spender` are implied — the signer and the
/// canonical Permit2 — so only the signed values travel.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Eip2612PermitRequest {
    value: String,
    deadline: String,
    v: u8,
    r: B256,
    s: B256,
}

/// Detail the facilitator attaches to `PERMIT2_ALLOWANCE_REQUIRED`, carrying the one value a
/// chain-free client cannot compute: the owner's current EIP-2612 nonce.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Permit2AllowanceResponse {
    eip2612_nonce: Option<String>,
}

/// Failure detail common to both endpoints; they differ only in which field carries the message.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FacilitatorFailure {
    permit2_allowance: Option<Permit2AllowanceResponse>,
    error_code: Option<String>,
    retryable: Option<bool>,
}

impl FacilitatorFailure {
    fn into_error(self, message: Option<String>) -> DepositError {
        let eip2612_nonce = self
            .permit2_allowance
            .and_then(|allowance| allowance.eip2612_nonce)
            .and_then(|raw| raw.parse().ok());
        DepositError::from_facilitator(
            self.error_code,
            message,
            // Absent means "not retryable": a facilitator that omits it is not promising anything.
            self.retryable.unwrap_or(false),
            eip2612_nonce,
        )
    }
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
    #[serde(flatten)]
    failure: FacilitatorFailure,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositVerifyResponse {
    is_valid: bool,
    invalid_reason: Option<String>,
    #[serde(flatten)]
    failure: FacilitatorFailure,
}
