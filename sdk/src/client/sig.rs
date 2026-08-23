//! EIP-712 authorizations a payer signs instead of transacting.
//!
//! Each one binds the payer, the amount, and a deadline into a digest that some other party can
//! redeem on-chain at their own expense. Signing never touches the network.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    signers::Signer,
};

use crate::{
    client::ClientCtx,
    contract::{
        Core4Mica::{
            Permit2Authorization, ReceiveAuthorization, WithdrawalCancelAuthorization,
            WithdrawalRequestAuthorization,
        },
        PERMIT2_ADDRESS,
    },
    digest::{
        eip712_digest_for_cancel_withdrawal, eip712_digest_for_permit,
        eip712_digest_for_permit2_transfer, eip712_digest_for_receive_authorization,
        eip712_digest_for_request_withdrawal,
    },
    error::{DepositError, SettlementError, SponsorshipError},
};

/// How long a signed authorization stays redeemable.
const AUTHORIZATION_TTL_SECS: u64 = 3600;

/// An EIP-2612 permit, ready to be handed to whoever will submit it. `owner` and `spender` are
/// implied by the call that produced it.
pub(super) struct Eip2612Permit {
    pub value: U256,
    pub deadline: U256,
    pub v: u8,
    pub r: B256,
    pub s: B256,
}

/// Wire form of an EIP-2612 permit. `owner` and `spender` are implied — the signer and the
/// canonical Permit2 — so only the signed values travel.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Eip2612PermitRequest {
    value: String,
    deadline: String,
    v: u8,
    r: B256,
    s: B256,
}

impl From<Eip2612Permit> for Eip2612PermitRequest {
    fn from(permit: Eip2612Permit) -> Self {
        Self {
            value: permit.value.to_string(),
            deadline: permit.deadline.to_string(),
            v: permit.v,
            r: permit.r,
            s: permit.s,
        }
    }
}

/// Signs an EIP-3009 `receiveWithAuthorization` crediting `amount` of `token` to the signer.
///
/// Only tokens implementing EIP-3009 (USDC and similar) can redeem this.
pub(super) async fn eip3009_authorization<S>(
    ctx: &ClientCtx<S>,
    token: Address,
    amount: U256,
) -> Result<ReceiveAuthorization, DepositError>
where
    S: Signer + Send + Sync,
{
    let nonce = B256::from(rand::random::<[u8; 32]>());
    let domain_separator = ctx.token_domain_separator(token).await?;
    signed_receive_authorization(ctx, domain_separator, ctx.contract_address(), amount, nonce)
        .await
        .map_err(|e| DepositError::Transport(e.to_string()))
}

/// Signs an EIP-3009 `receiveWithAuthorization` paying the signer's net debit: `amount` of `token`
/// to `receiver` (the ClearingHouse), with the nonce pinned to the cycle id as
/// `payNetDebitWithAuthorization` requires.
pub(super) async fn debit_authorization<S>(
    ctx: &ClientCtx<S>,
    token: Address,
    receiver: Address,
    amount: U256,
    cycle_id: B256,
) -> Result<ReceiveAuthorization, SettlementError>
where
    S: Signer + Send + Sync,
{
    let domain_separator = ctx.token_domain_separator(token).await?;
    signed_receive_authorization(ctx, domain_separator, receiver, amount, cycle_id)
        .await
        .map_err(|e| SettlementError::Transport(e.to_string()))
}

async fn signed_receive_authorization<S>(
    ctx: &ClientCtx<S>,
    domain_separator: B256,
    to: Address,
    amount: U256,
    nonce: B256,
) -> Result<ReceiveAuthorization, alloy::signers::Error>
where
    S: Signer + Send + Sync,
{
    let from = ctx.signer_address();
    let valid_before = U256::from(now_secs().saturating_add(AUTHORIZATION_TTL_SECS));
    let digest = eip712_digest_for_receive_authorization(
        domain_separator,
        from,
        to,
        amount,
        U256::ZERO,
        valid_before,
        nonce,
    );

    let sig = ctx.signer().sign_hash(&digest).await?;
    let bytes = sig.as_bytes();
    Ok(ReceiveAuthorization {
        from,
        validAfter: U256::ZERO,
        validBefore: valid_before,
        nonce,
        v: bytes[64],
        r: B256::from_slice(&bytes[0..32]),
        s: B256::from_slice(&bytes[32..64]),
    })
}

/// Signs a Permit2 `PermitTransferFrom` paying the signer's net debit: `amount` of `token` with
/// `receiver` (the ClearingHouse) as spender, and the nonce pinned to the cycle id as
/// `payNetDebitWithPermit2` requires.
///
/// Works for any ERC-20, but only if the signer has already approved Permit2 to move that token.
pub(super) async fn debit_permit2_authorization<S>(
    ctx: &ClientCtx<S>,
    token: Address,
    receiver: Address,
    amount: U256,
    cycle_id: B256,
) -> Result<Permit2Authorization, SettlementError>
where
    S: Signer + Send + Sync,
{
    let deadline = U256::from(now_secs().saturating_add(AUTHORIZATION_TTL_SECS));
    let digest = eip712_digest_for_permit2_transfer(
        ctx.permit2_domain_separator(),
        token,
        amount,
        receiver,
        U256::from_be_bytes(cycle_id.0),
        deadline,
    );

    let signature = ctx
        .signer()
        .sign_hash(&digest)
        .await
        .map_err(|e| SettlementError::Transport(e.to_string()))?;
    Ok(Permit2Authorization {
        from: ctx.signer_address(),
        nonce: U256::from_be_bytes(cycle_id.0),
        deadline,
        signature: Bytes::from(signature.as_bytes().to_vec()),
    })
}

/// Signs a Permit2 `PermitTransferFrom` for `amount` of `token`.
///
/// Works for any ERC-20, but only if the signer has already approved Permit2 to move that token.
pub(super) async fn permit2_authorization<S>(
    ctx: &ClientCtx<S>,
    token: Address,
    amount: U256,
) -> Result<Permit2Authorization, DepositError>
where
    S: Signer + Send + Sync,
{
    let from = ctx.signer_address();
    let spender = ctx.contract_address();
    let deadline = U256::from(now_secs().saturating_add(AUTHORIZATION_TTL_SECS));
    let nonce = U256::from_be_bytes(rand::random::<[u8; 32]>());

    let digest = eip712_digest_for_permit2_transfer(
        ctx.permit2_domain_separator(),
        token,
        amount,
        spender,
        nonce,
        deadline,
    );

    let signature = ctx
        .signer()
        .sign_hash(&digest)
        .await
        .map_err(|e| DepositError::Transport(e.to_string()))?;
    Ok(Permit2Authorization {
        from,
        nonce,
        deadline,
        signature: Bytes::from(signature.as_bytes().to_vec()),
    })
}

/// Signs an EIP-2612 permit granting Permit2 an unlimited allowance for `token`.
///
/// Unlimited deliberately: the allowance only lets Permit2 act, and Permit2 still requires a signed
/// `PermitTransferFrom` per transfer. A tight allowance would just force another permit on the next
/// deposit, at the submitter's expense.
pub(super) async fn eip2612_permit<S>(
    ctx: &ClientCtx<S>,
    token: Address,
    nonce: U256,
) -> Result<Eip2612Permit, DepositError>
where
    S: Signer + Send + Sync,
{
    let deadline = U256::from(now_secs().saturating_add(AUTHORIZATION_TTL_SECS));
    let value = U256::MAX;

    let domain_separator = ctx.token_domain_separator(token).await?;
    let digest = eip712_digest_for_permit(
        domain_separator,
        ctx.signer_address(),
        PERMIT2_ADDRESS,
        value,
        nonce,
        deadline,
    );

    let (v, r, s) = sign_vrs(ctx.signer(), &digest).await?;
    Ok(Eip2612Permit {
        value,
        deadline,
        v,
        r,
        s,
    })
}

/// [`eip2612_permit`] reported in the settlement error space, for sponsoring a debit's missing
/// Permit2 approval.
pub(super) async fn debit_eip2612_permit<S>(
    ctx: &ClientCtx<S>,
    token: Address,
    nonce: U256,
) -> Result<Eip2612Permit, SettlementError>
where
    S: Signer + Send + Sync,
{
    eip2612_permit(ctx, token, nonce)
        .await
        .map_err(|err| match err {
            DepositError::Client(client) => SettlementError::Client(client),
            other => SettlementError::Transport(other.to_string()),
        })
}

/// Signs a `RequestWithdrawal` authorization for `amount` of `asset` (`Address::ZERO` for ETH).
///
/// The digest binds the asset, the amount and the window, so whoever submits it can change none of
/// them — the worst they can do is not submit.
pub(super) async fn request_withdrawal_authorization<S>(
    ctx: &ClientCtx<S>,
    asset: Address,
    amount: U256,
) -> Result<WithdrawalRequestAuthorization, SponsorshipError>
where
    S: Signer + Send + Sync,
{
    let user = ctx.signer_address();
    let valid_before = U256::from(now_secs().saturating_add(AUTHORIZATION_TTL_SECS));
    let nonce = B256::from(rand::random::<[u8; 32]>());

    let digest = eip712_digest_for_request_withdrawal(
        ctx.core_domain_separator(),
        user,
        asset,
        amount,
        U256::ZERO,
        valid_before,
        nonce,
    );

    Ok(WithdrawalRequestAuthorization {
        user,
        asset,
        amount,
        validAfter: U256::ZERO,
        validBefore: valid_before,
        nonce,
        signature: sign_bytes(ctx, &digest).await?,
    })
}

/// Signs a `CancelWithdrawal` authorization for the pending request on `asset`.
pub(super) async fn cancel_withdrawal_authorization<S>(
    ctx: &ClientCtx<S>,
    asset: Address,
) -> Result<WithdrawalCancelAuthorization, SponsorshipError>
where
    S: Signer + Send + Sync,
{
    let user = ctx.signer_address();
    let valid_before = U256::from(now_secs().saturating_add(AUTHORIZATION_TTL_SECS));
    let nonce = B256::from(rand::random::<[u8; 32]>());

    let digest = eip712_digest_for_cancel_withdrawal(
        ctx.core_domain_separator(),
        user,
        asset,
        U256::ZERO,
        valid_before,
        nonce,
    );

    Ok(WithdrawalCancelAuthorization {
        user,
        asset,
        validAfter: U256::ZERO,
        validBefore: valid_before,
        nonce,
        signature: sign_bytes(ctx, &digest).await?,
    })
}

/// Signs `digest` into the packed 65-byte form Core4Mica's `SignatureChecker` expects.
async fn sign_bytes<S>(ctx: &ClientCtx<S>, digest: &B256) -> Result<Bytes, SponsorshipError>
where
    S: Signer + Send + Sync,
{
    let signature = ctx
        .signer()
        .sign_hash(digest)
        .await
        .map_err(|e| SponsorshipError::Transport(e.to_string()))?;
    Ok(Bytes::from(signature.as_bytes().to_vec()))
}

/// Current UNIX time in seconds, saturating to 0 if the clock is before the epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Signs `digest` and splits the result into `(v, r, s)`, with `v` left in Electrum notation
/// (27/28) as `ecrecover` expects — adding 27 here would invert the parity rather than fix it.
async fn sign_vrs<S: Signer>(signer: &S, digest: &B256) -> Result<(u8, B256, B256), DepositError> {
    let sig = signer
        .sign_hash(digest)
        .await
        .map_err(|e| DepositError::Transport(e.to_string()))?;
    let bytes = sig.as_bytes();
    Ok((
        bytes[64],
        B256::from_slice(&bytes[0..32]),
        B256::from_slice(&bytes[32..64]),
    ))
}
