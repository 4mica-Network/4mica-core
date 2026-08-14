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
    error::{DepositError, SponsorshipError},
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
    let from = ctx.signer_address();
    let to = ctx.contract_address();
    let valid_before = U256::from(now_secs().saturating_add(AUTHORIZATION_TTL_SECS));
    let nonce = B256::from(rand::random::<[u8; 32]>());

    let domain_separator = ctx.token_domain_separator(token).await?;
    let digest = eip712_digest_for_receive_authorization(
        domain_separator,
        from,
        to,
        amount,
        U256::ZERO,
        valid_before,
        nonce,
    );

    let (v, r, s) = sign_vrs(ctx.signer(), &digest).await?;
    Ok(ReceiveAuthorization {
        from,
        validAfter: U256::ZERO,
        validBefore: valid_before,
        nonce,
        v,
        r,
        s,
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
