//! Depositing collateral, over whichever route is cheapest for the payer.
//!
//! [`DepositClient::of`] captures the intent, a route pin (`gasless()`, `eip3009()`, `permit2()`,
//! `self_funded()`) narrows how, and a terminal (`send()`, `sign()`, `verify()`, `approve()`)
//! does it. Gasless routes ([EIP-3009] and [Permit2]) have the payer sign an authorization that
//! someone else redeems and pays gas for — attach one signed elsewhere with `authorization(…)` —
//! while the self-funded route is the payer's own transaction. Every route credits the
//! authorization's signer, so the choice only changes who pays — [`DepositReceipt::route`]
//! reports which one ran.
//!
//! [EIP-3009]: https://eips.ethereum.org/EIPS/eip-3009
//! [Permit2]: https://github.com/Uniswap/permit2

use alloy::{
    network::TxSigner,
    primitives::{Address, B256, U256},
    rpc::types::TransactionReceipt,
    signers::{Signature, Signer},
};
use serde::{Deserialize, Serialize};

use crate::{
    client::{
        ClientCtx, await_receipt, confirm_echoed,
        facilitator::FacilitatorFailure,
        model::{Asset, DepositReceipt, TokenRoute},
        route,
        sig::{self, Eip2612PermitRequest},
    },
    contract::Core4Mica::{Permit2Authorization, ReceiveAuthorization},
    error::{ClientError, DepositError},
};

pub struct DepositClient<S> {
    ctx: ClientCtx<S>,
}

impl<S> Clone for DepositClient<S> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
        }
    }
}

impl<S> DepositClient<S> {
    pub(super) fn new(ctx: ClientCtx<S>) -> Self {
        Self { ctx }
    }

    /// Whether a gasless route is available at all. Callers that want to decide for themselves
    /// rather than let the auto route fall back can branch on this instead of on an error.
    pub fn is_gasless_available(&self) -> bool {
        self.ctx.facilitator().is_configured()
    }

    /// Starts a deposit of `amount` of `asset`. Nothing happens until a terminal (`send()`,
    /// `sign()`, `verify()`, `approve()`) runs.
    pub fn of(&self, asset: Asset, amount: U256) -> DepositBuilder<S, route::Auto> {
        DepositBuilder {
            ctx: self.ctx.clone(),
            asset,
            amount,
            route: route::Auto,
        }
    }
}

/// A deposit being built. Terminal signer bounds are per route: gasless pins need only a
/// [`Signer`], the self-funded pin (and the auto route, which may fall back to it) a transaction
/// signer too.
#[must_use = "a builder does nothing until a terminal method (`send`, `sign`, `verify`, `approve`) runs"]
pub struct DepositBuilder<S, R = route::Auto> {
    ctx: ClientCtx<S>,
    asset: Asset,
    amount: U256,
    route: R,
}

impl<S, R> DepositBuilder<S, R> {
    fn with_route<T>(self, route: T) -> DepositBuilder<S, T> {
        DepositBuilder {
            ctx: self.ctx,
            asset: self.asset,
            amount: self.amount,
            route,
        }
    }

    /// The ERC-20 behind a gasless pin. Native ETH has no gasless route — no authorization scheme
    /// covers it — so this is the one invalid combination the types cannot rule out.
    fn erc20_token(&self) -> Result<Address, DepositError> {
        match self.asset {
            Asset::Erc20(token) => Ok(token),
            Asset::Native => Err(DepositError::InvalidParams(
                "native ETH has no gasless route; deposit it self-funded".into(),
            )),
        }
    }
}

impl<S> DepositBuilder<S, route::Auto> {
    /// Pins "any gasless scheme": EIP-3009 first, then Permit2 with the approval sponsored, with
    /// no self-funded fallback.
    pub fn gasless(self) -> DepositBuilder<S, route::Gasless> {
        self.with_route(route::Gasless)
    }

    /// Pins the EIP-3009 route, failing rather than trying another scheme.
    pub fn eip3009(self) -> DepositBuilder<S, route::Eip3009> {
        self.with_route(route::Eip3009)
    }

    /// Pins the Permit2 route, failing rather than trying another scheme.
    pub fn permit2(self) -> DepositBuilder<S, route::Permit2> {
        self.with_route(route::Permit2)
    }

    /// Pins the payer's own transaction.
    pub fn self_funded(self) -> DepositBuilder<S, route::SelfFunded> {
        self.with_route(route::SelfFunded)
    }

    /// Deposits over the cheapest route available.
    ///
    /// Prefers routes someone else pays for, in order: EIP-3009, then Permit2 with the approval
    /// sponsored where the token allows it. Falls back to the payer's own transaction when no
    /// gasless route applies — native ETH, no facilitator configured, or a token whose Permit2
    /// approval cannot be sponsored.
    ///
    /// Read [`DepositReceipt::route`] to see which route ran, or pin one instead.
    pub async fn send(self) -> Result<DepositReceipt, DepositError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let Asset::Erc20(token) = self.asset else {
            return self.with_route(route::SelfFunded).send().await;
        };
        if !self.ctx.facilitator().is_configured() {
            return self.with_route(route::SelfFunded).send().await;
        }

        // EIP-3009 is the cheapest route, but nothing says up front whether a token implements it —
        // a domain separator only proves EIP-712, which EIP-2612 has too. So try it and read the
        // answer off the rejection, which costs no gas.
        let rejection = match send_eip3009(&self.ctx, token, self.amount).await {
            Ok(receipt) => return Ok(receipt),
            Err(err) => err,
        };
        if !rejection.refuses_the_authorization() {
            return Err(rejection);
        }

        match send_sponsored_permit2(&self.ctx, token, self.amount).await {
            // The approval cannot be sponsored, so gaslessness is off the table either way; paying
            // for the deposit directly is one transaction rather than an approval plus a deposit.
            Err(DepositError::Permit2AllowanceRequired { .. }) => {
                fallback_to_self_funded(&self.ctx, token, self.amount).await
            }
            outcome => outcome,
        }
    }
}

impl<S> DepositBuilder<S, route::Gasless> {
    /// Deposits gaslessly, over whichever scheme the token supports: EIP-3009 first, then Permit2
    /// with the approval sponsored. Fails rather than falling back to the payer's own transaction.
    pub async fn send(self) -> Result<DepositReceipt, DepositError>
    where
        S: Signer + Send + Sync,
    {
        let token = self.erc20_token()?;
        let rejection = match send_eip3009(&self.ctx, token, self.amount).await {
            Ok(receipt) => return Ok(receipt),
            Err(err) => err,
        };
        if !rejection.refuses_the_authorization() {
            return Err(rejection);
        }
        send_sponsored_permit2(&self.ctx, token, self.amount).await
    }
}

impl<S> DepositBuilder<S, route::Eip3009> {
    /// Signs the EIP-3009 authorization without submitting it, for callers that redeem it
    /// elsewhere. Redeem by attaching it to a fresh builder:
    /// `deposit.of(asset, amount).eip3009().authorization(auth).send()`.
    pub async fn sign(self) -> Result<ReceiveAuthorization, DepositError>
    where
        S: Signer + Send + Sync,
    {
        let token = self.erc20_token()?;
        sig::eip3009_authorization(&self.ctx, token, self.amount).await
    }

    /// Attaches an EIP-3009 authorization signed elsewhere — a hardware wallet, another process,
    /// or an earlier session. The authorization is self-contained, so it need not have been
    /// signed here.
    pub fn authorization(
        self,
        authorization: ReceiveAuthorization,
    ) -> DepositBuilder<S, route::Authorized<ReceiveAuthorization>> {
        self.with_route(route::Authorized {
            auth: authorization,
        })
    }

    /// Deposits gaslessly with an EIP-3009 authorization. The payer needs no native balance and
    /// makes no transaction.
    ///
    /// Requires a token implementing EIP-3009 (USDC and similar); for anything else pin
    /// `permit2()`.
    pub async fn send(self) -> Result<DepositReceipt, DepositError>
    where
        S: Signer + Send + Sync,
    {
        let token = self.erc20_token()?;
        send_eip3009(&self.ctx, token, self.amount).await
    }
}

impl<S> DepositBuilder<S, route::Permit2> {
    /// Upgrades the pin to sign the missing Permit2 approval (EIP-2612) rather than fail on it.
    pub fn sponsor_approval(self) -> DepositBuilder<S, route::SponsoredPermit2> {
        self.with_route(route::SponsoredPermit2)
    }

    /// Signs the Permit2 authorization without submitting it. Redeem by attaching it to a fresh
    /// builder: `deposit.of(asset, amount).permit2().authorization(auth).send()`.
    pub async fn sign(self) -> Result<Permit2Authorization, DepositError>
    where
        S: Signer + Send + Sync,
    {
        let token = self.erc20_token()?;
        sig::permit2_authorization(&self.ctx, token, self.amount).await
    }

    /// Attaches a Permit2 authorization signed elsewhere.
    pub fn authorization(
        self,
        authorization: Permit2Authorization,
    ) -> DepositBuilder<S, route::Authorized<Permit2Authorization>> {
        self.with_route(route::Authorized {
            auth: authorization,
        })
    }

    /// Deposits gaslessly through Permit2.
    ///
    /// Works for any ERC-20, but **is not gasless on its own**: Permit2 needs a one-time on-chain
    /// `approve(PERMIT2, …)` from the payer, without which this fails with
    /// [`DepositError::Permit2AllowanceRequired`]. `sponsor_approval()` covers that approval too,
    /// where the token allows it.
    pub async fn send(self) -> Result<DepositReceipt, DepositError>
    where
        S: Signer + Send + Sync,
    {
        let token = self.erc20_token()?;
        send_permit2(&self.ctx, token, self.amount).await
    }
}

impl<S> DepositBuilder<S, route::SponsoredPermit2> {
    /// Deposits through Permit2, signing the missing approval rather than transacting for it.
    ///
    /// Tries the plain Permit2 route first; if the allowance is missing *and* the token supports
    /// EIP-2612, signs a permit for it and retries so both are submitted together. Still costs the
    /// payer nothing.
    ///
    /// Fails with [`DepositError::Permit2AllowanceRequired`] for tokens with no EIP-2612 surface —
    /// their approval cannot be sponsored, so the payer must send it themselves.
    ///
    /// No `sign()` on this pin: the permit needs the payer's current EIP-2612 nonce, which only
    /// arrives with the facilitator's rejection, so there is nothing self-contained to sign
    /// offline.
    pub async fn send(self) -> Result<DepositReceipt, DepositError>
    where
        S: Signer + Send + Sync,
    {
        let token = self.erc20_token()?;
        send_sponsored_permit2(&self.ctx, token, self.amount).await
    }
}

impl<S> DepositBuilder<S, route::Authorized<ReceiveAuthorization>> {
    /// Preflight: runs every check a real submission would run, without spending anyone's gas.
    ///
    /// Worth doing before handing an authorization to a user-facing flow, since it tells a
    /// permanently unusable authorization apart from a transient failure.
    pub async fn verify(&self) -> Result<(), DepositError> {
        let token = self.erc20_token()?;
        let request = DepositRequest::new(
            token,
            self.amount,
            DepositAuthorization::Eip3009 {
                authorization: self.route.auth.clone(),
            },
        );
        verify_deposit(&self.ctx, &request).await
    }

    /// Deposits with the attached authorization. The submitter needs no signer of their own.
    pub async fn send(self) -> Result<DepositReceipt, DepositError> {
        let token = self.erc20_token()?;
        let deposited = Deposited {
            payer: self.route.auth.from,
            asset: token,
            amount: self.amount,
        };
        submit(
            &self.ctx,
            DepositRequest::new(
                token,
                self.amount,
                DepositAuthorization::Eip3009 {
                    authorization: self.route.auth,
                },
            ),
            TokenRoute::Eip3009,
            deposited,
        )
        .await
    }
}

impl<S> DepositBuilder<S, route::Authorized<Permit2Authorization>> {
    /// Preflight: runs every check a real submission would run, without spending anyone's gas.
    pub async fn verify(&self) -> Result<(), DepositError> {
        let token = self.erc20_token()?;
        let request = DepositRequest::new(
            token,
            self.amount,
            DepositAuthorization::Permit2 {
                permit2_authorization: self.route.auth.clone(),
                eip2612_permit: None,
            },
        );
        verify_deposit(&self.ctx, &request).await
    }

    /// Deposits with the attached authorization. The submitter needs no signer of their own.
    pub async fn send(self) -> Result<DepositReceipt, DepositError> {
        let token = self.erc20_token()?;
        let deposited = Deposited {
            payer: self.route.auth.from,
            asset: token,
            amount: self.amount,
        };
        submit(
            &self.ctx,
            DepositRequest::new(
                token,
                self.amount,
                DepositAuthorization::Permit2 {
                    permit2_authorization: self.route.auth,
                    eip2612_permit: None,
                },
            ),
            TokenRoute::Permit2,
            deposited,
        )
        .await
    }
}

impl<S> DepositBuilder<S, route::SelfFunded> {
    /// Allows the 4Mica contract to spend the deposit's amount of its token, which a self-funded
    /// ERC-20 deposit needs before `send()`.
    pub async fn approve(&self) -> Result<TransactionReceipt, DepositError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let Asset::Erc20(token) = self.asset else {
            return Err(DepositError::InvalidParams(
                "native ETH needs no approval; its value rides with the transaction".into(),
            ));
        };
        let contract = self.ctx.get_erc20_write_contract(token).await?;
        let sent = contract
            .approve(self.ctx.contract_address(), self.amount)
            .send()
            .await;
        Ok(await_receipt(sent).await?)
    }

    /// Deposits with the payer's own transaction, reported in the same shape as a gasless one.
    ///
    /// For ERC-20 deposits the signer must have approved the contract first; see
    /// [`Self::approve`].
    pub async fn send(self) -> Result<DepositReceipt, DepositError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        send_self_funded(&self.ctx, self.asset, self.amount).await
    }
}

async fn send_eip3009<S>(
    ctx: &ClientCtx<S>,
    token: Address,
    amount: U256,
) -> Result<DepositReceipt, DepositError>
where
    S: Signer + Send + Sync,
{
    let authorization = sig::eip3009_authorization(ctx, token, amount).await?;
    let deposited = Deposited {
        payer: authorization.from,
        asset: token,
        amount,
    };
    submit(
        ctx,
        DepositRequest::new(
            token,
            amount,
            DepositAuthorization::Eip3009 { authorization },
        ),
        TokenRoute::Eip3009,
        deposited,
    )
    .await
}

async fn send_permit2<S>(
    ctx: &ClientCtx<S>,
    token: Address,
    amount: U256,
) -> Result<DepositReceipt, DepositError>
where
    S: Signer + Send + Sync,
{
    let authorization = sig::permit2_authorization(ctx, token, amount).await?;
    let deposited = Deposited {
        payer: authorization.from,
        asset: token,
        amount,
    };
    submit(
        ctx,
        DepositRequest::new(
            token,
            amount,
            DepositAuthorization::Permit2 {
                permit2_authorization: authorization,
                eip2612_permit: None,
            },
        ),
        TokenRoute::Permit2,
        deposited,
    )
    .await
}

async fn send_sponsored_permit2<S>(
    ctx: &ClientCtx<S>,
    token: Address,
    amount: U256,
) -> Result<DepositReceipt, DepositError>
where
    S: Signer + Send + Sync,
{
    // Try the plain route first: the payer may already have approved, in which case a permit is
    // pointless and only costs the submitter a no-op.
    let authorization = sig::permit2_authorization(ctx, token, amount).await?;
    let deposited = Deposited {
        payer: authorization.from,
        asset: token,
        amount,
    };
    let rejection = match submit(
        ctx,
        DepositRequest::new(
            token,
            amount,
            DepositAuthorization::Permit2 {
                permit2_authorization: authorization.clone(),
                eip2612_permit: None,
            },
        ),
        TokenRoute::Permit2,
        deposited,
    )
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
        // Either a different failure, or a token whose approval cannot be sponsored.
        return Err(rejection);
    };

    let permit = match sig::eip2612_permit(ctx, token, *nonce).await {
        Ok(permit) => permit,
        // The permit digest needs the token's domain separator; without one the approval
        // cannot be sponsored from here — the same dead end as a token with no EIP-2612
        // surface, and reported the same way: the nonce advertised that sponsoring *could*
        // work, which has just been disproven, so it is stripped.
        Err(DepositError::Client(ClientError::MissingTokenDomainSeparator { .. })) => {
            return Err(match rejection {
                DepositError::Permit2AllowanceRequired { message, .. } => {
                    DepositError::Permit2AllowanceRequired {
                        message,
                        eip2612_nonce: None,
                    }
                }
                other => other,
            });
        }
        Err(err) => return Err(err),
    };
    submit(
        ctx,
        DepositRequest::new(
            token,
            amount,
            DepositAuthorization::Permit2 {
                permit2_authorization: authorization,
                eip2612_permit: Some(permit.into()),
            },
        ),
        TokenRoute::SponsoredPermit2,
        deposited,
    )
    .await
}

/// The self-funded fallback, taken only after every gasless route was refused. Pre-checks the
/// ERC-20 allowance the fallback needs and the gasless routes never did, so a payer who has not
/// approved the contract is told exactly that instead of getting an opaque revert from inside the
/// token.
async fn fallback_to_self_funded<S>(
    ctx: &ClientCtx<S>,
    token: Address,
    amount: U256,
) -> Result<DepositReceipt, DepositError>
where
    S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
{
    let spender = ctx.contract_address();
    let allowance = ctx
        .get_erc20_contract(token)
        .await?
        .allowance(ctx.signer_address(), spender)
        .call()
        .await?;
    if allowance < amount {
        return Err(DepositError::Erc20AllowanceRequired {
            token,
            spender,
            allowance,
            needed: amount,
        });
    }
    send_self_funded(ctx, Asset::Erc20(token), amount).await
}

async fn send_self_funded<S>(
    ctx: &ClientCtx<S>,
    asset: Asset,
    amount: U256,
) -> Result<DepositReceipt, DepositError>
where
    S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
{
    let contract = ctx.get_write_contract().await?;
    let sent = match asset {
        Asset::Erc20(token) => contract.depositStablecoin(token, amount).send().await,
        Asset::Native => contract.deposit().value(amount).send().await,
    };
    let receipt = await_receipt(sent).await?;

    Ok(DepositReceipt {
        tx_hash: receipt.transaction_hash,
        route: TokenRoute::SelfFunded,
        account: ctx.signer_address(),
        asset: asset.address(),
        amount,
        network: None,
    })
}

/// `deposited` is what the receipt is checked against; it must describe the same deposit the
/// request does.
async fn submit<S>(
    ctx: &ClientCtx<S>,
    request: DepositRequest,
    route: TokenRoute,
    deposited: Deposited,
) -> Result<DepositReceipt, DepositError> {
    let response: DepositResponse = ctx.facilitator().post("deposit", &request).await?;
    response.into_receipt(route, deposited)
}

async fn verify_deposit<S>(
    ctx: &ClientCtx<S>,
    request: &DepositRequest,
) -> Result<(), DepositError> {
    let response: DepositVerifyResponse = ctx.facilitator().post("deposit/verify", request).await?;
    if response.is_valid {
        return Ok(());
    }
    Err(response.failure.into_error(response.invalid_reason))
}

/// What a deposit was asked to do, to hold the facilitator's answer against.
#[derive(Clone, Copy)]
struct Deposited {
    /// Whoever signed the authorization — the account the contract credits, which need not be this
    /// client's signer when the authorization was signed elsewhere.
    payer: Address,
    asset: Address,
    amount: U256,
}

/// Wire format for `POST /deposit` and `POST /deposit/verify`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DepositRequest {
    /// Omitted to use the facilitator's default network, which is the single-network case.
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    asset: String,
    amount: String,
    #[serde(flatten)]
    authorization: DepositAuthorization,
}

/// The authorization and its `assetTransferMethod` tag, flattened into the request as siblings.
#[derive(Debug, Serialize)]
#[serde(
    tag = "assetTransferMethod",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum DepositAuthorization {
    Eip3009 {
        authorization: ReceiveAuthorization,
    },
    Permit2 {
        permit2_authorization: Permit2Authorization,
        /// Sponsored approval, so the payer never transacts.
        #[serde(skip_serializing_if = "Option::is_none")]
        eip2612_permit: Option<Eip2612PermitRequest>,
    },
}

impl DepositRequest {
    fn new(asset: Address, amount: U256, authorization: DepositAuthorization) -> Self {
        Self {
            network: None,
            asset: asset.to_string(),
            amount: amount.to_string(),
            authorization,
        }
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

impl DepositResponse {
    /// `from`, `asset` and `amount` fall back to what was asked for: they are echoed for
    /// reconciliation, and a facilitator that omits them has not changed what the contract did. One
    /// that echoes a different deposit has, and the receipt is refused rather than made to describe
    /// it.
    fn into_receipt(
        self,
        route: TokenRoute,
        deposited: Deposited,
    ) -> Result<DepositReceipt, DepositError> {
        if !self.success {
            return Err(self.failure.into_error(self.error));
        }

        let tx_hash = self
            .tx_hash
            .as_deref()
            .and_then(|raw| raw.parse::<B256>().ok())
            .ok_or_else(|| {
                DepositError::OutcomeUnknown("facilitator reported success without a txHash".into())
            })?;

        Ok(DepositReceipt {
            tx_hash,
            route,
            account: confirm_echoed(
                "from",
                self.from.as_deref(),
                deposited.payer,
                DepositError::OutcomeUnknown,
            )?,
            asset: confirm_echoed(
                "asset",
                self.asset.as_deref(),
                deposited.asset,
                DepositError::OutcomeUnknown,
            )?,
            amount: confirm_echoed(
                "amount",
                self.amount.as_deref(),
                deposited.amount,
                DepositError::OutcomeUnknown,
            )?,
            network: self.network,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositVerifyResponse {
    is_valid: bool,
    invalid_reason: Option<String>,
    #[serde(flatten)]
    failure: FacilitatorFailure,
}
