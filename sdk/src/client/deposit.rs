//! Depositing collateral, over whichever route is cheapest for the payer.
//!
//! A deposit either costs the payer a transaction or it does not. Sponsored routes ([EIP-3009] and
//! [Permit2]) have the payer sign an authorization that someone else redeems and pays gas for;
//! the self-funded route is the payer's own transaction. Every route credits the signer, so the
//! choice only changes who pays — [`DepositReceipt::path`] reports which one ran.
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
        model::{Asset, DepositPath, DepositReceipt},
        sig::{self, Eip2612Permit},
    },
    contract::Core4Mica::{Permit2Authorization, ReceiveAuthorization},
    error::{ApproveErc20Error, DepositError},
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

    /// Whether a sponsored route is available at all. Callers that want to decide for themselves
    /// rather than let [`Self::send`] fall back can branch on this instead of on an error.
    pub fn is_gasless_available(&self) -> bool {
        self.ctx.facilitator().is_configured()
    }
}

impl<S> DepositClient<S>
where
    S: Signer + Send + Sync,
{
    /// Deposits `amount` of `token` gaslessly with an EIP-3009 authorization. The payer needs no
    /// native balance and makes no transaction.
    ///
    /// Requires a token implementing EIP-3009 (USDC and similar); for anything else see
    /// [`Self::send_permit2`].
    pub async fn send_eip3009(
        &self,
        token: Address,
        amount: U256,
    ) -> Result<DepositReceipt, DepositError> {
        let authorization = self.sign_eip3009(token, amount).await?;
        self.submit_eip3009(token, amount, authorization).await
    }

    /// Deposits `amount` of `token` gaslessly through Permit2.
    ///
    /// Works for any ERC-20, but **is not gasless on its own**: Permit2 needs a one-time on-chain
    /// `approve(PERMIT2, …)` from the payer, without which this fails with
    /// [`DepositError::Permit2AllowanceRequired`]. [`Self::send_sponsored_permit2`] covers that
    /// approval too, where the token allows it.
    pub async fn send_permit2(
        &self,
        token: Address,
        amount: U256,
    ) -> Result<DepositReceipt, DepositError> {
        let authorization = self.sign_permit2(token, amount).await?;
        self.submit_permit2(token, amount, authorization).await
    }

    /// Deposits through Permit2, signing the missing approval rather than transacting for it.
    ///
    /// Tries the plain Permit2 route first; if the allowance is missing *and* the token supports
    /// EIP-2612, signs a permit for it and retries so both are submitted together. Still costs the
    /// payer nothing.
    ///
    /// Fails with [`DepositError::Permit2AllowanceRequired`] for tokens with no EIP-2612 surface —
    /// their approval cannot be sponsored, so the payer must send it themselves.
    pub async fn send_sponsored_permit2(
        &self,
        token: Address,
        amount: U256,
    ) -> Result<DepositReceipt, DepositError> {
        // Try the plain route first: the payer may already have approved, in which case a permit is
        // pointless and only costs the submitter a no-op.
        let authorization = self.sign_permit2(token, amount).await?;
        let rejection = match self
            .submit_permit2(token, amount, authorization.clone())
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

        let permit = sig::eip2612_permit(&self.ctx, token, *nonce).await?;
        let deposited = Deposited {
            payer: authorization.from,
            asset: token,
            amount,
        };
        self.submit(
            DepositRequest::new(
                token,
                amount,
                DepositAuthorization::Permit2 {
                    permit2_authorization: authorization,
                    eip2612_permit: Some(permit.into()),
                },
            ),
            DepositPath::SponsoredPermit2,
            deposited,
        )
        .await
    }

    /// Signs an EIP-3009 authorization without submitting it, for callers that redeem it elsewhere.
    pub async fn sign_eip3009(
        &self,
        token: Address,
        amount: U256,
    ) -> Result<ReceiveAuthorization, DepositError> {
        sig::eip3009_authorization(&self.ctx, token, amount).await
    }

    /// Signs a Permit2 authorization without submitting it.
    pub async fn sign_permit2(
        &self,
        token: Address,
        amount: U256,
    ) -> Result<Permit2Authorization, DepositError> {
        sig::permit2_authorization(&self.ctx, token, amount).await
    }

    /// Deposits with an EIP-3009 authorization signed elsewhere — a hardware wallet, another
    /// process, or an earlier session. The authorization is self-contained, so it need not have
    /// been signed here.
    pub async fn submit_eip3009(
        &self,
        token: Address,
        amount: U256,
        authorization: ReceiveAuthorization,
    ) -> Result<DepositReceipt, DepositError> {
        let deposited = Deposited {
            payer: authorization.from,
            asset: token,
            amount,
        };
        self.submit(
            DepositRequest::new(
                token,
                amount,
                DepositAuthorization::Eip3009 { authorization },
            ),
            DepositPath::Eip3009,
            deposited,
        )
        .await
    }

    /// Deposits with a Permit2 authorization signed elsewhere.
    pub async fn submit_permit2(
        &self,
        token: Address,
        amount: U256,
        authorization: Permit2Authorization,
    ) -> Result<DepositReceipt, DepositError> {
        let deposited = Deposited {
            payer: authorization.from,
            asset: token,
            amount,
        };
        self.submit(
            DepositRequest::new(
                token,
                amount,
                DepositAuthorization::Permit2 {
                    permit2_authorization: authorization,
                    eip2612_permit: None,
                },
            ),
            DepositPath::Permit2,
            deposited,
        )
        .await
    }

    /// Preflight: runs every check a real submission would run, without spending anyone's gas.
    ///
    /// Worth doing before handing an authorization to a user-facing flow, since it tells a
    /// permanently unusable authorization apart from a transient failure.
    pub async fn verify_eip3009(
        &self,
        token: Address,
        amount: U256,
        authorization: ReceiveAuthorization,
    ) -> Result<(), DepositError> {
        let request = DepositRequest::new(
            token,
            amount,
            DepositAuthorization::Eip3009 { authorization },
        );
        let response: DepositVerifyResponse = self
            .ctx
            .facilitator()
            .post("deposit/verify", &request)
            .await?;
        if response.is_valid {
            return Ok(());
        }
        Err(response.failure.into_error(response.invalid_reason))
    }

    /// `deposited` is what the receipt is checked against; it must describe the same deposit the
    /// request does.
    async fn submit(
        &self,
        request: DepositRequest,
        path: DepositPath,
        deposited: Deposited,
    ) -> Result<DepositReceipt, DepositError> {
        let response: DepositResponse = self.ctx.facilitator().post("deposit", &request).await?;
        response.into_receipt(path, deposited)
    }
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

impl<S> DepositClient<S>
where
    S: TxSigner<Signature> + Signer + Send + Sync + Clone + 'static,
{
    /// Deposits `amount` of `asset`, taking the cheapest route available.
    ///
    /// Prefers routes someone else pays for, in order: EIP-3009, then Permit2 with the approval
    /// sponsored where the token allows it. Falls back to the payer's own transaction when no
    /// sponsored route applies — native ETH, no facilitator configured, or a token whose Permit2
    /// approval cannot be sponsored.
    ///
    /// Read [`DepositReceipt::path`] to see which route ran, or call [`Self::send_via`] to pin one.
    pub async fn send(&self, asset: Asset, amount: U256) -> Result<DepositReceipt, DepositError> {
        let Asset::Erc20(token) = asset else {
            return self.send_self_funded(asset, amount).await;
        };
        if !self.is_gasless_available() {
            return self.send_self_funded(asset, amount).await;
        }

        // EIP-3009 is the cheapest route, but nothing says up front whether a token implements it —
        // a domain separator only proves EIP-712, which EIP-2612 has too. So try it and read the
        // answer off the rejection, which costs no gas.
        let rejection = match self.send_eip3009(token, amount).await {
            Ok(receipt) => return Ok(receipt),
            Err(err) => err,
        };
        if !rejection.refuses_the_authorization() {
            return Err(rejection);
        }

        match self.send_sponsored_permit2(token, amount).await {
            // The approval cannot be sponsored, so gaslessness is off the table either way; paying
            // for the deposit directly is one transaction rather than an approval plus a deposit.
            Err(DepositError::Permit2AllowanceRequired { .. }) => {
                self.send_self_funded(asset, amount).await
            }
            outcome => outcome,
        }
    }

    /// Deposits over one specific route, failing rather than choosing another.
    ///
    /// For callers with a policy — and for tests, which need to exercise a route rather than
    /// whichever one happens to be cheapest.
    pub async fn send_via(
        &self,
        path: DepositPath,
        asset: Asset,
        amount: U256,
    ) -> Result<DepositReceipt, DepositError> {
        let token = match (path, asset) {
            (DepositPath::SelfFunded, asset) => return self.send_self_funded(asset, amount).await,
            (_, Asset::Erc20(token)) => token,
            (_, Asset::Native) => {
                return Err(DepositError::InvalidParams(
                    "native ETH has no gasless route; deposit it with DepositPath::SelfFunded"
                        .into(),
                ));
            }
        };

        match path {
            DepositPath::Eip3009 => self.send_eip3009(token, amount).await,
            DepositPath::Permit2 => self.send_permit2(token, amount).await,
            DepositPath::SponsoredPermit2 => self.send_sponsored_permit2(token, amount).await,
            DepositPath::SelfFunded => unreachable!("handled above"),
        }
    }

    /// Allows the 4Mica contract to spend `amount` of `token` on the signer's behalf.
    ///
    /// Only the self-funded route needs this; sponsored routes carry their own authorization.
    pub async fn approve_erc20(
        &self,
        token: Address,
        amount: U256,
    ) -> Result<TransactionReceipt, ApproveErc20Error> {
        let spender = self.ctx.contract_address();
        let contract = self.ctx.get_erc20_write_contract(token).await?;

        Ok(await_receipt(contract.approve(spender, amount).send().await).await?)
    }

    /// The payer's own transaction, reported in the same shape as a sponsored one.
    ///
    /// For ERC-20 deposits the signer must have approved the contract first; see
    /// [`Self::approve_erc20`].
    async fn send_self_funded(
        &self,
        asset: Asset,
        amount: U256,
    ) -> Result<DepositReceipt, DepositError> {
        let contract = self.ctx.get_write_contract().await?;
        let sent = match asset {
            Asset::Erc20(token) => contract.depositStablecoin(token, amount).send().await,
            Asset::Native => contract.deposit().value(amount).send().await,
        };
        let receipt = await_receipt(sent).await?;

        Ok(DepositReceipt {
            tx_hash: receipt.transaction_hash,
            path: DepositPath::SelfFunded,
            from: self.ctx.signer_address(),
            asset: asset.address(),
            amount,
            network: None,
        })
    }
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
        path: DepositPath,
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
            path,
            from: confirm_echoed(
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
