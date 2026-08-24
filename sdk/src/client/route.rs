//! Type-state markers for the operation builders.
//!
//! A builder starts at [`Auto`] and pinning a route changes its type, so each route exposes
//! exactly the terminals that exist for it — a gasless pin offers `sign()`, a self-funded pin
//! does not, and an unpinned builder offers no `sign()` at all because the signature type is
//! unknowable before a route is chosen. Attaching an externally signed authorization moves a
//! pinned builder to [`Authorized`], where nothing is left to sign and the terminals are
//! `verify()` and `send()`.

/// No route pinned: the terminal picks the cheapest available and may fall back.
#[derive(Debug, Clone, Copy)]
pub struct Auto;

/// Strictly gasless: sponsored by the facilitator, never falling back to the caller's own
/// transaction. For token-moving operations this still spans every gasless scheme.
#[derive(Debug, Clone, Copy)]
pub struct Gasless;

/// The caller's own transaction, paying their own gas.
#[derive(Debug, Clone, Copy)]
pub struct SelfFunded;

/// EIP-3009 `receiveWithAuthorization` — gasless, for tokens that implement it (USDC and
/// similar).
#[derive(Debug, Clone, Copy)]
pub struct Eip3009;

/// Permit2 — gasless for any ERC-20, but only after the signer's one-time on-chain
/// `approve(PERMIT2, …)`.
#[derive(Debug, Clone, Copy)]
pub struct Permit2;

/// Permit2 with the missing approval signed (EIP-2612) rather than transacted, so the signer
/// never pays gas even without a prior approval.
#[derive(Debug, Clone, Copy)]
pub struct SponsoredPermit2;

/// A pinned route carrying an authorization signed elsewhere. The signature already fixes the
/// terms, so there is nothing left to sign — only `verify()` and `send()`.
#[derive(Debug, Clone)]
pub struct Authorized<A> {
    pub(crate) auth: A,
}
