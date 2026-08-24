[![Crates.io](https://img.shields.io/crates/v/sdk-4mica.svg)](https://crates.io/crates/sdk-4mica)

# 4Mica Rust SDK

The official Rust SDK for interacting with the 4Mica payment network.

## Overview

4Mica is a payment network that enables cryptographically-enforced lines of credit for autonomous payments. The SDK provides:

- **User Client**: Deposit collateral, sign payments, pay net debits, and manage withdrawals in ETH or ERC20 tokens
- **Recipient Client**: Issue and verify payment guarantees, and claim net credits at cycle settlement
- **X402 Flow Helper**: Generate X-PAYMENT headers for 402-protected HTTP resources via an X402-compatible service
- **Validated Guarantees**: Build and verify guarantees gated on an external validator's approval

## Installation

Add the SDK to your `Cargo.toml`:

```toml
[dependencies]
sdk-4mica = "2.0.0-alpha.4"
```

Examples below that build claims by hand also use `rand` to generate a `req_id` nonce; add
`rand = "0.10"` if you do the same. `X402Flow` generates the nonce internally, so callers
using it need nothing extra.

## The Builder Grammar

Every operation follows the same three-step grammar:

1. **Entry — the intent.** What to do: `client.deposit.of(asset, amount)`,
   `client.withdraw.request(asset, amount)`, `client.settlement.pay(cycle_id)`. Entries do no
   IO; they return a builder.
2. **Modifiers — optional.** How to do it: a route pin (`.gasless()`, `.eip3009()`,
   `.permit2()`, `.permit2().sponsor_approval()`, `.self_funded()`) and, on a pinned route,
   `.authorization(auth)` to attach an authorization signed elsewhere. Each modifier changes
   the builder's type, so each state offers exactly the terminals that exist for it.
   Unpinned, the terminal takes the cheapest route available and may fall back.
3. **Terminal — the effect.** `.send()` executes; `.sign()` (gasless pins only) produces an
   authorization for someone else to submit; `.verify()` preflights without consuming the
   builder; `.approve()` (self-funded pins) sends the prerequisite ERC-20 approval;
   `.action()` (settlement) fetches the prepared call.

```rust
client.deposit.of(asset, amount).send().await?;                  // auto route
client.deposit.of(asset, amount).eip3009().sign().await?;        // offline authorization
client.deposit.of(asset, amount).eip3009().authorization(auth)   // signed elsewhere,
    .send().await?;                                              // submitted here
client.withdraw.request(asset, amount).gasless().send().await?;  // strictly gasless
client.settlement.claim(cycle_id).creditor(addr).send().await?;  // someone else's credit
```

Terminal signer bounds are per route: a gasless pin needs only an `alloy` `Signer`, while
self-funded terminals (and unpinned ones, which may fall back) also need `TxSigner<Signature>`.
A signing-only backend can therefore drive every gasless flow without transaction-submission
capability.

Every receipt reports which route actually ran — `receipt.route` — with `is_gasless()` telling
you whether the caller paid gas.

## Settlement Cycles

Payments settle in **cycles**, not in long-lived per-counterparty tabs.

A cycle is a fixed, wall-clock-aligned window scoped to a single asset. Every guarantee
core issues is bound to the cycle that is open at the time — you never name a cycle when
paying, and `req_id` is a random nonce you generate rather than a value you fetch. When
the window closes, all guarantees in it are netted multilaterally into one net debit or
net credit per participant, committed on-chain as a Merkle root, and settled.

A `cycle_id` is the text form `{asset_address}:{period_start}`, for example
`0x0000000000000000000000000000000000000000:1784210160`. You obtain one from the
guarantee claims (`claims.cycle_id`) or from your settlement tooling, then pass it to the
settlement builders below.

That gives each side one settlement call per cycle:

- Payers who owe: `settlement.pay(cycle_id).send()`
- Recipients who are owed: `settlement.claim(cycle_id).send()`

Both are single netted amounts covering every payment in the window, not one call per payment.

## Guarantee Versions

The SDK signs at its own `GUARANTEE_CLAIMS_VERSION`. Core accepts every version it can decode,
listed in `/core/public-params` as `supported_guarantee_versions`, so an older client keeps
working; a client newer than the core it talks to fails at construction with a clear message.

## Validated Guarantees

A guarantee that carries a `validation` requirement is payable only once the named validator
approves it, and is cancelled if that has not happened by the deadline. Core resolves only
validators it whitelists, listed in `/core/public-params` as `validators`.

- `payment.sign_request(...)` signs the claims a guarantee is issued against.

## Initialization and Configuration

The SDK requires a signer and can use sensible defaults for the rest:

- `signer` (**required**): Any `alloy::signers::Signer` (typically `PrivateKeySigner` from a hex private key). On-chain methods require a signer that also implements `TxSigner<Signature>`.
- `rpc_url` (optional): URL of the 4Mica RPC server. Defaults to `https://ethereum.sepolia.api.4mica.xyz/`; override for local development.
- `network` (optional): select a hosted network with the `Network` enum.
- `credentials` (optional): how API calls authenticate — `Credentials::Siwe` (the default: sign in with the configured signer), `Credentials::Bearer(token)`, or `Credentials::None`.

Hosted networks:

| `Network` variant  | CAIP-2            | Core API URL                              |
| ------------------ | ----------------- | ----------------------------------------- |
| `Base`             | `eip155:8453`     | `https://base.api.4mica.xyz/`             |
| `BaseSepolia`      | `eip155:84532`    | `https://base.sepolia.api.4mica.xyz/`     |
| `EthereumSepolia`  | `eip155:11155111` | `https://ethereum.sepolia.api.4mica.xyz/` |

`Network` also parses from the shorthand (`"base"`) or CAIP-2 id, which is how the
`4MICA_NETWORK` environment variable is read.

The following parameters are **optional** and will be automatically fetched from the server if not provided.

- `ethereum_http_rpc_url`: URL of the Ethereum JSON-RPC endpoint (optional)
- `contract_address`: Address of the deployed Core4Mica smart contract (optional)

> **Note:** You normally don't need to provide `ethereum_http_rpc_url` and `contract_address` as the SDK will fetch these from the server automatically. Only override these if you need to use different values than the server's defaults.
>
> The Ethereum `chain_id` is fetched from the core service and validated against the connected Ethereum provider automatically.

### Configuration Methods

#### 1. Using ClientBuilder

```rust
use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::{Client, Network};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = PrivateKeySigner::from_str("your_private_key")?;
    let client = Client::builder()
        .network(Network::Base)
        .signer(signer)
        .connect()
        .await?;
    Ok(())
}
```

`connect()` builds the config and reaches core for its public parameters, which is why
construction is fallible and async. `build()` is also available when you want the `Config`
itself; pass it to `Client::connect(config)` later.

#### 2. Using Environment Variables (`ClientBuilder::from_env`)

`ClientBuilder::from_env()` reads these keys:

- `4MICA_WALLET_PRIVATE_KEY` (required)
- `4MICA_NETWORK` (optional; shorthand or CAIP-2 id; takes precedence over `4MICA_RPC_URL`)
- `4MICA_RPC_URL` (optional; defaults to `https://ethereum.sepolia.api.4mica.xyz/`)
- `4MICA_ETHEREUM_HTTP_RPC_URL` (optional)
- `4MICA_CONTRACT_ADDRESS` (optional)
- `4MICA_FACILITATOR_URL` (optional)
- `4MICA_BEARER_TOKEN` (optional; selects bearer credentials in place of SIWE)
- `4MICA_AUTH_URL` (optional)
- `4MICA_AUTH_REFRESH_MARGIN_SECS` (optional)

Because these variable names start with a digit, use a `.env` file (or set process env programmatically) instead of `export` in a shell.

Example `.env`:

```ini
4MICA_WALLET_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
4MICA_NETWORK=base
4MICA_ETHEREUM_HTTP_RPC_URL=http://localhost:8545
4MICA_CONTRACT_ADDRESS=0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0
```

Then in your code:

```rust
use sdk_4mica::ClientBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let client = ClientBuilder::from_env()?.connect().await?;
    Ok(())
}
```

Add `dotenv = "0.15"` to your app dependencies if you load `.env` files this way.

## Usage

`Client` groups its methods by what you are doing:

- `client.deposit`: deposit collateral, gasless or self-funded
- `client.withdraw`: request, cancel and finalize withdrawals
- `client.payment`: sign payment requests, issue and verify guarantees
- `client.settlement`: pay a net debit or claim a net credit for a cycle
- `client.account`: read your own balances and positions
- `client.tokens`: supported-token metadata and ERC20 approvals

Plus `X402Flow`, a standalone helper that builds X-PAYMENT headers for X402-protected HTTP
endpoints.

### X402 flow (HTTP 402)

The X402 helper turns the `paymentRequirements` emitted by a `402 Payment Required` response into an X-PAYMENT header (and optional `/settle` call) that the facilitator will accept. The examples in `https://github.com/4mica-Network/x402-4mica/examples` model the expected flow: the client speaks to the resource server, and the resource server talks to the facilitator for `/verify` and `/settle`.

Signing is entirely local. `X402Flow` generates a random `req_id` nonce itself and makes no
network call before signing, so no endpoint needs to be advertised for it.

#### What the SDK expects from `paymentRequirements`

`sdk-4mica` accepts the canonical X402 JSON (camelCase). At minimum you need:

- `scheme` and `network`: `scheme` must contain `4mica` (e.g. `4mica-credit`)
- `asset`, `amount` (v2) or `maxAmountRequired` (v1), and `payTo`

V1 requires no `extra` at all. V2 requires `extra` carrying the validation policy fields
(`validationRegistryAddress`, `validationChainId`, `validatorAddress`, `validatorAgentId`,
`minValidationScore`, `jobHash`, and optionally `requiredValidationTag`).

#### End-to-end client flow

##### X402 Version 1

Version 1 returns payment requirements in the JSON response body:

- GET the protected endpoint; parse the JSON body to get the response with `accepts` array.
- Select a payment option from `accepts` array.
- Call `X402Flow::sign_payment` to get the base64 `X-PAYMENT` header.
- Retry the protected endpoint with `X-PAYMENT`; the resource server will call the facilitator `/verify` and `/settle`.

```rust
use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::{Client, X402Flow};
use sdk_4mica::x402::PaymentRequirements;
use serde::Deserialize;
use std::str::FromStr;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResourceResponse {
    x402_version: u64,
    accepts: Vec<PaymentRequirements>,
    error: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payer_signer = PrivateKeySigner::from_str(&std::env::var("PAYER_KEY")?)?;
    let user_address = payer_signer.address().to_string();
    let payer = Client::builder().signer(payer_signer).connect().await?;

    // 1) GET the protected endpoint and parse JSON body
    let response = reqwest::get("https://resource-url/resource").await?;
    let body: ResourceResponse = response.json().await?;

    // 2) Select a payment option (first one for simplicity)
    let payment_requirements = body.accepts
        .first()
        .ok_or("No payment options available")?
        .clone();

    // 3) Build the X-PAYMENT header with the SDK
    let flow = X402Flow::new(payer)?;
    let signed = flow
        .sign_payment(payment_requirements, user_address)
        .await?;
    let x_payment_header = signed.header;

    // 4) Call the protected resource with the header
    let _paid = reqwest::Client::new()
        .get("https://resource-url/resource")
        .header("X-PAYMENT", &x_payment_header)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}
```

##### X402 Version 2

Version 2 uses the `PAYMENT-REQUIRED` header (base64-encoded) instead of a JSON response body:

- GET the protected endpoint; extract and decode the `payment-required` header to get `X402PaymentRequiredV2`.
- Select a payment option from `accepts` array.
- Call `X402Flow::sign_payment_v2` to get the base64 `PAYMENT-SIGNATURE` header.
- Retry the protected endpoint with `PAYMENT-SIGNATURE`; the resource server will call the facilitator `/verify` and `/settle`.

```rust
use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::{Client, X402Flow};
use sdk_4mica::x402::{X402PaymentRequiredV2, PaymentRequirementsV2};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payer_signer = PrivateKeySigner::from_str(&std::env::var("PAYER_KEY")?)?;
    let user_address = payer_signer.address().to_string();
    let payer = Client::builder().signer(payer_signer).connect().await?;

    // 1) GET the protected endpoint and extract payment-required header
    let response = reqwest::get("https://resource-url/resource").await?;
    let payment_header = response.headers()
        .get("payment-required")
        .ok_or("Missing payment-required header")?
        .to_str()?;

    // 2) Decode the header
    let decoded = BASE64.decode(payment_header)?;
    let payment_required: X402PaymentRequiredV2 = serde_json::from_slice(&decoded)?;

    // 3) Select a payment option (first one for simplicity)
    let accepted = payment_required.accepts
        .first()
        .ok_or("No payment options available")?
        .clone();

    // 4) Build the PAYMENT-SIGNATURE header with the SDK
    let flow = X402Flow::new(payer)?;
    let signed = flow
        .sign_payment_v2(payment_required, accepted, user_address)
        .await?;
    let payment_signature_header = signed.header;

    // 5) Call the protected resource with the header
    let _paid = reqwest::Client::new()
        .get("https://resource-url/resource")
        .header("PAYMENT-SIGNATURE", &payment_signature_header)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}
```

#### Resource server / facilitator side

If your resource server proxies to the facilitator (the pattern used in `examples/server/mock_paid_api.py`), you can reuse the SDK to settle after verifying:

```rust
use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::{Client, X402Flow, X402SignedPayment};
use sdk_4mica::x402::PaymentRequirements;
use std::str::FromStr;

async fn settle(
    facilitator_url: &str,
    payment_requirements: PaymentRequirements,
    payment: X402SignedPayment,
) -> Result<(), Box<dyn std::error::Error>> {
    let resource_signer = PrivateKeySigner::from_str(&std::env::var("RESOURCE_SIGNER_KEY")?)?;
    let core = Client::builder().signer(resource_signer).connect().await?;
    let flow = X402Flow::new(core)?;

    // POST /settle to the facilitator; returns the facilitator JSON body on success
    let settled = flow
        .settle_payment(payment, payment_requirements, facilitator_url)
        .await?;
    println!("settlement result: {}", settled.settlement);
    Ok(())
}
```

Notes:

- `sign_payment` and `sign_payment_v2` sign the x402 v1 and v2 flows respectively; both use EIP-712 and error if the scheme is not 4mica.
- `settle_payment` only hits `/settle`; resource servers should still call the facilitator `/verify` first when enforcing access (see the Python example for the end-to-end pattern).

### API Methods Summary

#### `client.deposit`

Entry: `of(asset: Asset, amount: U256)` returns a `DepositBuilder`.

- `of(…).send()`: Deposit over the cheapest route available, falling back to a self-funded transaction
- `of(…).gasless().send()`: Any gasless scheme — EIP-3009 first, then Permit2 with the approval sponsored — never falling back to self-funded
- `of(…).eip3009().send()` / `.sign()`: The EIP-3009 route only; `sign()` produces a `ReceiveAuthorization` for someone else to submit
- `of(…).permit2().send()` / `.sign()`: The Permit2 route only, given an existing Permit2 approval; `sign()` produces a `Permit2Authorization`
- `of(…).permit2().sponsor_approval().send()`: Permit2 with the missing approval signed (EIP-2612) rather than transacted. No `sign()` on this pin — the permit needs the payer's current EIP-2612 nonce, which only arrives with the facilitator's rejection
- `of(…).self_funded().send()`: The payer's own transaction
- `of(…).self_funded().approve()`: The ERC-20 approval a self-funded deposit needs — the builder knows the token, spender and amount
- `of(…).eip3009().authorization(auth)` / `of(…).permit2().authorization(auth)`: Attach an authorization signed elsewhere; the authorized builder offers `send()` and a non-consuming `verify()` preflight
- `is_gasless_available() -> bool`: Whether a facilitator is configured at all

All deposit terminals return `Result<DepositReceipt, DepositError>`; `receipt.route` is a
`TokenRoute` (`Eip3009` / `Permit2` / `SponsoredPermit2` / `SelfFunded`).

#### `client.withdraw`

Entries: `request(asset, amount)`, `cancel(asset)`, `finalize(asset)`.

- `request(…).send()` / `cancel(…).send()` / `finalize(…).send()`: Gasless where possible, falling back to the user's own transaction
- `….gasless().send()`: The gasless route only, failing rather than falling back. Works for ETH too — the contract verifies the signature itself
- `….self_funded().send()`: The user's own transaction only
- `request(…).gasless().sign()` / `cancel(…).gasless().sign()`: Sign an authorization for someone else to submit. Finalize has no `sign()` — `finalizeWithdrawalFor` is permissionless because it pays the user
- `request(…).gasless().authorization(auth)` / `cancel(…).gasless().authorization(auth)`: Attach an authorization signed elsewhere; the authorized builder offers `send()` and a non-consuming `verify()` preflight
- `finalize(…).verify()`: Preflight a finalization without spending gas — the one step that can be refused purely by the clock
- `is_gasless_available() -> bool`: Whether a facilitator is configured at all

All withdraw terminals return `Result<WithdrawReceipt, WithdrawError>`; `receipt.route` is a
`Route` (`Gasless` / `SelfFunded`).

#### `client.payment`

- `sign_request(claims: PaymentGuaranteeRequestClaims, scheme: SigningScheme) -> Result<PaymentSignature, PaymentError>`: Sign a payment as the payer
- `issue_guarantee(claims, signature, scheme) -> Result<BLSCert, PaymentError>`: Redeem a payer's signature for a guarantee, as the recipient
- `verify_guarantee(cert: &BLSCert) -> Result<PaymentGuaranteeClaims, PaymentError>`: Verify a certificate and extract its claims
- `list_received() -> Result<Vec<RecipientPaymentInfo>, PaymentError>`: Payments guaranteed to the signer as a recipient
- `guarantee_domain() -> &[u8; 32]`: The EIP-712 domain guarantees are signed under

#### `client.settlement`

Entries: `pay(cycle_id)`, `claim(cycle_id)`.

- `pay(…).send()`: Pay the caller's committed net debit, gaslessly via the facilitator where possible, falling back to the caller's own transaction
- `pay(…).gasless().send()`: Any gasless scheme, no fallback
- `pay(…).eip3009().send()` / `pay(…).permit2().send()` / `pay(…).permit2().sponsor_approval().send()`: One specific scheme
- `pay(…).eip3009().sign()` / `pay(…).permit2().sign()`: Sign the debit authorization for someone else to submit — the terms come from core, the nonce is the cycle id
- `pay(…).eip3009().authorization(auth)` / `pay(…).permit2().authorization(auth)`: Attach a debit authorization signed elsewhere; the authorized builder offers `send()` and a non-consuming `verify()` preflight
- `pay(…).self_funded().send()`: The caller's own transaction
- `pay(…).self_funded().approve()`: Approve the settling ClearingHouse for exactly the committed debit — token, spender and amount all come from the cycle's prepared action
- `pay(…).action()`: The prepared `payNetDebit` call (amount, proof, contract)
- `claim(…).send()`: Claim the caller's committed net credit, gaslessly where possible
- `claim(…).creditor(addr)`: Address someone else's credit — the payout still goes to the address the committed leaf names
- `claim(…).gasless().send()` / `claim(…).self_funded().send()`: Pin the route
- `claim(…).verify()`: Preflight the claim without spending gas
- `claim(…).action()`: The prepared claim call
- `is_gasless_available() -> bool`: Whether a facilitator is configured at all

Pay terminals return `Result<PayReceipt, SettlementError>` (`receipt.route` is a `TokenRoute`);
claim terminals return `Result<ClaimReceipt, SettlementError>` (`receipt.route` is a `Route`).

A claim needs no signature from the creditor: the on-chain payout goes to the address the committed Merkle leaf names, for the amount it fixes, so a submitter can neither redirect nor inflate it. That is also what makes it sponsorable — with a `facilitator_url` configured, `claim(…).send()` POSTs the cycle and creditor to the facilitator's `/clearing/claim`, whose relayer resolves the terms from core and pays the gas, and falls back to the caller's own transaction when the facilitator would not sponsor (never when its refusal names the claim itself — that would revert self-funded too). `ClaimReceipt::route` reports which route ran. Every route ends in the contract's single claim entrypoint, `claimNetCreditFor` — a self-claim just names the caller's own address.

A payment does need the debtor's signature — it pulls money out of their wallet. For an ERC-20 cycle with a `facilitator_url` configured, `pay(…).send()` signs an EIP-3009 `receiveWithAuthorization` binding the ClearingHouse as receiver, the committed amount, and the cycle id as nonce, and POSTs it to the facilitator's `/clearing/pay`; the relayer submits `payNetDebitWithAuthorization` and pays the gas, so the debtor needs no native balance and no allowance. The same fallback discipline applies, and `PayReceipt::route` reports the route. Native-asset cycles cannot be pulled by signature and always settle self-funded (`payNetDebit`, with the debit riding as transaction value; ERC-20 self-funded needs `pay(…).self_funded().approve()` first).

#### `client.account`

- `assets() -> Result<Vec<AssetPosition>, AccountError>`: Every asset the signer holds collateral in
- `principal_balance(asset: Asset) -> Result<U256, AccountError>`: Collateral deposited in an asset, before yield
- `withdrawable_balance(asset: Asset) -> Result<U256, AccountError>`: What could be withdrawn right now
- `stablecoin_position(token: Address) -> Result<StablecoinPosition, AccountError>`: Full yield-bearing stablecoin position
- `asset_balance(asset: Asset) -> Result<Option<AssetBalanceInfo>, AccountError>`: Balance as guarantees are accounted against it, including the locked portion

#### `client.tokens`

- `supported() -> Result<SupportedTokensResponse, TokenError>`: Assets that can be deposited, with the metadata needed to sign for them
- `approve(token: Address, amount: U256) -> Result<TransactionReceipt, TokenError>`: Approve the 4Mica contract to spend an ERC20, needed only for self-funded deposits

#### `Client`

- `builder() -> ClientBuilder`: Start configuring a client; finish with `connect()`
- `connect(config: Config) -> Result<Client, ClientError>`: Connect with an already-built config
- `signer_address() -> Address`: The address this client signs as
- `login() -> Result<AuthTokens, AuthError>`: Sign in with the configured signer

> **Note:** `BLSCert` exposes typed claims and signatures. Use `cert.claims().to_hex()` or `cert.signature().to_hex()` when you need hex strings.

> **Note:** Each sub-client returns its own error type — see [Error Handling](#error-handling). The umbrella `sdk_4mica::Error` implements `From` for all of them, for callers that funnel everything into one `?`.

### Collateral

#### Approve ERC20 Token (self-funded deposits only)

Gasless deposits carry their own authorization; only a self-funded ERC20 deposit needs an
allowance first. The deposit builder can grant it itself —
`client.deposit.of(asset, amount).self_funded().approve()` — or use the token utility
directly:

```rust
use sdk_4mica::{Address, U256};

// Approve the 4Mica contract to spend 1000 USDC on your behalf
let token_address: Address = "0x1234567890123456789012345678901234567890".parse()?;
let amount = U256::from(1000_000_000u128); // 1000 USDC (6 decimals)

match client.tokens.approve(token_address, amount).await {
    Ok(receipt) => {
        println!("ERC20 approval successful: {:?}", receipt.transaction_hash);
    }
    Err(e) => {
        eprintln!("ERC20 approval failed: {}", e);
    }
}
```

#### Deposit Collateral

The unpinned `send()` takes the cheapest route the asset and configuration allow, and reports
which one ran.

```rust
use sdk_4mica::{Address, Asset, U256};

// Deposit 1 ETH as collateral. Native ETH is always self-funded.
let amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH in wei
match client.deposit.of(Asset::Native, amount).send().await {
    Ok(receipt) => {
        println!("Deposit successful: {:?}", receipt.tx_hash);
    }
    Err(e) => {
        eprintln!("Deposit failed: {}", e);
    }
}

// Or deposit 1000 USDC, gaslessly where the token and facilitator allow it.
let token_address: Address = "0x1234567890123456789012345678901234567890".parse()?;
let amount = U256::from(1000_000_000u128);
let receipt = client.deposit.of(Asset::Erc20(token_address), amount).send().await?;
println!("USDC deposit successful over {:?}: {:?}", receipt.route, receipt.tx_hash);

// To rule out ever paying gas yourself, pin the route instead of letting it fall back.
let receipt = client
    .deposit
    .of(Asset::Erc20(token_address), amount)
    .eip3009()
    .send()
    .await?;
```

#### Read Your Positions

```rust
// Every asset you hold collateral in
let positions = client.account.assets().await?;
for position in positions {
    println!("Asset: {}", position.asset);
    println!("Collateral: {}", position.collateral);
    println!("Withdrawal request amount: {}", position.withdrawal_request_amount);
    println!("Withdrawal request timestamp: {}", position.withdrawal_request_timestamp);
    println!("---");
}
```

### Withdrawals

#### Request Withdrawal

```rust
use sdk_4mica::{Address, Asset, U256};

// Request to withdraw 0.5 ETH
let amount = U256::from(500_000_000_000_000_000u128);
let receipt = client.withdraw.request(Asset::Native, amount).send().await?;
println!("Withdrawal requested: {:?}", receipt.tx_hash);

// Or request to withdraw 500 USDC
let token_address: Address = "0x1234567890123456789012345678901234567890".parse()?;
let amount_usdc = U256::from(500_000_000u128);
let receipt = client
    .withdraw
    .request(Asset::Erc20(token_address), amount_usdc)
    .send()
    .await?;
println!("USDC withdrawal requested: {:?}", receipt.tx_hash);

// Whoever paid for it is on the receipt.
if !receipt.route.is_gasless() {
    println!("no facilitator sponsored this one");
}
```

#### Cancel Withdrawal

```rust
// Cancel a pending ETH withdrawal request
let receipt = client.withdraw.cancel(Asset::Native).send().await?;
println!("Withdrawal cancelled: {:?}", receipt.tx_hash);

// Cancel a pending USDC withdrawal request
let receipt = client.withdraw.cancel(Asset::Erc20(token_address)).send().await?;
println!("USDC withdrawal cancelled: {:?}", receipt.tx_hash);
```

#### Finalize Withdrawal

```rust
// Finalize ETH withdrawal (after the waiting period)
let receipt = client.withdraw.finalize(Asset::Native).send().await?;
println!("Withdrawal finalized: {:?}", receipt.tx_hash);

// Finalize USDC withdrawal (after the waiting period)
let receipt = client.withdraw.finalize(Asset::Erc20(token_address)).send().await?;
println!("USDC withdrawal finalized: {:?}", receipt.tx_hash);
```

### Payment Guarantees

#### Sign a Payment

```rust
use sdk_4mica::{PaymentGuaranteeRequestClaims, SigningScheme, U256};

// Create payment claims for ETH payment.
// req_id is a random per-request nonce (see the note below); the guarantee is
// bound to the active settlement cycle for you.
let req_id = U256::from_be_bytes(rand::random::<[u8; 32]>());

let claims = PaymentGuaranteeRequestClaims::new(
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(), // user_address
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(), // recipient_address
    req_id,                                                     // req_id
    U256::from(1_000_000_000_000_000_000u128),                  // amount (1 ETH)
    1704067200,                                                 // timestamp
    None,                                                       // erc20_token (None for ETH)
);

// Sign using EIP-712 (recommended)
match client.payment.sign_request(claims.clone(), SigningScheme::Eip712).await {
    Ok(payment_sig) => {
        println!("Signature: {}", payment_sig.signature);
        println!("Scheme: {:?}", payment_sig.scheme);
    }
    Err(e) => {
        eprintln!("Signing failed: {}", e);
    }
}

// Or use EIP-191 (personal_sign)
let payment_sig = client.payment.sign_request(claims, SigningScheme::Eip191).await?;

// For ERC20 token payment, pass the token address
let usdc_token = "0x1234567890123456789012345678901234567890".to_string();
let claims_usdc = PaymentGuaranteeRequestClaims::new(
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
    U256::from_be_bytes(rand::random::<[u8; 32]>()),
    U256::from(1000_000_000u128), // 1000 USDC
    1704067200,
    Some(usdc_token),
);
let payment_sig_usdc = client.payment.sign_request(claims_usdc, SigningScheme::Eip712).await?;
```

> **Note on `req_id`:** `req_id` is a per-request nonce, **not** a sequential counter. Use a freshly generated random `U256` for each guarantee request. Replay protection comes from two independent checks: a request is bound to one settlement cycle via its signed `timestamp` (a request whose timestamp predates the active cycle is rejected as stale), and within a cycle the `(req_id, ...)` digest must be unique, so reusing a `req_id` for an otherwise-identical request is rejected as a duplicate. Random `req_id`s avoid accidental collisions; they do not need to increase or follow any order. `X402Flow` does this for you.

#### Issue Payment Guarantee

```rust
use sdk_4mica::{PaymentGuaranteeRequestClaims, SigningScheme, U256};

// First, the user signs the payment (see User Client example above)
let claims = PaymentGuaranteeRequestClaims::new(
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
    U256::from_be_bytes(rand::random::<[u8; 32]>()), // req_id
    U256::from(1_000_000_000_000_000_000u128),       // 1 ETH
    1704067200,
    None, // None for ETH
);

let payment_sig = client.payment.sign_request(claims.clone(), SigningScheme::Eip712).await?;

let bls_cert = client.payment.issue_guarantee(
    claims,
    payment_sig.signature,
    payment_sig.scheme,
).await?;

// The issued claims name the cycle the guarantee was bound to.
let issued = client.payment.verify_guarantee(&bls_cert)?;
println!("Guarantee bound to cycle: {:#x}", issued.cycle_id);
```

### Settlement

#### Pay a Net Debit

Once a cycle's netting is committed on-chain, a payer who ended the window owing money
makes a single call covering every payment they made in it.

```rust
let cycle_id = "0x0000000000000000000000000000000000000000:1784210160".to_string();

// For self-funded ERC20 settlement, approve the settling contract first. The builder
// resolves the token, the ClearingHouse and the exact committed debit from the cycle.
let pay = client.settlement.pay(cycle_id).self_funded();
pay.approve().await?;

// Native-asset debits carry their value with the call; no approval needed.
let receipt = pay.send().await?;
println!("Net debit paid via {:?}: {:?}", receipt.route, receipt.tx_hash);
```

#### Claim a Net Credit

Once a cycle's netting is committed on-chain, each net creditor makes a single call to
collect everything owed to them for that cycle.

```rust
let cycle_id = "0x0000000000000000000000000000000000000000:1784210160".to_string();

// Inspect the prepared call first (amount, Merkle proof, ClearingHouse address)
let action = client.settlement.claim(cycle_id.clone()).action().await?;
println!("claiming {} via {}", action.amount, action.contract_address);

// Or just execute it. With a facilitator configured this goes out gaslessly through its
// relayer; otherwise it is the caller's own transaction. `route` reports which one ran.
let receipt = client.settlement.claim(cycle_id).send().await?;
println!("Net credit claimed via {:?}: {:?}", receipt.route, receipt.tx_hash);
```

A third party can also claim on a creditor's behalf, paying the gas so the creditor needs no
native balance. The payout still goes to the creditor — the committed leaf fixes both the payee
and the amount:

```rust
let receipt = client
    .settlement
    .claim(cycle_id)
    .creditor(creditor_address)
    .send()
    .await?;
println!("Sponsored claim: {:?}", receipt.tx_hash);
```

## Complete Example

Here's a complete example showing a payment flow with ETH:

```rust
use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::{Asset, Client, PaymentGuaranteeRequestClaims, SigningScheme, U256};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup clients (user and recipient each have their own)
    let user_signer = PrivateKeySigner::from_str("user_private_key")?;
    let user_client = Client::builder().signer(user_signer).connect().await?;

    let recipient_signer = PrivateKeySigner::from_str("recipient_private_key")?;
    let recipient_client = Client::builder().signer(recipient_signer).connect().await?;

    // 2. User deposits collateral
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let receipt = user_client
        .deposit
        .of(Asset::Native, deposit_amount)
        .send()
        .await?;
    println!("Deposited collateral: {:?}", receipt.tx_hash);

    // 3. User signs a payment. No setup call is needed first: the guarantee is bound
    //    to whichever settlement cycle is open.
    let user_address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string();
    let recipient_address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string();
    let claims = PaymentGuaranteeRequestClaims::new(
        user_address.clone(),
        recipient_address.clone(),
        U256::from_be_bytes(rand::random::<[u8; 32]>()), // req_id nonce
        U256::from(1_000_000_000_000_000_000u128),       // 1 ETH
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        None, // None for ETH
    );
    let payment_sig = user_client.payment.sign_request(claims.clone(), SigningScheme::Eip712).await?;
    println!("Payment signed");

    // 4. Recipient issues the guarantee
    let bls_cert = recipient_client
        .payment
        .issue_guarantee(claims, payment_sig.signature, payment_sig.scheme)
        .await?;
    let issued = recipient_client.payment.verify_guarantee(&bls_cert)?;
    println!("Guarantee issued in cycle {:#x}", issued.cycle_id);

    // 5. Later, once the cycle is netted and committed on-chain, each side makes
    //    one settlement call covering every payment in that window:
    //      user_client.settlement.pay(cycle_id).send().await?;
    //      recipient_client.settlement.claim(cycle_id).send().await?;

    Ok(())
}
```

### Complete Example with ERC20 Token (USDC)

Here's a complete example showing a payment flow with an ERC20 token:

```rust
use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::{Address, Asset, Client, PaymentGuaranteeRequestClaims, SigningScheme, U256};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let user_signer = PrivateKeySigner::from_str("user_private_key")?;
    let user_client = Client::builder().signer(user_signer).connect().await?;

    let recipient_signer = PrivateKeySigner::from_str("recipient_private_key")?;
    let recipient_client = Client::builder().signer(recipient_signer).connect().await?;

    let usdc_token = "0x1234567890123456789012345678901234567890".to_string();
    let usdc_address: Address = usdc_token.parse()?;

    // 1. User deposits USDC collateral. The unpinned route prefers a gasless scheme,
    //    which needs no allowance; it only falls back to a self-funded transaction,
    //    and only that fallback needs the approval below.
    let deposit_amount = U256::from(5000_000_000u128); // 5,000 USDC
    if !user_client.deposit.is_gasless_available() {
        let approval_amount = U256::from(10000_000_000u128); // 10,000 USDC
        user_client.tokens.approve(usdc_address, approval_amount).await?;
    }
    let receipt = user_client
        .deposit
        .of(Asset::Erc20(usdc_address), deposit_amount)
        .send()
        .await?;
    println!("Deposited USDC collateral over {:?}", receipt.route);

    // 3. User signs a USDC payment
    let user_address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string();
    let recipient_address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string();
    let claims = PaymentGuaranteeRequestClaims::new(
        user_address.clone(),
        recipient_address.clone(),
        U256::from_be_bytes(rand::random::<[u8; 32]>()), // req_id nonce
        U256::from(1000_000_000u128),                    // 1,000 USDC
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        Some(usdc_token.clone()),
    );
    let payment_sig = user_client.payment.sign_request(claims.clone(), SigningScheme::Eip712).await?;
    println!("Payment signed");

    // 4. Recipient issues the guarantee
    let bls_cert = recipient_client
        .payment
        .issue_guarantee(claims, payment_sig.signature, payment_sig.scheme)
        .await?;
    let issued = recipient_client.payment.verify_guarantee(&bls_cert)?;
    println!("Guarantee issued in cycle {:#x}", issued.cycle_id);

    // 5. At cycle settlement the payer approves the ClearingHouse for the ERC20
    //    net debit (self-funded only), then pays it:
    //      let pay = user_client.settlement.pay(cycle_id).self_funded();
    //      pay.approve().await?;
    //      pay.send().await?;

    Ok(())
}
```

## Error Handling

Each sub-client returns one error enum, with typed variants for the states callers branch on
and `#[from]` conversions for the shared infrastructure failures. The umbrella
`sdk_4mica::Error` implements `From` for every one of them.

### Importing

```rust
use sdk_4mica::Error; // the umbrella
use sdk_4mica::error::{
    AccountError, AuthError, ClientError, ConfigError, DepositError, PaymentError,
    SettlementError, SponsorshipError, TokenError, WithdrawError, X402Error,
};
```

### Error Types

#### Configuration Errors

**`ConfigError`**

- `InvalidValue(String)`: Invalid configuration value
- `Missing(String)`: Required configuration parameter is missing

#### Client Errors

**`ClientError`**

- `Rpc(String)`: RPC connection error
- `Provider(String)`: Provider initialization error
- `Initialization(String)`: Client initialization error
- `ChainRpcUnavailable`: No Ethereum endpoint is available for a path that needs one
- `MissingTokenDomainSeparator { token }`: Core publishes no EIP-712 domain for the token, so no EIP-3009/EIP-2612 digest can be built for it

#### Sponsorship Errors

**`SponsorshipError`** — shared by every gasless route:

- `NotConfigured`: No facilitator URL was configured
- `Rejected { code, message, retryable }`: The facilitator refused; `code` is carried verbatim
- `InvalidParams(String)` / `Transport(String)` / `OutcomeUnknown(String)`

#### Deposit Errors

**`DepositError`**

- `InvalidParams(String)`, `AmountZero`, `UnsupportedAsset(Address)`, `AaveNotConfigured`
- `ValueMismatch { expected, actual }`: Fee-on-transfer token delivered less than signed for
- `ZeroCollateralCredit { asset, amount }`: Amount too small to mint any scaled collateral
- `AuthorizationExpired { expires_at, now }`: The authorization's deadline already elapsed
- `Permit2AllowanceRequired { message, eip2612_nonce }`: Permit2 needs a one-time approval; when `eip2612_nonce` is present, `permit2().sponsor_approval()` can sign it instead
- `Erc20AllowanceRequired { token, spender, allowance, needed }`: The self-funded fallback needs an allowance; grant it with `client.tokens.approve`
- `FacilitatorNotConfigured` / `Facilitator { code, message, retryable }`
- `Client(ClientError)`, `UnknownRevert { … }`, `Transport(String)`, `OutcomeUnknown(String)`

#### Withdrawal Errors

**`WithdrawError`** — one enum for request, cancel and finalize:

- `InvalidParams(String)`, `AmountZero`, `InsufficientAvailable`, `NoWithdrawalRequested`,
  `GracePeriodNotElapsed`, `TransferFailed`, `UnsupportedAsset(Address)`,
  `StablecoinWithdrawShortfall { … }`
- `Sponsorship(SponsorshipError)`, `Client(ClientError)`, `UnknownRevert { … }`, `Transport(String)`

#### Cycle Settlement Errors

**`SettlementError`**

- `InvalidParams(String)`: Invalid parameters in the prepared clearing action
- `Permit2AllowanceRequired { message, eip2612_nonce }` / `Erc20AllowanceRequired { … }`: As for deposits, but for the debit; the self-funded allowance is granted with `pay(…).self_funded().approve()`
- `RevertedOnChain { tx_hash }`: Mined and reverted, so gas was spent
- `Rpc(rpc::ApiClientError)`, `Auth(AuthError)`, `Sponsorship(SponsorshipError)`, `Client(ClientError)`, `UnknownRevert { … }`, `Transport(String)`

#### Payment Guarantee Errors

**`PaymentError`** — signing, issuing, verifying and listing:

- `AddressMismatch { signer, claims }`, `InvalidUserAddress`, `InvalidRecipientAddress`, `SigningFailed(String)`
- `InvalidCertificate(anyhow::Error)`, `CertificateMismatch`, `GuaranteeDomainMismatch`, `UnsupportedGuaranteeVersion(u64)`
- `InvalidParams(String)`, `Decode(String)`, `Rpc(rpc::ApiClientError)`, `Auth(AuthError)`

#### Account Errors

**`AccountError`**

- `UnsupportedAsset(Address)`, `AaveNotConfigured`, `Decode(String)`
- `Rpc(rpc::ApiClientError)`, `Auth(AuthError)`, `Client(ClientError)`, `UnknownRevert { … }`, `Transport(String)`

#### Token Errors

**`TokenError`**

- `InvalidParams(String)`, `Api(rpc::ApiClientError)`, `Client(ClientError)`, `UnknownRevert { … }`, `Transport(String)`

#### X402 Errors

**`X402Error`**

- `InvalidScheme(String)`: `paymentRequirements.scheme` must include `4mica`
- `InvalidVersion(String)`: Unexpected x402 version
- `InvalidFacilitatorUrl(String)`: Invalid facilitator `/settle` base URL
- `InvalidExtra(String)`: Issues parsing `paymentRequirements.extra` (v2 validation policy fields)
- `InvalidNumber { field, source }`: Invalid numeric field in requirements
- `EncodeEnvelope(String)`: Failed to encode the X-PAYMENT envelope
- `SettlementFailed { status, body }`: Facilitator `/settle` returned a non-success status
- `Signing(PaymentError)` / `Http(reqwest::Error)`: Errors while signing or making HTTP requests

## Development

### Running Tests

```bash
cargo test
```

### Building

```bash
cargo build --release
```

## Security Considerations

- **Never commit private keys**: Always use environment variables or secure key management systems
- **Validate addresses**: The SDK validates addresses automatically and returns `PaymentError::AddressMismatch` if the signer doesn't match the claims
- **Signature verification**: The SDK ensures the signer address matches the claims user address before signing
- **Use EIP-712**: Prefer EIP-712 signing over EIP-191 for better security and structured data hashing
- **Handle errors properly**: Always handle errors explicitly. The SDK provides specific error types for each failure scenario to help you build robust applications
- **Check signer addresses**: When acting as a recipient, ensure your signer address matches the recipient address. The SDK will return `InvalidParams` errors for mismatches
- **Validate amounts**: The SDK prevents zero-amount transactions at the contract level, but you should validate amounts in your application for better UX
- **ERC20 Approvals**: A self-funded ERC20 deposit needs an approval first — `deposit.of(…).self_funded().approve()` — while gasless routes carry their own authorization and need none. Approve only the amount you need. Paying an ERC20 net debit self-funded needs a _separate_ approval via `settlement.pay(…).self_funded().approve()` — a different contract from the one the deposit approval targets
- **Asset Matching**: Cycles are scoped to a single asset. Ensure the asset in your payment claims matches the asset you intend to settle in; the contract will reject mismatched assets
- **Use random `req_id`s**: Never reuse or sequence `req_id`. A duplicate within a cycle is rejected, and `X402Flow` generates one for you
- **Multi-Asset Management**: Each asset (ETH and each ERC20 token) has its own collateral balance and withdrawal request. Use `client.account.assets()` to view all your asset balances

## License

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0).

## Support

- Website: [https://4mica.xyz](https://4mica.xyz)
- Documentation: [https://docs.4mica.xyz](https://docs.4mica.xyz)
- GitHub: [https://github.com/4mica-Network/4mica-core](https://github.com/4mica-Network/4mica-core)

---

<p align="center">Made with ❤️ by the 4Mica Network</p>
