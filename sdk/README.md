[![Crates.io](https://img.shields.io/crates/v/sdk-4mica.svg)](https://crates.io/crates/sdk-4mica)

# 4Mica Rust SDK

The official Rust SDK for interacting with the 4Mica payment network.

## Overview

4Mica is a payment network that enables cryptographically-enforced lines of credit for autonomous payments. The SDK provides:

- **User Client**: Deposit collateral, sign payments, and manage withdrawals in ETH or ERC20 tokens
- **Recipient Client**: Issue and verify payment guarantees, and claim settled credit from user collateral
- **X402 Flow Helper**: Generate X-PAYMENT headers for 402-protected HTTP resources via an X402-compatible service
- **Validated Guarantees**: Build and verify guarantees gated on an external validator's approval

## Installation

Add the SDK to your `Cargo.toml`:

```toml
[dependencies]
sdk-4mica = "0.6.0"
```

## Guarantee Versions

The SDK signs at its own `GUARANTEE_CLAIMS_VERSION`. Core accepts every version it can decode,
listed in `/core/public-params` as `supported_guarantee_versions`, so an older client keeps
working; a client newer than the core it talks to fails at construction with a clear message.

## Validated Guarantees

A guarantee that carries a `validation` requirement is payable only once the named validator
approves it, and is cancelled if that has not happened by the deadline. Core resolves only
validators it whitelists, listed in `/core/public-params` as `validators`.

Attach one by building the claims with `PaymentGuaranteeRequestClaims::new(...).with_validation(...)`
and signing them with `user.sign_payment(...)`.

## Initialization and Configuration

The SDK requires a signer and can use sensible defaults for the rest:

- `signer` (**required**): Any `alloy::signers::Signer` (typically `PrivateKeySigner` from a hex private key). On-chain methods require a signer that also implements `TxSigner<Signature>`.
- `rpc_url` (optional): URL of the 4Mica RPC server. Defaults to `https://api.4mica.xyz/`; override for local development.
- `network` (optional): select a hosted network by shorthand or CAIP-2 id.

Hosted networks:

| Shorthand          | CAIP-2            | Core API URL                              |
| ------------------ | ----------------- | ----------------------------------------- |
| `base`             | `eip155:8453`     | `https://base.api.4mica.xyz/`             |
| `base-sepolia`     | `eip155:84532`    | `https://base.sepolia.api.4mica.xyz/`     |
| `ethereum-sepolia` | `eip155:11155111` | `https://ethereum.sepolia.api.4mica.xyz/` |

The following parameters are **optional** and will be automatically fetched from the server if not provided.

- `ethereum_http_rpc_url`: URL of the Ethereum JSON-RPC endpoint (optional)
- `contract_address`: Address of the deployed Core4Mica smart contract (optional)

> **Note:** You normally don't need to provide `ethereum_http_rpc_url` and `contract_address` as the SDK will fetch these from the server automatically. Only override these if you need to use different values than the server's defaults.
>
> The Ethereum `chain_id` is fetched from the core service and validated against the connected Ethereum provider automatically.

### Configuration Methods

#### 1. Using ConfigBuilder

```rust
use alloy::signers::{Signer, local::PrivateKeySigner};
use sdk_4mica::{ConfigBuilder, Client};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = PrivateKeySigner::from_str("your_private_key")?;
    let config = ConfigBuilder::default()
        .network("base")?
        .signer(signer)
        .build()?;

    let client = Client::new(config).await?;
    Ok(())
}
```

#### 2. Using Environment Variables (`ConfigBuilder::from_env`)

`ConfigBuilder::from_env()` reads these keys:

- `4MICA_WALLET_PRIVATE_KEY` (required)
- `4MICA_NETWORK` (optional; shorthand or CAIP-2 id; takes precedence over `4MICA_RPC_URL`)
- `4MICA_RPC_URL` (optional; defaults to `https://api.4mica.xyz/`)
- `4MICA_ETHEREUM_HTTP_RPC_URL` (optional)
- `4MICA_CONTRACT_ADDRESS` (optional)
- `4MICA_BEARER_TOKEN` (optional)
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
use sdk_4mica::{Client, ConfigBuilder};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let config = ConfigBuilder::from_env()? // Loads environment variables
        .build()?;

    let client = Client::new(config).await?;
    Ok(())
}
```

Add `dotenv = "0.15"` to your app dependencies if you load `.env` files this way.

## Usage

The SDK provides client interfaces for both sides of the payment flow plus a helper to bridge HTTP 402 resources:

- `UserClient`: payer controls collateral and signs payments
- `RecipientClient`: payment recipient issues and verifies guarantees, and claims settled credit
- `X402Flow`: builds X-PAYMENT headers for X402-protected HTTP endpoints

### X402 flow (HTTP 402)

The X402 helper turns the `paymentRequirements` emitted by a `402 Payment Required` response into an X-PAYMENT header (and optional `/settle` call) that the facilitator will accept. The examples in `https://github.com/4mica-Network/x402-4mica/examples` model the expected flow: the client speaks to the resource server, and the resource server talks to the facilitator for `/tabs`, `/verify`, and `/settle`.

#### What the SDK expects from `paymentRequirements`

`sdk-4mica` accepts the canonical X402 JSON (camelCase). At minimum you need:

- `scheme` and `network`: `scheme` must contain `4mica` (e.g. `4mica-credit`)
  `X402Flow` will refresh the tab by calling `extra.tabEndpoint` before signing.

#### End-to-end client flow

##### X402 Version 1

Version 1 returns payment requirements in the JSON response body:

- GET the protected endpoint; parse the JSON body to get the response with `accepts` array.
- Select a payment option from `accepts` array.
- Call `X402Flow::sign_payment` to get the base64 `X-PAYMENT` header.
- Retry the protected endpoint with `X-PAYMENT`; the resource server will call the facilitator `/verify` and `/settle`.

```rust
use alloy::signers::{Signer, local::PrivateKeySigner};
use sdk_4mica::{Client, ConfigBuilder, X402Flow};
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
    let payer = Client::new(
        ConfigBuilder::default()
            .signer(payer_signer)
            .build()?,
    )
    .await?;

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
use sdk_4mica::{Client, ConfigBuilder, X402Flow};
use sdk_4mica::x402::{X402PaymentRequiredV2, PaymentRequirementsV2};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payer_signer = PrivateKeySigner::from_str(&std::env::var("PAYER_KEY")?)?;
    let user_address = payer_signer.address().to_string();
    let payer = Client::new(
        ConfigBuilder::default()
            .signer(payer_signer)
            .build()?,
    )
    .await?;

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
use sdk_4mica::{Client, ConfigBuilder, X402Flow, X402SignedPayment};
use sdk_4mica::x402::PaymentRequirements;
use std::str::FromStr;

async fn settle(
    facilitator_url: &str,
    payment_requirements: PaymentRequirements,
    payment: X402SignedPayment,
) -> Result<(), Box<dyn std::error::Error>> {
    let resource_signer = PrivateKeySigner::from_str(&std::env::var("RESOURCE_SIGNER_KEY")?)?;
    let core = Client::new(
        ConfigBuilder::default()
            .signer(resource_signer)
            .build()?,
    )
    .await?;
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

#### UserClient Methods

- `approve_erc20(token: String, amount: U256) -> Result<TransactionReceipt, ApproveErc20Error>`: Approve the 4Mica contract to spend ERC20 tokens on behalf of the user
- `deposit(amount: U256, erc20_token: Option<String>) -> Result<TransactionReceipt, DepositError>`: Deposit collateral in ETH or ERC20 token
- `get_user() -> Result<Vec<UserInfo>, GetUserError>`: Get current user information for all assets
- `sign_payment(claims: PaymentGuaranteeRequestClaims, scheme: SigningScheme) -> Result<PaymentSignature, SignPaymentError>`: Sign a payment; the claims carry an optional `validation` requirement
- `request_withdrawal(amount: U256, erc20_token: Option<String>) -> Result<TransactionReceipt, RequestWithdrawalError>`: Request withdrawal of collateral in ETH or ERC20 token
- `cancel_withdrawal(erc20_token: Option<String>) -> Result<TransactionReceipt, CancelWithdrawalError>`: Cancel pending withdrawal
- `finalize_withdrawal(erc20_token: Option<String>) -> Result<TransactionReceipt, FinalizeWithdrawalError>`: Finalize withdrawal after waiting period

#### RecipientClient Methods

- `issue_payment_guarantee(claims: PaymentGuaranteeRequestClaims, signature: String, scheme: SigningScheme) -> Result<BLSCert, IssuePaymentGuaranteeError>`: Issue a payment guarantee
- `verify_payment_guarantee(cert: &BLSCert) -> Result<PaymentGuaranteeClaims, VerifyGuaranteeError>`: Verify a BLS certificate and extract claims
- `guarantee_domain() -> &[u8; 32]`: On-chain domain separator guarantees are signed under
- `list_recipient_payments() -> Result<Vec<RecipientPaymentInfo>, RecipientQueryError>`: List all payments for the recipient
- `get_user_asset_balance(asset_address: String) -> Result<Option<AssetBalanceInfo>, RecipientQueryError>`: Get the recipient's balance for one asset
- `get_clearing_claim_net_credit_action(cycle_id: String) -> Result<ClearingSettlementActionResponse, ClearingSettlementError>`: Prepare the on-chain call that claims a settled cycle's net credit
- `claim_net_credit(cycle_id: String) -> Result<TransactionReceipt, ClearingSettlementError>`: Claim the recipient's net credit for a cycle

### User Client (Payer)

The user client allows you to manage your collateral and sign payments in ETH or ERC20 tokens.

#### Approve ERC20 Token (Required before depositing or paying with ERC20)

```rust
use sdk_4mica::U256;

// Approve the 4Mica contract to spend 1000 USDC on your behalf
let token_address = "0x1234567890123456789012345678901234567890".to_string();
let amount = U256::from(1000_000_000u128); // 1000 USDC (6 decimals)

match client.user.approve_erc20(token_address, amount).await {
    Ok(receipt) => {
        println!("ERC20 approval successful: {:?}", receipt.transaction_hash);
    }
    Err(e) => {
        eprintln!("ERC20 approval failed: {}", e);
    }
}
```

#### Deposit Collateral

```rust
use sdk_4mica::U256;

// Deposit 1 ETH as collateral
let amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH in wei
match client.user.deposit(amount, None).await {
    Ok(receipt) => {
        println!("Deposit successful: {:?}", receipt.transaction_hash);
    }
    Err(e) => {
        eprintln!("Deposit failed: {}", e);
    }
}

// Or deposit 1000 USDC (make sure to approve first!)
let token_address = "0x1234567890123456789012345678901234567890".to_string();
let amount = U256::from(1000_000_000u128);
let receipt = client.user.deposit(amount, Some(token_address)).await?;
println!("USDC deposit successful: {:?}", receipt.transaction_hash);
```

#### Get User Info

```rust
// Get information about the current user for all assets
let user_assets = client.user.get_user().await?;
for user_info in user_assets {
    println!("Asset: {}", user_info.asset);
    println!("Collateral: {}", user_info.collateral);
    println!("Withdrawal request amount: {}", user_info.withdrawal_request_amount);
    println!("Withdrawal request timestamp: {}", user_info.withdrawal_request_timestamp);
    println!("---");
}
```

#### Sign a Payment

```rust
use sdk_4mica::{PaymentGuaranteeRequestClaims, SigningScheme, U256};

// Create payment claims for ETH payment
let claims = PaymentGuaranteeRequestClaims::new(
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(), // user_address
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(), // recipient_address
    U256::ZERO,                                                // req_id (random nonce, see note below)
    U256::from(1_000_000_000_000_000_000u128),                 // amount (1 ETH)
    1704067200,                                                // timestamp
    None,                                                      // erc20_token (None for ETH)
);

// Sign using EIP-712 (recommended)
match client.user.sign_payment(claims.clone(), SigningScheme::Eip712).await {
    Ok(payment_sig) => {
        println!("Signature: {}", payment_sig.signature);
        println!("Scheme: {:?}", payment_sig.scheme);
    }
    Err(e) => {
        eprintln!("Signing failed: {}", e);
    }
}

// Or use EIP-191 (personal_sign)
let payment_sig = client.user.sign_payment(claims, SigningScheme::Eip191).await?;

// For ERC20 token payment, pass the token address
let usdc_token = "0x1234567890123456789012345678901234567890".to_string();
let claims_usdc = PaymentGuaranteeRequestClaims::new(
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
    U256::ZERO,
    U256::from(1000_000_000u128), // 1000 USDC
    1704067200,
    Some(usdc_token),
);
let payment_sig_usdc = client.user.sign_payment(claims_usdc, SigningScheme::Eip712).await?;
```

> **Note on `req_id`:** `req_id` is a per-request nonce, **not** a sequential counter. Use a freshly generated random `U256` for each guarantee request (the `U256::ZERO` above is only for a readable example). Replay protection comes from two independent checks: a request is bound to one settlement cycle via its signed `timestamp` (a request whose timestamp predates the active cycle is rejected as stale), and within a cycle the `(req_id, ...)` digest must be unique, so reusing a `req_id` for an otherwise-identical request is rejected as a duplicate. Random `req_id`s avoid accidental collisions; they do not need to increase or follow any order.

#### Request Withdrawal

```rust
use sdk_4mica::U256;

// Request to withdraw 0.5 ETH
let amount = U256::from(500_000_000_000_000_000u128);
let receipt = client.user.request_withdrawal(amount, None).await?;
println!("Withdrawal requested: {:?}", receipt.transaction_hash);

// Or request to withdraw 500 USDC
let token_address = "0x1234567890123456789012345678901234567890".to_string();
let amount_usdc = U256::from(500_000_000u128);
let receipt = client.user.request_withdrawal(amount_usdc, Some(token_address)).await?;
println!("USDC withdrawal requested: {:?}", receipt.transaction_hash);
```

#### Cancel Withdrawal

```rust
// Cancel a pending ETH withdrawal request
let receipt = client.user.cancel_withdrawal(None).await?;
println!("Withdrawal cancelled: {:?}", receipt.transaction_hash);

// Cancel a pending USDC withdrawal request
let token_address = "0x1234567890123456789012345678901234567890".to_string();
let receipt = client.user.cancel_withdrawal(Some(token_address)).await?;
println!("USDC withdrawal cancelled: {:?}", receipt.transaction_hash);
```

#### Finalize Withdrawal

```rust
// Finalize ETH withdrawal (after the waiting period)
let receipt = client.user.finalize_withdrawal(None).await?;
println!("Withdrawal finalized: {:?}", receipt.transaction_hash);

// Finalize USDC withdrawal (after the waiting period)
let token_address = "0x1234567890123456789012345678901234567890".to_string();
let receipt = client.user.finalize_withdrawal(Some(token_address)).await?;
println!("USDC withdrawal finalized: {:?}", receipt.transaction_hash);
```

### Recipient Client

The recipient client allows you to issue and verify payment guarantees, and claim settled credit from user collateral.

#### Issue Payment Guarantee

```rust
use sdk_4mica::{PaymentGuaranteeRequestClaims, SigningScheme, U256};

// First, the user signs the payment (see User Client example above)
let claims = PaymentGuaranteeRequestClaims::new(
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
    U256::from(1),
    U256::ZERO,
    U256::from(1_000_000_000_000_000_000u128), // 1 ETH
    1704067200,
    None, // None for ETH
);

let payment_sig = client.user.sign_payment(claims.clone(), SigningScheme::Eip712).await?;

let bls_cert = client.recipient.issue_payment_guarantee(
    claims,
    payment_sig.signature,
    payment_sig.scheme,
).await?;
println!("BLS Certificate: {:?}", bls_cert);
```

## Complete Example

Here's a complete example showing a payment flow with ETH:

```rust
use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::{
    Client, ConfigBuilder, PaymentGuaranteeRequestClaims, SigningScheme, U256,
};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup clients (user and recipient each have their own)
    let user_signer = PrivateKeySigner::from_str("user_private_key")?;
    let user_config = ConfigBuilder::default().signer(user_signer).build()?;
    let user_client = Client::new(user_config).await?;

    let recipient_signer = PrivateKeySigner::from_str("recipient_private_key")?;
    let recipient_config = ConfigBuilder::default()
        .signer(recipient_signer)
        .build()?;
    let recipient_client = Client::new(recipient_config).await?;

    // 2. User deposits collateral
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    let receipt = user_client.user.deposit(deposit_amount, None).await?;
    println!("Deposited collateral: {:?}", receipt.transaction_hash);

    // 3. User signs a payment
    let user_address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string();
    let recipient_address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string();
    let claims = PaymentGuaranteeRequestClaims::new(
        user_address.clone(),
        recipient_address.clone(),
        U256::ZERO, // req_id: use a fresh random nonce in production
        U256::from(1_000_000_000_000_000_000u128), // 1 ETH
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        None, // None for ETH
    );
    let payment_sig = user_client.user.sign_payment(claims.clone(), SigningScheme::Eip712).await?;
    println!("Payment signed");

    // 4. Recipient issues the guarantee
    let bls_cert = recipient_client
        .recipient
        .issue_payment_guarantee(claims, payment_sig.signature, payment_sig.scheme)
        .await?;
    println!("Guarantee issued");

    Ok(())
}
```

### Complete Example with ERC20 Token (USDC)

Here's a complete example showing a payment flow with an ERC20 token:

```rust
use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::{
    Client, ConfigBuilder, PaymentGuaranteeRequestClaims, SigningScheme, U256,
};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let user_signer = PrivateKeySigner::from_str("user_private_key")?;
    let user_config = ConfigBuilder::default().signer(user_signer).build()?;
    let user_client = Client::new(user_config).await?;

    let recipient_signer = PrivateKeySigner::from_str("recipient_private_key")?;
    let recipient_config = ConfigBuilder::default()
        .signer(recipient_signer)
        .build()?;
    let recipient_client = Client::new(recipient_config).await?;

    let usdc_token = "0x1234567890123456789012345678901234567890".to_string();

    // 1. User approves the 4Mica contract to spend USDC
    let approval_amount = U256::from(10000_000_000u128); // 10,000 USDC
    user_client.user.approve_erc20(usdc_token.clone(), approval_amount).await?;
    println!("Approved USDC spending");

    // 2. User deposits USDC collateral
    let deposit_amount = U256::from(5000_000_000u128); // 5,000 USDC
    user_client.user.deposit(deposit_amount, Some(usdc_token.clone())).await?;
    println!("Deposited USDC collateral");

    // 3. User signs a USDC payment
    let user_address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string();
    let recipient_address = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string();
    let claims = PaymentGuaranteeRequestClaims::new(
        user_address.clone(),
        recipient_address.clone(),
        U256::ZERO, // req_id: use a fresh random nonce in production
        U256::from(1000_000_000u128), // 1,000 USDC
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        Some(usdc_token.clone()),
    );
    let payment_sig = user_client.user.sign_payment(claims.clone(), SigningScheme::Eip712).await?;
    println!("Payment signed");

    // 4. Recipient issues the guarantee
    let bls_cert = recipient_client
        .recipient
        .issue_payment_guarantee(claims, payment_sig.signature, payment_sig.scheme)
        .await?;
    println!("Guarantee issued");

    Ok(())
}
```

## Error Handling

The SDK provides comprehensive, type-safe error handling with specific error types for each operation. All errors are strongly typed and provide detailed context about what went wrong.

### Importing

```rust
// Import specific error types when needed
use sdk_4mica::error::{
    ApproveErc20Error, DepositError, RequestWithdrawalError,
    SignPaymentError, FinalizeWithdrawalError,
    IssuePaymentGuaranteeError, VerifyGuaranteeError, RecipientQueryError,
    // ... other error types as needed
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

#### Payment Signing Errors

**`SignPaymentError`**

- `AddressMismatch { signer: Address, claims: String }`: Signer address doesn't match user address in claims
- `InvalidUserAddress`: User address in claims is invalid
- `InvalidRecipientAddress`: Recipient address in claims is invalid
- `Failed(String)`: Failed to sign the payment (includes digest computation and signing errors)
- `Rpc(rpc::ApiClientError)`: RPC communication error

#### Deposit Errors

**`ApproveErc20Error`**

- `InvalidParams(String)`: Invalid parameters provided (e.g., invalid token address)
- `Client(ClientError)`: Client initialization or provider error while preparing the transaction
- `UnknownRevert { selector: u32, data: Vec<u8> }`: Unknown contract revert
- `Transport(String)`: Provider or transport error

**`DepositError`**

- `InvalidParams(String)`: Invalid parameters provided (e.g., invalid token address)
- `AmountZero`: Cannot deposit zero amount
- `Client(ClientError)`: Client initialization or provider error while preparing the transaction
- `UnknownRevert { selector: u32, data: Vec<u8> }`: Unknown contract revert
- `Transport(String)`: Provider or transport error

#### Withdrawal Errors

**`RequestWithdrawalError`**

- `InvalidParams(String)`: Invalid parameters provided (e.g., invalid token address)
- `AmountZero`: Cannot withdraw zero amount
- `InsufficientAvailable`: Not enough available balance to withdraw
- `Client(ClientError)`: Client initialization or provider error while preparing the transaction
- `UnknownRevert { selector: u32, data: Vec<u8> }`: Unknown contract revert
- `Transport(String)`: Provider or transport error

**`CancelWithdrawalError`**

- `InvalidParams(String)`: Invalid parameters provided (e.g., invalid token address)
- `NoWithdrawalRequested`: No withdrawal request exists to cancel
- `Client(ClientError)`: Client initialization or provider error while preparing the transaction
- `UnknownRevert { selector: u32, data: Vec<u8> }`: Unknown contract revert
- `Transport(String)`: Provider or transport error

**`FinalizeWithdrawalError`**

- `InvalidParams(String)`: Invalid parameters provided (e.g., invalid token address)
- `NoWithdrawalRequested`: No withdrawal request exists to finalize
- `GracePeriodNotElapsed`: Grace period has not elapsed yet
- `TransferFailed`: Transfer of funds failed
- `Client(ClientError)`: Client initialization or provider error while preparing the transaction
- `UnknownRevert { selector: u32, data: Vec<u8> }`: Unknown contract revert
- `Transport(String)`: Provider or transport error

#### Payment Guarantee Errors

**`IssuePaymentGuaranteeError`**

- `InvalidParams(String)`: Invalid parameters (e.g., signer address mismatch)
- `Rpc(rpc::ApiClientError)`: RPC communication error

**`VerifyGuaranteeError`**

- `InvalidCertificate(anyhow::Error)`: Invalid BLS certificate
- `CertificateMismatch`: Certificate signature mismatch
- `GuaranteeDomainMismatch`: Guarantee domain mismatch
- `UnsupportedGuaranteeVersion(u64)`: Unsupported guarantee version

**`X402Error`**

- `InvalidScheme(String)`: `paymentRequirements.scheme` must include `4mica`
- `InvalidFacilitatorUrl(String)`: Invalid facilitator `/settle` base URL
- `TabResolutionFailed(String)` / `InvalidExtra(String)`: Issues resolving or parsing `paymentRequirements.extra`
- `InvalidNumber { field, source }` / `UserMismatch { found, expected }`: Invalid numeric fields or wrong user in requirements
- `EncodeEnvelope(String)`: Failed to encode the X-PAYMENT envelope
- `SettlementFailed { status, body }`: Facilitator `/settle` returned a non-success status
- `Signing(SignPaymentError)` / `Http(reqwest::Error)`: Errors while signing or making HTTP requests

**`RecipientQueryError`**

- `Rpc(rpc::ApiClientError)`: RPC communication error

**`GetUserError`**

- `UnknownRevert { selector: u32, data: Vec<u8> }`: Unknown contract revert
- `Transport(String)`: Provider or transport error

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
- **Validate addresses**: The SDK validates addresses automatically and returns `SignPaymentError::AddressMismatch` if the signer doesn't match the claims
- **Signature verification**: The SDK ensures the signer address matches the claims user address before signing
- **Use EIP-712**: Prefer EIP-712 signing over EIP-191 for better security and structured data hashing
- **Handle errors properly**: Always handle errors explicitly. The SDK provides specific error types for each failure scenario to help you build robust applications
- **Check signer addresses**: For `RecipientClient` operations, ensure your signer address matches the recipient address. The SDK will return `InvalidParams` errors for mismatches
- **Validate amounts**: The SDK prevents zero-amount transactions at the contract level, but you should validate amounts in your application for better UX
- **ERC20 Approvals**: Always approve the 4Mica contract before depositing or paying with ERC20 tokens. Approve only the amount you need to minimize risk
- **Asset Matching**: A guarantee's asset must match the collateral the payer deposited; the contract rejects mismatched assets
- **Multi-Asset Management**: Each asset (ETH and each ERC20 token) has its own collateral balance and withdrawal request. Use `get_user()` to view all your asset balances

## License

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0).

## Support

- Website: [https://4mica.xyz](https://4mica.xyz)
- Documentation: [https://docs.4mica.xyz](https://docs.4mica.xyz)
- GitHub: [https://github.com/4mica-Network/4mica-core](https://github.com/4mica-Network/4mica-core)

---

<p align="center">Made with ❤️ by the 4Mica Network</p>
