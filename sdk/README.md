# 4Mica Rust SDK

The official Rust SDK for interacting with the 4Mica payment network. This SDK provides a simple and type-safe interface for both payment users and recipients.

## Overview

4Mica is a blockchain-based payment network that enables secure and cryptographically-guaranteed tab-based payments. The SDK provides:

- **User Client**: Deposit collateral, sign payments, and manage withdrawals
- **Recipient Client**: Create payment tabs, issue payment guarantees, and claim from user collateral when payments aren't fulfilled
- Built-in EIP-712 and EIP-191 signing support
- Type-safe interactions with the Core4Mica smart contract

## Installation

Add the SDK to your `Cargo.toml`:

```toml
[dependencies]
rust-sdk-4mica = "0.1.0"
```

## Configuration

The SDK requires four configuration parameters:

- `rpc_url`: URL of the 4Mica RPC server
- `ethereum_http_rpc_url`: URL of the Ethereum JSON-RPC endpoint
- `contract_address`: Address of the deployed Core4Mica smart contract
- `wallet_private_key`: Private key for signing transactions (hex string with or without `0x` prefix)

### Configuration Methods

#### 1. Using ConfigBuilder

```rust
use rust_sdk_4mica::{Config, ConfigBuilder, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default()
        .rpc_url("http://localhost:3000".to_string())
        .ethereum_http_rpc_url("http://localhost:8545".to_string())
        .contract_address("0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0".to_string())
        .wallet_private_key("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string())
        .build()?;

    let client = Client::new(config).await?;
    Ok(())
}
```

#### 2. Using Environment Variables

Set the following environment variables:

```bash
export 4MICA_RPC_URL="http://localhost:3000"
export 4MICA_ETHEREUM_HTTP_RPC_URL="http://localhost:8545"
export 4MICA_CONTRACT_ADDRESS="0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0"
export 4MICA_WALLET_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
```

Then in your code:

```rust
use rust_sdk_4mica::{ConfigBuilder, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default()
        .from_env()  // Loads environment variables
        .build()?;

    let client = Client::new(config).await?;
    Ok(())
}
```

#### 3. Default Configuration (Development)

For local development, you can use the default configuration:

```rust
use rust_sdk_4mica::{ConfigBuilder, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default()
        .wallet_private_key("your_private_key".to_string())  // Only private key required
        .build()?;

    let client = Client::new(config).await?;
    Ok(())
}
```

The default configuration uses:

- RPC URL: `http://localhost:3000`
- Ethereum RPC URL: `http://localhost:8545`
- Contract Address: `0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0`

## Usage

The SDK provides two client interfaces: `UserClient` for payers and `RecipientClient` for payment recipients.

### User Client (Payer)

The user client allows you to manage your collateral and sign payments.

#### Deposit Collateral

```rust
use rust_sdk_4mica::U256;

// Deposit 1 ETH as collateral
let amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH in wei
client.user.deposit(amount).await?;
```

#### Sign a Payment

```rust
use rust_sdk_4mica::{PaymentGuaranteeClaims, SigningScheme, U256};

let claims = PaymentGuaranteeClaims {
    user_address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
    recipient_address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
    tab_id: U256::from(1),
    req_id: U256::from(1),
    amount: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
    timestamp: 1704067200,
};

// Sign using EIP-712 (recommended)
let signature = client.user.sign_payment(claims, SigningScheme::Eip712).await?;
println!("Signature: {}", signature.signature);

// Or use EIP-191 (personal_sign)
let signature = client.user.sign_payment(claims, SigningScheme::Eip191).await?;
```

#### Request Withdrawal

```rust
use rust_sdk_4mica::U256;

// Request to withdraw 0.5 ETH
let amount = U256::from(500_000_000_000_000_000u128);
client.user.request_withdrawal(amount).await?;
```

#### Cancel Withdrawal

```rust
// Cancel a pending withdrawal request
client.user.cancel_withdrawal().await?;
```

#### Finalize Withdrawal

```rust
// Finalize withdrawal (after the waiting period)
client.user.finalize_withdrawal().await?;
```

### Recipient Client

The recipient client allows you to create payment tabs, issue payment guarantees, and claim from user collateral when payments aren't fulfilled.

#### Create Payment Tab

```rust
use rust_sdk_4mica::CreatePaymentTabRequest;

let tab_request = CreatePaymentTabRequest {
    user_address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
    recipient_address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
    ttl: Some(3600), // Tab expires in 1 hour (optional)
};

let tab_id = client.recipient.create_tab(tab_request).await?;
println!("Created tab with ID: {}", tab_id);
```

#### Issue Payment Guarantee

```rust
use rust_sdk_4mica::{PaymentGuaranteeRequest, PaymentGuaranteeClaims, SigningScheme};

// First, the user signs the payment (see User Client example above)
let signature = client.user.sign_payment(claims.clone(), SigningScheme::Eip712).await?;

// Then, the recipient requests a guarantee
let guarantee_request = PaymentGuaranteeRequest {
    claims,
    signature: signature.signature,
    scheme: signature.scheme,
};

let bls_cert = client.recipient.issue_payment_guarantee(guarantee_request).await?;
println!("BLS Certificate: {:?}", bls_cert);
```

#### Remunerate (Claim from Collateral)

```rust
// If the user doesn't fulfill the payment guarantee,
// the recipient can claim from the user's collateral on-chain
client.recipient.remunerate(bls_cert).await?;
println!("Claimed from user collateral successfully!");
```

## Complete Example

Here's a complete example showing a payment flow:

```rust
use rust_sdk_4mica::{
    Client, ConfigBuilder, CreatePaymentTabRequest, PaymentGuaranteeClaims,
    PaymentGuaranteeRequest, SigningScheme, U256,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Setup clients (user and recipient each have their own)
    let user_config = ConfigBuilder::default()
        .wallet_private_key("user_private_key".to_string())
        .build()?;
    let user_client = Client::new(user_config).await?;

    let recipient_config = ConfigBuilder::default()
        .wallet_private_key("recipient_private_key".to_string())
        .build()?;
    let recipient_client = Client::new(recipient_config).await?;

    // 2. User deposits collateral
    let deposit_amount = U256::from(2_000_000_000_000_000_000u128); // 2 ETH
    user_client.user.deposit(deposit_amount).await?;
    println!("Deposited collateral");

    // 3. Recipient creates a payment tab
    let tab_request = CreatePaymentTabRequest {
        user_address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
        recipient_address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
        ttl: Some(3600),
    };
    let tab_id = recipient_client.recipient.create_tab(tab_request).await?;
    println!("Created tab: {}", tab_id);

    // 4. User signs a payment
    let claims = PaymentGuaranteeClaims {
        user_address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
        recipient_address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
        tab_id,
        req_id: U256::from(1),
        amount: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    };
    let signature = user_client.user.sign_payment(claims.clone(), SigningScheme::Eip712).await?;
    println!("Payment signed");

    // 5. Recipient issues guarantee
    let guarantee_request = PaymentGuaranteeRequest {
        claims,
        signature: signature.signature,
        scheme: signature.scheme,
    };
    let bls_cert = recipient_client
        .recipient
        .issue_payment_guarantee(guarantee_request)
        .await?;
    println!("Guarantee issued");

    // 6. If user doesn't pay, recipient can claim from user's collateral
    recipient_client.recipient.remunerate(bls_cert).await?;
    println!("Claimed from user collateral!");

    Ok(())
}
```

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

- **Never commit private keys**: Always use environment variables or secure key management
- **Validate addresses**: The SDK validates addresses automatically, but ensure you're using correct addresses
- **Signature verification**: The SDK ensures the signer address matches the claims user address
- **Use EIP-712**: Prefer EIP-712 signing over EIP-191 for better security

## License

This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0).

## Support

- Website: [https://4mica.xyz](https://4mica.xyz)
- Documentation: [https://docs.4mica.xyz](https://docs.4mica.xyz)
- GitHub: [https://github.com/4mica-Network/4mica-core](https://github.com/4mica-Network/4mica-core)

---

<p align="center">Made with ❤️ by the 4Mica Network</p>
