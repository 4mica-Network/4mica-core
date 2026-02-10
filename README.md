<p align="center">
  <img src="https://4mica.xyz/assets/logo_transparent.png" alt="4Mica Logo" width="200"/>
</p>

<h1 align="center">4Mica</h1>

<p align="center">
  <a href="https://github.com/4mica-Network/4mica-core/actions/workflows/deploy.yml">
    <img src="https://github.com/4mica-Network/4mica-core/actions/workflows/deploy.yml/badge.svg" alt="CD Status"/>
  </a>
  <a href="https://crates.io/crates/sdk-4mica">
    <img src="https://img.shields.io/crates/v/sdk-4mica.svg" alt="Rust SDK on crates.io"/>
  </a>
  <a href="https://4mica.xyz/resources/technical-docs">
    <img src="https://img.shields.io/badge/docs-4mica.xyz-0A84FF.svg" alt="Docs"/>
  </a>
<a href="https://creativecommons.org/licenses/by-nc/4.0/">
    <img src="https://img.shields.io/badge/License-CC_BY--NC_4.0-lightgrey.svg" alt="License: CC BY-NC 4.0"/>
</a>
  </a>
</p>

---

## 🌐 Website

Visit the official website: [https://4mica.xyz](https://4mica.xyz)

---

## 📚 Documentation

- Developer docs: [https://4mica.xyz/resources/technical-docs](https://4mica.xyz/resources/technical-docsz)
- Rust SDK API: [crates.io/sdk-4mica](https://crates.io/crates/sdk-4mica) · [docs.rs](https://docs.rs/sdk-4mica)

---

## 📦 Rust SDK

The official Rust client for interacting with the 4Mica payment network ships in this repository under `sdk/`. It provides:

- User flows: deposit collateral, sign payments, manage withdrawals (ETH or ERC20)
- Recipient flows: create tabs, verify guarantees, and claim collateral
- X402 helper: build `X-PAYMENT` headers for HTTP 402-protected resources

Install from crates.io:

```toml
[dependencies]
sdk-4mica = "0.5.0"
```

Minimal bootstrap:

```rust
use sdk_4mica::{Client, ConfigBuilder};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = Client::new(
        ConfigBuilder::default()
            .wallet_private_key(std::env::var("WALLET_PRIVATE_KEY")?)
            .build()?,
    )
    .await?;

    println!("Connected to 4Mica as {}", client.address());
    Ok(())
}
```

See `sdk/README.md` for full examples, configuration options, and X402 flows.

---

## Run Locally

### Requirements

- [Docker](https://www.docker.com/)
- [Rust](https://www.rust-lang.org/) `stable`

### Running the Project

To run the project locally, execute:

```bash
deployment/deploy_local.sh
```
This script prepares and launches all required development services. It is designed to:

For more details, refer to the documentation.

### 🤝 Contributing

We welcome contributions! Please check the contribution guide before submitting pull requests.

### 📜 License

This project is temporarily licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) Legal Code.

<p align="center">Made with ❤️ by the 4Mica Network</p> 
