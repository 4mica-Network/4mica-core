<p align="center">
  <img src="https://4mica.xyz/assets/logo_transparent.png" alt="4Mica Logo" width="200"/>
</p>

<h1 align="center">4Mica</h1>

<p align="center">
  <a href="https://github.com/4mica-Network/4mica-core/actions/workflows/deploy-prod.yml">
    <img src="https://github.com/4mica-Network/4mica-core/actions/workflows/deploy-prod.yml/badge.svg" alt="CD Status"/>
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

- Developer docs: [https://4mica.xyz/resources/technical-docs](https://4mica.xyz/resources/technical-docs)
- Rust SDK API: [crates.io/sdk-4mica](https://crates.io/crates/sdk-4mica) · [docs.rs](https://docs.rs/sdk-4mica)
- Contract deployment and activation: [contracts/README.md](contracts/README.md) · [contracts/GUARANTEE_V2_ACTIVATION.md](contracts/GUARANTEE_V2_ACTIVATION.md)
- V2 implementation notes: [changes.md](changes.md)

---

## 📦 Rust SDK

The official Rust client for interacting with the 4Mica payment network ships in this repository under `sdk/`. It provides:

- User flows: deposit collateral, sign payments, manage withdrawals (ETH or ERC20)
- Recipient flows: create tabs, verify guarantees, and claim collateral
- X402 helper: build `X-PAYMENT` headers for HTTP 402-protected resources

Install from crates.io:

```toml
[dependencies]
sdk-4mica = "0.6.0"
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

## Guarantee V2

This repository includes the ERC-8004 validation-gated remuneration flow described in
[`changes.md`](changes.md).

- Core accepts guarantee request versions according to `GUARANTEE_REQUEST_VERSION` and
  `GUARANTEE_ACCEPTED_REQUEST_VERSIONS`.
- The output certificate version is derived from the incoming request payload. The env var does
  not force the issued version.
- When V2 is accepted, `TRUSTED_VALIDATION_REGISTRIES` must be configured.
- Activate V2 on-chain with the runbook in
  [contracts/GUARANTEE_V2_ACTIVATION.md](contracts/GUARANTEE_V2_ACTIVATION.md).

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

This script prepares and launches all required development services. It deploys the local stack
and starts the services needed for end-to-end development.

For contract deployment and V2 activation details, refer to
[contracts/README.md](contracts/README.md) and
[contracts/GUARANTEE_V2_ACTIVATION.md](contracts/GUARANTEE_V2_ACTIVATION.md).

---

## 📊 Exported Metrics

All metrics carry two global labels: `app="core"` and `chain=<chain_id>`.

**`http_request_total`** · Counter  
Total HTTP requests received.

- `method`: HTTP verb (e.g. `GET`, `POST`)
- `path`: matched route path
- `status`: HTTP status code as string (e.g. `200`, `404`)

**`http_request_duration_seconds`** · Histogram  
Latency of HTTP requests.

- same labels as `http_request_total`

**`db_query_total`** · Counter  
Number of database queries executed.

- `name`: function name

**`db_query_duration_seconds`** · Histogram  
Execution time of database queries.

- same labels as `db_query_total`

**`ethereum_event_total`** · Counter  
Number of Ethereum event handler invocations.

- `name`: event handler function name

**`ethereum_event_duration_seconds`** · Histogram  
Execution time of Ethereum event handlers.

- same labels as `ethereum_event_total`

**`task_execution_total`** · Counter  
Number of scheduled task executions.

- `name`: task name

**`task_execution_duration_seconds`** · Histogram  
Execution time of scheduled tasks.

- same labels as `task_execution_total`

**`processed_payment_tx_total`** · Counter  
Number of processed payment transactions per status.

- `status`: `pending` | `confirmed` | `recorded` | `finalized` | `reverted`
- `asset`: asset address

**`processed_payment_tx_duration_seconds`** · Histogram  
Time elapsed between a payment transaction's previous and current status.

- same labels as `processed_payment_tx_total`

**`processed_event_tx_total`** · Counter  
Number of processed blockchain event transactions per status.

- `status`: `pending` | `confirmed` | `reverted`
- `signature`: event signature string

**`processed_event_tx_duration_seconds`** · Histogram  
Time elapsed between a blockchain event transaction's previous and current status.

- same labels as `processed_event_tx_total`

**`scanned_payment_tx_block`** · Gauge  
Latest block number scanned for payment transactions.

- no labels

**`scanned_event_tx_block`** · Gauge  
Latest block number scanned for blockchain event transactions.

- no labels

**`blockchain_safe_head`** · Gauge  
Latest known safe block number on the tracked chain.

- no labels

**`health_status`** · Gauge  
Health of a subsystem: `1` = healthy, `0` = unhealthy.

- `scope`: `db` | `chain_rpc` | `overall`

---

### 🤝 Contributing

We welcome contributions! Please check the contribution guide before submitting pull requests.

### 📜 License

This project is temporarily licensed under the Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0) Legal Code.

<p align="center">Made with ❤️ by the 4Mica Network</p>
