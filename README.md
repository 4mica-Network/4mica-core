<p align="center">
  <img src="https://4mica.io/assets/logo_transparent.png" alt="4Mica Logo" width="200"/>
</p>

<h1 align="center">4Mica</h1>

<p align="center">
  <a href="https://github.com/4mica-Network/4mica-core/actions/workflows/deploy-prod.yml">
    <img src="https://github.com/4mica-Network/4mica-core/actions/workflows/deploy-prod.yml/badge.svg" alt="CD Status"/>
  </a>
  <a href="https://crates.io/crates/sdk-4mica">
    <img src="https://img.shields.io/crates/v/sdk-4mica.svg" alt="Rust SDK on crates.io"/>
  </a>
  <a href="https://docs.4mica.io">
    <img src="https://img.shields.io/badge/docs-4mica.io-0A84FF.svg" alt="Docs"/>
  </a>
<a href="https://creativecommons.org/licenses/by-nc/4.0/">
    <img src="https://img.shields.io/badge/License-CC_BY--NC_4.0-lightgrey.svg" alt="License: CC BY-NC 4.0"/>
</a>
</p>

---

## 🌐 Website

Visit the official website: [https://4mica.io](https://4mica.io)

---

## 📚 Documentation

- Developer docs: [https://docs.4mica.io](https://docs.4mica.io)
- Rust SDK API: [crates.io/sdk-4mica](https://crates.io/crates/sdk-4mica) · [docs.rs](https://docs.rs/sdk-4mica)
- Contract deployment: [contracts/README.md](contracts/README.md)

---

## 📦 Rust SDK

The official Rust client for interacting with the 4Mica payment network lives in the [4mica](https://github.com/4mica-Network/4mica) monorepo under `packages/sdk-rust/`. It provides:

- User flows: deposit collateral, sign payments, manage withdrawals (ETH or ERC20)
- Recipient flows: create tabs, verify guarantees, and claim collateral
- X402 helper: build `X-PAYMENT` headers for HTTP 402-protected resources

Install from crates.io:

```toml
[dependencies]
sdk-4mica = "2.0.0-alpha.4"
```

Minimal bootstrap:

```rust
use alloy::signers::local::PrivateKeySigner;
use sdk_4mica::Client;
use std::str::FromStr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let signer = PrivateKeySigner::from_str(&std::env::var("WALLET_PRIVATE_KEY")?)?;
    let client = Client::builder().signer(signer).connect().await?;

    println!("Connected to 4Mica as {}", client.signer_address());
    Ok(())
}
```

See the [SDK README](https://github.com/4mica-Network/4mica/tree/main/packages/sdk-rust) for full examples, configuration options, and X402 flows.

## Validated guarantees

A guarantee may optionally carry a **validation requirement**: it only becomes payable once an
external validator approves it before a deadline. Validators are whitelisted per operator via
`GUARANTEE_VALIDATORS` and driven by pluggable adapters, so core stays agnostic to what any
particular validator checks.

---

## Run Locally

### Requirements

- [Docker](https://www.docker.com/) (your user must be able to reach the Docker daemon)
- [Rust](https://www.rust-lang.org/) `stable`
- [Foundry](https://book.getfoundry.sh/) (`anvil`, `forge`)

### Running the Project

The local stack — Postgres, an Anvil node, forge-deployed contracts, database
migrations, and `core-service` — is orchestrated through the `Makefile` (which wraps
[deployment/dev_stack.sh](deployment/dev_stack.sh)). Every step generates a complete
`.env` for you, including the deployed contract and ClearingHouse addresses and a BLS
verification key derived from `BLS_PRIVATE_KEY`, so there are no env vars to wire by hand.

To run the full stack (for development or the SDK e2e tests):

```bash
make dev-up
```

#### Running the tests

The two suites need different amounts of the stack, so they are **not** run the same way:

- **Core tests** must run with **no external `core-service` running** — each test builds
  its own in-process `CoreService` (and the chain tests spawn their own Anvil), so a
  second long-lived service would race the in-process event scanner on the shared
  database. They only need infra (Postgres + Anvil + deployed contracts):

  ```bash
  make infra-up     # pg + anvil + contracts + migrations, but NOT core-service
  make test-core
  ```

- **SDK e2e tests** talk to a running `core-service` on `:3000`, so they need the full
  stack up:

  ```bash
  make dev-up
  make test-sdk
  ```

`make test` chains both correctly: infra → `test-core` (core down) → full stack →
`test-sdk` (core up).

Other useful targets: `make status`, `make logs`, `make deploy` (redeploy contracts),
`make dev-down` (stop core + anvil), `make dev-down-all` (also stop Postgres). Run
`make help` for the full list. See [deployment/dev_stack.sh](deployment/dev_stack.sh) for
the underlying steps and tunables.

For contract deployment details, refer to [contracts/README.md](contracts/README.md).

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
