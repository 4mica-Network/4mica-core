# Contributing to 4Mica Core

First off, thank you for taking the time to contribute! 🚀  
We welcome all kinds of contributions: bug reports, feature requests, code, documentation, tests, and more.

---

## 📦 Development Setup

#### 1. Clone the repository:

   ```bash
   git clone --recurse-submodules git@github.com:4mica-Network/4mica-core.git
   cd 4mica-core
   ```

#### 2. Install prerequisites:
   - Rust (stable)
   - Docker
   - Foundry (for Solidity tests)

#### 3. Enable git hooks:

   ```bash
   git config core.hooksPath .githooks
   ```

   This installs a pre-push hook that runs `cargo fmt --check` and `cargo clippy` before every push.

### 4. Code Style

- **Formatting:** Run `cargo fmt` before committing.  
- **Linting:** Run `cargo clippy --workspace --all-targets --all-features` and fix warnings.  

#### Testing

The integration tests need a local stack (Postgres + Anvil + deployed contracts),
which is orchestrated through the `Makefile`. The two suites require different setups,
so don't run them with a single `cargo test`:

- **Core tests** must run with **no external `core-service` running** — each test builds
  its own in-process `CoreService` (and chain tests spawn their own Anvil), so a
  long-lived service would race the in-process event scanner on the shared database.
  They only need infra:

  ```bash
  make infra-up     # pg + anvil + contracts + migrations, NOT core-service
  make test-core
  ```

- **SDK e2e tests** talk to a running `core-service` on `:3000`, so bring the full
  stack up first:

  ```bash
  make dev-up
  make test-sdk
  ```

`make test` runs both in the correct order (infra → `test-core` with core down → full
stack → `test-sdk` with core up). Use `make dev-down` (or `dev-down-all`) to tear the
stack back down, and `make help` for the full list of targets.

Solidity contracts should be tested with Foundry:

```bash
cd contracts
forge test -vvvv
```

### 5. ✅ Pull Request Process

1. Fork the repo and create a feature branch:

   ```bash
   git checkout -b feature/my-new-feature
   ```
2. Make sure your changes pass:
    ```bash
    cargo fmt
    cargo clippy
    make test       # core tests (core down) + sdk e2e (core up)
    forge test      # for contracts (run from contracts/)
    ```
3. Commit with clear messages following [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)Conventional Commits
    ```scss
    feat(core): add new API endpoint
    fix(contract): resolve overflow issue
    ```
4. Push your branch and open a Pull Request against `develop`.
