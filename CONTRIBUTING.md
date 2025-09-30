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
   - Node.js (v20 or newer)
   - Foundry (for Solidity tests)

### 3. Code Style

- **Formatting:** Run `cargo fmt` before committing.  
- **Linting:** Run `cargo clippy --workspace --all-targets --all-features` and fix warnings.  
- **Testing:** Run `cargo test --workspace -- --test-threads=1` to ensure all tests pass.  

Solidity contracts should be tested with Foundry:

```bash
cd contracts
forge test -vvvv
```

### 4. ✅ Pull Request Process

1. Fork the repo and create a feature branch:

   ```bash
   git checkout -b feature/my-new-feature
   ```
2. Make sure your changes pass:
    ```bash
    cargo fmt
    cargo clippy
    cargo test
    forge test   # for contracts
    ```
3. Commit with clear messages following [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)Conventional Commits
    ```scss
    feat(core): add new API endpoint
    fix(contract): resolve overflow issue
    ```
4. Push your branch and open a Pull Request against `develop`.
