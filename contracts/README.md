# Core4Mica

This repository contains the **Core4Mica** smart contract, along with deployment and test setup using [Foundry](https://book.getfoundry.sh/).

---

## 📦 Requirements

- [Foundry](https://book.getfoundry.sh/getting-started/installation) (`forge`, `cast`, `anvil`)
- Node.js & npm (optional, for OpenZeppelin CLI or extra scripts)
- Local Ethereum node (recommended: `anvil`, bundled with Foundry)

> 🔒 **Authentication & Authorization:**  
> Access control in Core4Mica is managed using [OpenZeppelin AccessManager](https://docs.openzeppelin.com/contracts/5.x/access-control#access-management), providing robust role-based permissions for contract functions.

## ⚙️ Setup

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd <your-repo>
```

### 2. Install dependencies

```bash
forge install
```

### 3. Create a `.env` file

Place the `.env` file in the project root (next to `foundry.toml`).

**Example `.env`:**
```ini
# Private key of your deployer account (do not commit this!)
PRIVATE_KEY=0xabc123...deadbeef

# Deployment target RPC
DEPLOY_RPC_URL=http://127.0.0.1:8545

# Optional: Etherscan key for contract verification
ETHERSCAN_API_KEY=your-key-here
```

> ⚠️ **Never commit your real private key.**  
> For local testing, you can use the default Anvil keys.

---

## 🧪 Running Tests

Run all unit tests:

```bash
forge test -vvvv
```

- `-vvvv` = max verbosity (shows logs, gas, traces)
- Tests are located in the `test/` directory

Targeted guarantee versioning suites:

```bash
forge test --match-path test/Core4MicaGuaranteeVersions.t.sol
forge test --match-path test/ValidationRegistryGuaranteeDecoder.t.sol
forge test --match-path test/GuaranteeDecoderRouter.t.sol
```

---

## 🚀 Deploying Locally

### 1. Start a local node

```bash
anvil
```

- This prints 20 funded test accounts with their private keys.

### 2. Configure `.env`

Copy one private key into `.env` as `PRIVATE_KEY=...`.

### 3. Run the deployment script

```bash
forge script script/Core4Mica.s.sol:Core4MicaScript \
    --rpc-url $DEPLOY_RPC_URL \
    --broadcast \
    --via-ir \
    -vvvv
```

**Example output:**
```yaml
Core4Mica deployed at: 0x1234abcd...
```

### 3b. Full stack deploy (Core + guarantee decoders)

Deploys:
- `AccessManager`
- `Core4Mica`
- `GuaranteeDecoderRouter`
- `ValidationRegistryGuaranteeDecoder`

```bash
forge script script/Core4MicaFullStack.s.sol:Core4MicaFullStackScript \
    --rpc-url $DEPLOY_RPC_URL \
    --broadcast \
    --via-ir \
    -vvvv
```

Important env additions for full stack:
- Stablecoin setup (optional):
  - `STABLECOINS_COUNT` + `STABLECOIN_0..n-1`
- `TRUSTED_VALIDATION_REGISTRY` (single)
  or
- `TRUSTED_VALIDATION_REGISTRIES_COUNT` + `TRUSTED_VALIDATION_REGISTRY_0..n-1`
- `CREATE2_SALT` (optional; defaults to `4mica-core-v1`)
- `ACCESS_MANAGER_ADMIN` (optional; defaults to broadcaster)
- V2 is configured and enabled by default during full-stack deployment.
- V2 reuses the V1 guarantee key and derives its domain separator in-script.

### 4. Configure guarantee versions post-deploy

Router/module wiring:

```bash
forge script script/ConfigureGuaranteeRouter.s.sol:ConfigureGuaranteeRouterScript \
    --rpc-url $DEPLOY_RPC_URL \
    --broadcast \
    --via-ir \
    -vvvv
```

Core version config:

```bash
forge script script/ConfigureGuaranteeVersion.s.sol:ConfigureGuaranteeVersionScript \
    --rpc-url $DEPLOY_RPC_URL \
    --broadcast \
    --via-ir \
    -vvvv
```

Decoder-only deployment (with trusted-registry readback checks):

```bash
forge script script/DeployValidationRegistryGuaranteeDecoder.s.sol:DeployValidationRegistryGuaranteeDecoderScript \
    --rpc-url $DEPLOY_RPC_URL \
    --broadcast \
    --via-ir \
    -vvvv
```

`ConfigureGuaranteeVersion` supports reusing an existing key from another version:
- `GUARANTEE_REUSE_EXISTING_KEY=true`
- optional `GUARANTEE_KEY_SOURCE_VERSION` (defaults to `1`)

### Stablecoin configuration model

`Core4Mica` constructor no longer takes chain-specific token addresses.

- Constructor input is now chain-agnostic (`manager`, `verificationKey`) so bytecode can be deployed deterministically across chains.
- Stablecoins are configured post-deploy via admin calls:
  - `setStablecoinAsset(address asset, bool enabled)`
  - `setStablecoinAssets(address[] assets, bool enabled)`

Deployment scripts call `setStablecoinAssets(...)` automatically when `STABLECOINS_COUNT` and `STABLECOIN_<i>` env vars are provided.

For same-address deployment across chains, scripts now use deterministic deployment (`CREATE2`)
through the canonical deterministic deployer (`0x4e59...`) with:
- same `CREATE2_SALT`
- same init code (constructor args + bytecode)

If constructor inputs differ per chain (for example `ACCESS_MANAGER_ADMIN`, verification key, or trusted registry list), the resulting address will differ.

Runbook:
- `GUARANTEE_VERSIONING.md`
- `GUARANTEE_V2_ACTIVATION.md`
---

### 📜 Getting the ABI

To generate the ABI for your contracts, run:

```bash
forge build
```

This will compile your contracts and output the ABI files in the `out/` directory.  
For example, the ABI for `Core4Mica.sol` will be located at:

```
out/Core4Mica.sol/Core4Mica.json
```

The ABI is inside the `"abi"` field of this JSON file.

---

## 🔑 Role Management

The deployment script currently:

- Deploys an `AccessManager`
- Deploys `Core4Mica` managed by it

**Next step:**  
Extend the script to grant roles (e.g., `USER_ROLE`, `OPERATOR_ROLE`) so tests involving restricted functions don’t fail with `AccessManagedUnauthorized`.

**Example inside `Core4MicaScript.s.sol` after deploy:**
```solidity
manager.grantRole(USER_ROLE, deployer);
manager.grantRole(OPERATOR_ROLE, deployer);
```
This ensures the deployer account can interact with restricted functions.

---

## 📦 Current Deployment
> **Latest contracts deployed at:**  
> [https://holesky.4mica.xyz](https://holesky.4mica.xyz)

- **AccessManager**  
    Deployed at: `0x31676919335252527965da74b8dFFF589e23Ec81`

- **Core4Mica**  
    Deployed at: `0xFE4eae5d84412B70b1f04b3F78351a654D28Da25`


## 📂 Project Structure

```
├── src/                # Contracts
│   └── Core4Mica.sol
├── GUARANTEE_VERSIONING.md
├── script/             # Deployment scripts
│   ├── Core4Mica.s.sol
│   ├── Core4MicaFullStack.s.sol
│   ├── ConfigureGuaranteeVersion.s.sol
│   └── ConfigureGuaranteeRouter.s.sol
├── test/               # Foundry tests
├── .env                # Environment variables (ignored by git)
├── foundry.toml        # Foundry config
```

---

## 🧹 Cleanup

- Reset your `.env` if switching networks.
- **Never push your private key.**
- Use `forge clean` to wipe build artifacts.
