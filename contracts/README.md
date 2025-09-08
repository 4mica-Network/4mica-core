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

# Local RPC (Anvil)
RPC_URL=http://127.0.0.1:8545

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
    --rpc-url $RPC_URL \
    --broadcast \
    --via-ir \
    -vvvv
```

**Example output:**
```yaml
Core4Mica deployed at: 0x1234abcd...
```
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
├── script/             # Deployment scripts
│   └── Core4Mica.s.sol
├── test/               # Foundry tests
├── .env                # Environment variables (ignored by git)
├── foundry.toml        # Foundry config
```

---

## 🧹 Cleanup

- Reset your `.env` if switching networks.
- **Never push your private key.**
- Use `forge clean` to wipe build artifacts.

