## ERC-8004 Validation-Gated Remuneration V2

### Overview

Introduces V2 guarantee claims that gate `Core4Mica.remunerate()` behind an on-chain ERC-8004 validation check, while preserving full backward compatibility for V1 clients. The version is always derived from the claim payload — no flag or env var controls which version is produced.

---

### What V2 adds

V1 guarantees are BLS-signed payment intents. `remunerate()` only verifies the BLS signature — there is no additional on-chain guard.

V2 embeds a **validation policy** in the signed claims. When `remunerate()` is called with a V2 cert, the `ValidationRegistryGuaranteeDecoder` calls an ERC-8004 `ValidationRegistry` contract and reverts unless:

- `lastUpdate > 0` (response exists)
- `response >= min_validation_score` (score threshold met)
- `validatorAddress` and `agentId` match what was committed in the claims
- `tag` matches `required_validation_tag` (if non-empty)
- `validation_subject_hash` and `validation_request_hash` are canonical (recomputed and verified on-chain — prevents any field from being tampered after signing)
- `validation_registry_address` is in the decoder's trusted allowlist

`responseHash == 0` is explicitly allowed — it is an optional field in ERC-8004 and not used as a pass signal.

---

### New types (`crates/rpc`)

**`PaymentGuaranteeValidationPolicyV2`**

| Field | Type | Purpose |
|---|---|---|
| `validation_registry_address` | `Address` | ERC-8004 registry to query |
| `validation_request_hash` | `bytes32` | Canonical commitment to the full policy (computed deterministically) |
| `validation_chain_id` | `u64` | Must equal core's chain; prevents cross-chain replay |
| `validator_address` | `Address` | Expected validator |
| `validator_agent_id` | `U256` | Expected agent within that validator |
| `min_validation_score` | `u8` | Threshold 1–100 (0 is rejected) |
| `validation_subject_hash` | `bytes32` | Canonical commitment to the payment intent fields |
| `job_hash` | `bytes32` | Required binding for the validation job |
| `required_validation_tag` | `String` | Optional tag the registry response must carry |

**`PaymentGuaranteeRequestClaimsV2`** — same base fields as V1 plus the policy above. Construction (builder or deserialization) validates that both hashes are canonical:

```
validation_subject_hash = keccak256(abi.encode(
    keccak256("4MICA_VALIDATION_SUBJECT_V1"),
    tabId, reqId, user, recipient, amount, asset, timestamp
))

validation_request_hash = keccak256(abi.encode(
    keccak256("4MICA_VALIDATION_REQUEST_V2"),
    chainId, registryAddress, validatorAddress, agentId,
    validationSubjectHash, minScore, keccak256(tag), jobHash
))
```

Both functions are exported from `rpc` and used identically by core, SDK, and contracts — there is one canonical formula.

**`PaymentGuaranteeRequestClaims` enum** — extended with `V2(PaymentGuaranteeRequestClaimsV2)`. New `.version() -> u64` method returns `1` or `2` from the variant; no external constant needed.

**`signing.rs`** (new) — `SolGuaranteeRequestClaimsV1` and `SolGuaranteeRequestClaimsV2` sol structs now live in the `rpc` crate and are re-exported. Previously they were defined identically in both `core/src/auth/mod.rs` and `sdk/src/digest.rs`.

---

### Core service changes

**Config (`core/src/config.rs`)**

- `GUARANTEE_REQUEST_VERSION` env var now populates `max_accepted_version` (renamed from `request_version`). The name clarifies it is the ceiling for the default accepted-version range, not the output version.
- `TRUSTED_VALIDATION_REGISTRIES` — comma-separated ERC-155 address allowlist. Required when any accepted version is V2+; validated at startup.
- `VALIDATION_HASH_CANONICALIZATION_VERSION` — must be `4MICA_VALIDATION_REQUEST_V2`; guards against future algorithm mismatches.

**Startup (`core/src/service/mod.rs`)**

For each accepted version, core calls `getGuaranteeVersionConfig(version)` on-chain and:
1. Rejects if `enabled == false`
2. Loads the `domain_separator` into `guarantee_domains: HashMap<u64, [u8; 32]>`

Setting `GUARANTEE_REQUEST_VERSION=2` makes core accept V1 and V2 (default range `1..=2`) and load both domain separators automatically.

`CorePublicParameters` (`/core/public-params`) now exposes:

| New field | Purpose |
|---|---|
| `max_accepted_guarantee_version` | SDK uses as ceiling for default version range |
| `accepted_guarantee_versions` | Explicit list |
| `active_guarantee_domain_separator` | Domain at `max_accepted_version` |
| `trusted_validation_registries` | SDK picks first entry as default registry |
| `validation_hash_canonicalization_version` | SDK alignment check |

**Issuance (`core/src/service/guarantee.rs`)**

V2 verification runs all V1 checks (duplicate, tab status, address match, timestamp window) then additionally:
- Recomputes and validates both hashes (`claims.validate()`)
- Checks `validation_registry_address` is in the trusted allowlist
- Checks `validation_chain_id == core chain_id`

**The output version is derived from the claim payload** (`req.claims.version()`). V1 request → V1 cert. V2 request → V2 cert. The env var has no effect on which version is issued.

**Signature verification (`core/src/auth/mod.rs`)**

EIP-712 and EIP-191 digest functions dispatch on the claims variant. V2 includes all 15 fields in the signed struct. Any post-signing mutation to any validation policy field breaks the signature.

---

### Contract changes

**`ValidationRegistryGuaranteeDecoder.sol`** (new)

Implements `IGuaranteeDecoder.decode(bytes)`. Decodes the V2 ABI payload, recomputes both hashes on-chain, verifies registry trust, calls `ValidationRegistry.getValidationStatus(validation_request_hash)`, and enforces all policy constraints before returning the `Guarantee` struct.

**`GuaranteeDecoderRouter.sol`** (new)

Routes `decode()` to the correct decoder by version. V1 → simple decoder (existing behavior). V2 → `ValidationRegistryGuaranteeDecoder`.

**`Core4MicaFullStack.s.sol`** (new deployment script)

Deploys the full stack in a single run: `AccessManager` + `Core4Mica` + `GuaranteeDecoderRouter` + `ValidationRegistryGuaranteeDecoder`.

---

### SDK changes (`sdk/`)

**`sdk/src/guarantee.rs`** — `prepare_payment_guarantee_claims()` reads `accepted_guarantee_versions_or_default()` from core's public params:

- `validation: None` + V1 accepted → V1 claims
- `validation: Some(...)` + any validation-gated version accepted → V2 claims
- `validation: Some(...)` + no validation-gated version accepted → error
- `validation: None` + only validation-gated versions accepted → error

Callers do not pick a version number; they signal intent by passing or omitting `PaymentGuaranteeValidationInput`.

**`sdk/src/client/recipient.rs`** — `verify_payment_guarantee()` uses the version embedded in the decoded cert to select the correct domain separator. V2 certs expose `PaymentGuaranteeClaims.validation_policy` to the caller. `issue_payment_guarantee` and `issue_payment_guarantee_v2` both delegate to a shared private `issue_inner` helper.

**`sdk/src/client/mod.rs`** — `fetch_guarantee_metadata()` populates `guarantee_domains: HashMap<u64, [u8; 32]>` for all versions advertised by core.

---

### CI changes (`.github/workflows/ci.yml`)

- `actions-rs/toolchain@v1` (deprecated) → `dtolnay/rust-toolchain@stable` across all jobs
- Clippy now runs with `-D warnings` (was previously missing, causing local/CI divergence)
- Contract deployment uses `Core4MicaFullStack.s.sol:Core4MicaFullStackScript` (replaces V1-only script)
- All service steps set `GUARANTEE_REQUEST_VERSION=2` and `TRUSTED_VALIDATION_REGISTRIES`

---

### Rollout notes

- V1 clients require no changes. Core accepts both versions simultaneously.
- To activate V2: deploy the contracts via `Core4MicaFullStack.s.sol`, add `TRUSTED_VALIDATION_REGISTRY` to CI/environment secrets, set `GUARANTEE_REQUEST_VERSION=2`.
- To gate a specific core instance to V2 only: set `GUARANTEE_ACCEPTED_REQUEST_VERSIONS=2`.
- Rollback to V1 only: set `GUARANTEE_REQUEST_VERSION=1` (no contract change needed).
