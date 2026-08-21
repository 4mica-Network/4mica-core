use alloy::sol;

pub mod utils;

sol! {
    #[sol(rpc)]
    contract Core4Mica {
        error AmountZero();
        error InsufficientAvailable();
        error TransferFailed();
        error GracePeriodNotElapsed();
        error NoWithdrawalRequested();
        error DirectTransferNotAllowed();
        error InvalidSignature();
        error InvalidRecipient();
        error UnsupportedAsset(address asset);
        error InvalidAsset(address asset);
        error UnsupportedGuaranteeVersion(uint64 version);
        error InvalidGuaranteeDomain();
        error MissingGuaranteeDecoder(uint64 version);
        error AaveNotConfigured();
        error FeeTooHigh();
        error TreasuryClaimExceedsAvailable();
        error UnsupportedTreasuryAsset(address asset);
        error StablecoinWithdrawShortfall(address asset, uint256 requested, uint256 actual);
        error AaveProviderReconfigurationBlocked();
        error UserScaledBalanceUnderflow(address asset, address user, uint256 deduction, uint256 balance);
        error ZeroAddress();
        error InvalidAToken(address asset, address aToken);
        error ReconciliationLoss(address asset, uint256 tracked, uint256 observed);
        error SurplusClaimExceedsAvailable();
        /// The deposited asset delivered less than `expected` (fee-on-transfer tokens), or a
        /// native-value deposit did not match `msg.value`.
        error ValueMismatch(uint256 expected, uint256 actual);
        /// `amount` was too small to mint any scaled collateral.
        error ZeroCollateralCredit(address asset, uint256 amount);
        error EscrowScaledUnderflow(address asset, uint256 requested, uint256 available);
        error AuthorizationExpired(uint256 validBefore);
        error AuthorizationNotYetValid(uint256 validAfter);
        error AuthorizationAlreadyUsed(address user, bytes32 nonce);

        function withdrawalGracePeriod() external view returns (uint256);
        function aaveAddressesProvider() external view returns (address);
        function yieldFeeBps() external view returns (uint256);

        /// TODO(#22): move key to registry
        function GUARANTEE_VERIFICATION_KEY() external view returns (
            bytes32 x1, bytes32 x2, bytes32 y1, bytes32 y2
        );

        event CollateralDeposited(address indexed user, address indexed asset, uint256 amount);
        event CollateralWithdrawn(address indexed user, address indexed asset, uint256 amount);
        event WithdrawalRequested(address indexed user, address indexed asset, uint256 when, uint256 amount);
        event WithdrawalCanceled(address indexed user, address indexed asset);
        event AuthorizationUsed(address indexed user, bytes32 indexed nonce);
        event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);
        event VerificationKeyUpdated((bytes32,bytes32,bytes32,bytes32) newVerificationKey);
        event GuaranteeVersionUpdated(
            uint64 indexed version,
            (bytes32,bytes32,bytes32,bytes32) verificationKey,
            bytes32 domainSeparator,
            address decoder,
            bool enabled
        );
        event StablecoinAssetUpdated(address indexed asset, bool enabled);
        event AaveConfigured(address indexed provider, address indexed pool);
        event YieldFeeBpsUpdated(uint256 oldFeeBps, uint256 newFeeBps);
        event ProtocolYieldClaimed(address indexed asset, address indexed to, uint256 amount);
        event SurplusATokensClaimed(
            address indexed asset,
            address indexed to,
            uint256 scaledAmount,
            uint256 nominalAmount
        );

        struct WithdrawalRequest {
            uint256 timestamp;
            uint256 amount;
        }

        struct UserAssetInfo {
            address asset;
            uint256 collateral;
            uint256 withdrawalRequestTimestamp;
            uint256 withdrawalRequestAmount;
        }

        struct Guarantee {
            bytes32 domain;
            uint256 cycleId;
            uint256 reqId;
            address client;
            address recipient;
            uint256 amount;
            address asset;
            uint64 timestamp;
            uint64 version;
        }

        struct G1Point {
            bytes32 x_a;
            bytes32 x_b;
            bytes32 y_a;
            bytes32 y_b;
        }

        struct G2Point {
            bytes32 x_c0_a;
            bytes32 x_c0_b;
            bytes32 x_c1_a;
            bytes32 x_c1_b;
            bytes32 y_c0_a;
            bytes32 y_c0_b;
            bytes32 y_c1_a;
            bytes32 y_c1_b;
        }

        /// A client's EIP-3009 authorization to move the deposit amount from `from` into the
        /// Core4Mica contract. Any caller may submit it; collateral is credited to `from`, the
        /// signer, never `msg.sender`.
        ///
        /// Serde-encoded with alloy's `0x`-hex representation so a facilitator can accept one
        /// straight off an HTTP request body.
        #[derive(Debug, serde::Serialize, serde::Deserialize)]
        struct ReceiveAuthorization {
            address from;
            uint256 validAfter;
            uint256 validBefore;
            bytes32 nonce;
            uint8 v;
            bytes32 r;
            bytes32 s;
        }

        /// A client's Permit2 `PermitTransferFrom` authorization to move the deposit amount from
        /// `from` into the Core4Mica contract via the canonical Permit2 contract. Any caller may
        /// submit it; collateral is credited to `from`, the signer, never `msg.sender`. Requires a
        /// one-time ERC-20 approval from `from` to Permit2 for the deposited asset.
        #[derive(Debug, serde::Serialize, serde::Deserialize)]
        struct Permit2Authorization {
            address from;
            uint256 nonce;
            uint256 deadline;
            bytes signature;
        }

        /// A user's EIP-712 authorization to open a withdrawal request on their behalf. Any caller
        /// may submit it; the request is recorded against `user`, the signer, never `msg.sender`.
        /// `asset` is `address(0)` for ETH.
        ///
        /// `signature` covers every other field, so a submitter can alter none of them.
        #[derive(Debug, serde::Serialize, serde::Deserialize)]
        struct WithdrawalRequestAuthorization {
            address user;
            address asset;
            uint256 amount;
            uint256 validAfter;
            uint256 validBefore;
            bytes32 nonce;
            bytes signature;
        }

        /// A user's EIP-712 authorization to cancel their pending withdrawal request for `asset`.
        /// Shares its nonce namespace with [`WithdrawalRequestAuthorization`].
        #[derive(Debug, serde::Serialize, serde::Deserialize)]
        struct WithdrawalCancelAuthorization {
            address user;
            address asset;
            uint256 validAfter;
            uint256 validBefore;
            bytes32 nonce;
            bytes signature;
        }

        /// @param manager Address of AccessManager
        /// @param verificationKey Initial BLS verification key
        constructor(
            address manager,
            (bytes32,bytes32,bytes32,bytes32) verificationKey,
            address[] memory stablecoins_
        );

        function deposit() external payable;
        function depositStablecoin(address asset, uint256 amount) external;
        /// Gasless deposit: a third party (e.g. a facilitator sponsoring gas) submits an
        /// EIP-3009 `receiveWithAuthorization` signature; collateral is credited to `auth.from`.
        function depositStablecoinWithAuthorization(address asset, uint256 amount, ReceiveAuthorization calldata auth) external;
        /// Gasless deposit via Permit2: a third party submits a `PermitTransferFrom` signature;
        /// collateral is credited to `p.from`. Works for any ERC-20 with a prior Permit2 approval.
        function depositStablecoinWithPermit2(address asset, uint256 amount, Permit2Authorization calldata p) external;
        function requestWithdrawal(uint256 amount) external;
        function requestWithdrawal(address asset, uint256 amount) external;
        function cancelWithdrawal() external;
        function cancelWithdrawal(address asset) external;
        function finalizeWithdrawal() external;
        function finalizeWithdrawal(address asset) external;

        /// Gasless withdrawal request: a third party submits the user's EIP-712 signature and the
        /// request is recorded against `auth.user`.
        function requestWithdrawalWithAuthorization(WithdrawalRequestAuthorization calldata auth) external;
        /// Gasless cancellation of `auth.user`'s pending request.
        function cancelWithdrawalWithAuthorization(WithdrawalCancelAuthorization calldata auth) external;
        /// Permissionless finalization. Pays `user`, so no signature is needed — and requiring one
        /// would mean the user must be around a grace period after requesting.
        function finalizeWithdrawalFor(address user, address asset) external;

        /// Core4Mica's own EIP-712 domain separator, for building withdrawal-authorization digests.
        function DOMAIN_SEPARATOR() external view returns (bytes32);
        /// True once `nonce` has been spent by one of `user`'s authorizations.
        function authorizationState(address user, bytes32 nonce) external view returns (bool);
        function REQUEST_WITHDRAWAL_TYPEHASH() external view returns (bytes32);
        function CANCEL_WITHDRAWAL_TYPEHASH() external view returns (bytes32);

        function setWithdrawalGracePeriod(uint256 _gracePeriod) external;
        function setGuaranteeVerificationKey((bytes32,bytes32,bytes32,bytes32) verificationKey) external;
        function configureGuaranteeVersion(uint64 version, (bytes32,bytes32,bytes32,bytes32) verificationKey, bytes32 domainSeparator, address decoder, bool enabled) external;
        function configureAave(address poolAddressesProvider, address[] calldata aTokens) external;
        function addStablecoinAsset(address asset, address aToken) external;
        function setYieldFeeBps(uint256 feeBps) external;
        function claimProtocolYield(address asset, address to, uint256 amount) external;
        function claimSurplusATokens(address asset, address to, uint256 scaledAmount) external;
        function getGuaranteeVersionConfig(uint64 version)
            external
            view
            returns (
                G1Point memory verificationKey,
                bytes32 domainSeparator,
                address decoder,
                bool enabled
            );
        function getUserAllAssets(address userAddr)
            external
            view
            returns (UserAssetInfo[] memory);

        function getERC20Tokens() external view returns (address[] memory);

        function guaranteeDomainSeparator() external view returns (bytes32);
        function verifyAndDecodeGuarantee(
            bytes memory guarantee,
            G2Point memory signature
        ) external view returns (Guarantee memory);

        function collateral(address userAddr) external view returns (uint256);
        function collateral(address userAddr, address asset) external view returns (uint256);
        function principalBalance(address user, address asset) external view returns (uint256);
        function guaranteeCapacity(address user, address asset) external view returns (uint256);
        function grossYield(address user, address asset) external view returns (uint256);
        function protocolYieldShare(address user, address asset) external view returns (uint256);
        function userNetYield(address user, address asset) external view returns (uint256);
        function withdrawableBalance(address user, address asset) external view returns (uint256);
        function totalUserScaledBalance(address asset) external view returns (uint256);
        function protocolScaledBalance(address asset) external view returns (uint256);
        function surplusScaledBalance(address asset) external view returns (uint256);
        function contractScaledATokenBalance(address asset) external view returns (uint256);
        function reconciliationDustToleranceScaled() external view returns (uint256);
        function stablecoinAToken(address asset) external view returns (address);

        function getUser(address userAddr) external view returns (
            uint256 assetCollateral,
            uint256 withdrawalRequestTimestamp,
            uint256 withdrawalRequestAmount
        );
        function getUser(address userAddr, address asset) external view returns (
            uint256 assetCollateral,
            uint256 withdrawalRequestTimestamp,
            uint256 withdrawalRequestAmount
        );
    }
}

sol! {
    #[sol(rpc)]
    contract ERC20 {
        event Transfer(address indexed from, address indexed to, uint256 amount);
        event Approval(address indexed owner, address indexed spender, uint256 amount);

        constructor(string memory name_, string memory symbol_);

        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function transfer(address to, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        /// EIP-712 domain separator, exposed by EIP-2612/EIP-3009 tokens (e.g. USDC). Used to build
        /// the gasless-deposit signing hash without reconstructing name/version/chainId.
        function DOMAIN_SEPARATOR() external view returns (bytes32);
    }
}

/// Canonical Permit2 contract, deployed at the same address on every supported chain.
pub const PERMIT2_ADDRESS: alloy::primitives::Address =
    alloy::primitives::address!("000000000022D473030F116dDEE9F6B43aC78BA3");

sol! {
    #[sol(rpc)]
    contract Permit2 {
        /// Permit2's own EIP-712 domain separator, used to build the Permit2 gasless-deposit hash.
        function DOMAIN_SEPARATOR() external view returns (bytes32);
    }
}

sol! {
    #[sol(rpc)]
    contract ClearingHouse {
        /// Same shape as [`Core4Mica::ReceiveAuthorization`]; redeclared because `sol!` blocks
        /// cannot share types.
        #[derive(Debug, serde::Serialize, serde::Deserialize)]
        struct ReceiveAuthorization {
            address from;
            uint256 validAfter;
            uint256 validBefore;
            bytes32 nonce;
            uint8 v;
            bytes32 r;
            bytes32 s;
        }

        /// Same shape as [`Core4Mica::Permit2Authorization`]; redeclared because `sol!` blocks
        /// cannot share types.
        #[derive(Debug, serde::Serialize, serde::Deserialize)]
        struct Permit2Authorization {
            address from;
            uint256 nonce;
            uint256 deadline;
            bytes signature;
        }

        function payNetDebit(bytes32 cycleId, uint256 netDebit, bytes32[] calldata proof) external payable;
        /// Sponsored debit payment: a third party submits the debtor's EIP-3009 signature and the
        /// exact net debit is pulled from `auth.from`'s wallet. `auth.nonce` must equal `cycleId`.
        function payNetDebitWithAuthorization(bytes32 cycleId, uint256 netDebit, bytes32[] calldata proof, ReceiveAuthorization calldata auth) external;
        /// Sponsored debit payment via Permit2: a third party submits the debtor's
        /// `PermitTransferFrom` signature and the exact net debit is pulled from `p.from`'s
        /// wallet. `p.nonce` must equal `uint256(cycleId)`.
        function payNetDebitWithPermit2(bytes32 cycleId, uint256 netDebit, bytes32[] calldata proof, Permit2Authorization calldata p) external;
        function claimNetCreditFor(address creditor, bytes32 cycleId, uint256 netCredit, bytes32[] calldata proof) external;
    }
}
