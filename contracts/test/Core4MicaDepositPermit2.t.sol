// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Core4MicaTestBase, MockERC20} from "./Core4MicaTestBase.sol";
import {MockAToken} from "./helpers/MockAave.sol";
import {Core4Mica, Permit2Authorization} from "../src/Core4Mica.sol";

interface IERC20Like {
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);
}

/// ERC-20 that skims a fee on every transfer, so a Permit2 pull delivers less than the requested
/// amount. Used to prove the deposit path rejects short-delivering tokens.
contract MockERC20FeeOnTransfer is MockERC20 {
    uint256 internal immutable feeBps;

    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        uint256 feeBps_
    ) MockERC20(name_, symbol_, decimals_) {
        feeBps = feeBps_;
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        uint256 fee = (amount * feeBps) / 10_000;
        require(balanceOf[from] >= amount, "BALANCE");
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
        totalSupply -= fee;
        emit Transfer(from, to, amount - fee);
    }
}

/// Minimal Permit2 `SignatureTransfer` mock, mirroring the canonical Permit2's `permitTransferFrom`
/// EIP-712 domain and witness. It is `vm.etch`ed at the canonical Permit2 address so `Core4Mica`'s
/// hardcoded `PERMIT2` constant resolves to it. Signatures are real EIP-712 digests verified via
/// `ecrecover`; nonces model unordered replay protection with a simple used-flag.
contract MockPermit2 {
    // owner => nonce => used
    mapping(address => mapping(uint256 => bool)) public usedNonce;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
        );
    bytes32 private constant TOKEN_PERMISSIONS_TYPEHASH =
        keccak256("TokenPermissions(address token,uint256 amount)");
    // Permit2's PermitTransferFrom witness — note the trailing nested TokenPermissions type string.
    bytes32 private constant PERMIT_TRANSFER_FROM_TYPEHASH =
        keccak256(
            "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
        );

    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    // Permit2's domain omits `version`.
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    DOMAIN_TYPEHASH,
                    keccak256(bytes("Permit2")),
                    block.chainid,
                    address(this)
                )
            );
    }

    function permitTransferFrom(
        PermitTransferFrom calldata permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external {
        // forge-lint: disable-next-line(block-timestamp)
        require(
            block.timestamp <= permit.deadline,
            "Permit2: signature expired"
        );
        require(
            transferDetails.requestedAmount <= permit.permitted.amount,
            "Permit2: amount exceeds permission"
        );
        require(!usedNonce[owner][permit.nonce], "Permit2: nonce used");

        bytes32 tokenPermissions = keccak256(
            abi.encode(
                TOKEN_PERMISSIONS_TYPEHASH,
                permit.permitted.token,
                permit.permitted.amount
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TRANSFER_FROM_TYPEHASH,
                tokenPermissions,
                msg.sender, // spender is the caller (Core4Mica), bound into the signed digest
                permit.nonce,
                permit.deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash)
        );

        (bytes32 r, bytes32 s, uint8 v) = _split(signature);
        require(
            ecrecover(digest, v, r, s) == owner,
            "Permit2: invalid signature"
        );

        usedNonce[owner][permit.nonce] = true;
        require(
            IERC20Like(permit.permitted.token).transferFrom(
                owner,
                transferDetails.to,
                transferDetails.requestedAmount
            ),
            "Permit2: transfer failed"
        );
    }

    function _split(
        bytes calldata sig
    ) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Permit2: bad signature length");
        r = bytes32(sig[0:32]);
        s = bytes32(sig[32:64]);
        v = uint8(sig[64]);
    }
}

contract Core4MicaDepositPermit2Test is Core4MicaTestBase {
    // Canonical Permit2 address, matching `Core4Mica.PERMIT2`.
    address internal constant PERMIT2 =
        0x000000000022D473030F116dDEE9F6B43aC78BA3;

    // Client that signs the Permit2 authorization (has a real key so we can sign).
    uint256 internal constant SIGNER_PK = 0xA11CE;
    address internal signer;
    // Third party that submits the tx and pays gas — must NOT be credited.
    address internal constant FACILITATOR = address(0xFACADE);

    uint256 internal constant AMOUNT = 1_000 ether;

    function setUp() public override {
        super.setUp();
        signer = vm.addr(SIGNER_PK);

        // Place the Permit2 mock at the canonical address the contract calls into.
        vm.etch(PERMIT2, address(new MockPermit2()).code);

        // `usdc` from the base is a plain ERC-20 already registered as a supported stablecoin.
        usdc.mint(signer, 10_000 ether);
        // The one-time ERC-20 approval Permit2 requires (the single on-chain step for the payer).
        vm.prank(signer);
        usdc.approve(PERMIT2, type(uint256).max);
    }

    function _permit2Domain() internal view returns (bytes32) {
        return MockPermit2(PERMIT2).DOMAIN_SEPARATOR();
    }

    function _authorization(
        address token,
        uint256 permittedAmount,
        uint256 deadline,
        uint256 nonce
    ) internal view returns (Permit2Authorization memory auth) {
        bytes32 tokenPermissions = keccak256(
            abi.encode(
                keccak256("TokenPermissions(address token,uint256 amount)"),
                token,
                permittedAmount
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
                ),
                tokenPermissions,
                address(core4Mica), // spender
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _permit2Domain(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, digest);
        auth = Permit2Authorization({
            from: signer,
            nonce: nonce,
            deadline: deadline,
            signature: abi.encodePacked(r, s, v)
        });
    }

    function _validAuthorization(
        uint256 permittedAmount,
        uint256 nonce
    ) internal view returns (Permit2Authorization memory) {
        return
            _authorization(
                address(usdc),
                permittedAmount,
                block.timestamp + 1 hours,
                nonce
            );
    }

    /// Sign a Permit2 permit with an arbitrary key, `from`, and `spender`, so tests can forge
    /// wrong-signer / wrong-spender cases.
    function _authorizationFull(
        uint256 pk,
        address from,
        address spender,
        address token,
        uint256 permittedAmount,
        uint256 deadline,
        uint256 nonce
    ) internal view returns (Permit2Authorization memory auth) {
        bytes32 tokenPermissions = keccak256(
            abi.encode(
                keccak256("TokenPermissions(address token,uint256 amount)"),
                token,
                permittedAmount
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
                ),
                tokenPermissions,
                spender,
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _permit2Domain(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        auth = Permit2Authorization({
            from: from,
            nonce: nonce,
            deadline: deadline,
            signature: abi.encodePacked(r, s, v)
        });
    }

    /// The core guarantee: a third party submits the tx, but the *signer* is credited.
    function test_DepositWithPermit2_CreditsSignerNotSubmitter() public {
        Permit2Authorization memory auth = _validAuthorization(AMOUNT, 1);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralDeposited(signer, address(usdc), AMOUNT);

        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT, auth);

        // Collateral credited to the signer, not the facilitator.
        assertEq(
            core4Mica.collateral(signer, address(usdc)),
            AMOUNT,
            "signer collateral"
        );
        assertEq(
            core4Mica.collateral(FACILITATOR, address(usdc)),
            0,
            "facilitator must not be credited"
        );

        // Funds pulled from the signer and supplied into Aave; facilitator balance untouched.
        assertEq(
            usdc.balanceOf(signer),
            10_000 ether - AMOUNT,
            "signer debited"
        );
        assertEq(
            usdc.balanceOf(FACILITATOR),
            0,
            "facilitator balance unchanged"
        );
        assertEq(
            usdc.balanceOf(address(core4Mica)),
            0,
            "contract forwards to pool"
        );
        assertEq(
            usdc.balanceOf(address(mockPool)),
            AMOUNT,
            "pool holds supply"
        );
    }

    function test_DepositWithPermit2_AccumulatesAcrossDeposits() public {
        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithPermit2(
            address(usdc),
            AMOUNT,
            _validAuthorization(AMOUNT, 1)
        );
        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithPermit2(
            address(usdc),
            500 ether,
            _validAuthorization(500 ether, 2)
        );

        assertEq(
            core4Mica.collateral(signer, address(usdc)),
            AMOUNT + 500 ether,
            "accumulated collateral"
        );
    }

    function test_DepositWithPermit2_RevertReplayedNonce() public {
        Permit2Authorization memory auth = _validAuthorization(AMOUNT, 7);

        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT, auth);

        // Same authorization cannot be redeemed twice — Permit2 marks the nonce used.
        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("Permit2: nonce used"));
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT, auth);
    }

    function test_DepositWithPermit2_RevertExpiredDeadline() public {
        Permit2Authorization memory auth = _authorization(
            address(usdc),
            AMOUNT,
            block.timestamp + 1,
            3
        );
        vm.warp(block.timestamp + 2);

        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("Permit2: signature expired"));
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT, auth);
    }

    /// A mismatch between the on-chain `amount` and the signed `permitted.amount` breaks the signature,
    /// so Permit2 rejects it — the caller cannot inflate the deposit beyond what the user authorized.
    function test_DepositWithPermit2_RevertAmountExceedsSignedPermission()
        public
    {
        Permit2Authorization memory auth = _validAuthorization(AMOUNT, 4);

        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("Permit2: invalid signature"));
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT + 1, auth);
    }

    /// An unsupported asset is rejected by the `stablecoin` modifier before Permit2 is ever called.
    function test_DepositWithPermit2_RevertUnsupportedAsset() public {
        MockERC20 fake = new MockERC20("Fake", "FAKE", 6);
        Permit2Authorization memory auth = _authorization(
            address(fake),
            AMOUNT,
            block.timestamp + 1 hours,
            5
        );

        vm.prank(FACILITATOR);
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UnsupportedAsset.selector,
                address(fake)
            )
        );
        core4Mica.depositStablecoinWithPermit2(address(fake), AMOUNT, auth);
    }

    function test_DepositWithPermit2_RevertAmountZero() public {
        Permit2Authorization memory auth = _validAuthorization(0, 6);

        vm.prank(FACILITATOR);
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.depositStablecoinWithPermit2(address(usdc), 0, auth);
    }

    function test_DepositWithPermit2_RevertWhenPaused() public {
        core4Mica.pause();
        Permit2Authorization memory auth = _validAuthorization(AMOUNT, 8);

        vm.prank(FACILITATOR);
        vm.expectRevert();
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT, auth);
    }

    // ========================= Edge cases =========================

    uint256 internal constant SIGNER2_PK = 0xB0B;

    /// Without the one-time ERC-20 approval to Permit2, the pull fails at the token allowance check.
    function test_DepositWithPermit2_RevertNoPermit2Approval() public {
        uint256 pk = 0xC0DE;
        address noApprove = vm.addr(pk);
        usdc.mint(noApprove, 10_000 ether); // has balance, but never approved Permit2

        Permit2Authorization memory auth = _authorizationFull(
            pk,
            noApprove,
            address(core4Mica),
            address(usdc),
            AMOUNT,
            block.timestamp + 1 hours,
            20
        );
        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("ALLOWANCE"));
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT, auth);
    }

    /// Approved Permit2 but insufficient token balance → the pull reverts.
    function test_DepositWithPermit2_RevertInsufficientBalance() public {
        uint256 pk = 0xD00D;
        address broke = vm.addr(pk);
        vm.prank(broke);
        usdc.approve(PERMIT2, type(uint256).max); // approves but has zero balance

        Permit2Authorization memory auth = _authorizationFull(
            pk,
            broke,
            address(core4Mica),
            address(usdc),
            AMOUNT,
            block.timestamp + 1 hours,
            21
        );
        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("BALANCE"));
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT, auth);
    }

    /// A tampered signature no longer recovers to the owner.
    function test_DepositWithPermit2_RevertTamperedSignature() public {
        Permit2Authorization memory auth = _validAuthorization(AMOUNT, 22);
        auth.signature[10] = bytes1(uint8(auth.signature[10]) ^ 0x01); // flip a bit in r

        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("Permit2: invalid signature"));
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT, auth);
    }

    /// A signature from a key other than `from` is rejected.
    function test_DepositWithPermit2_RevertWrongSigner() public {
        // Signed by SIGNER2_PK but claims `from = signer`.
        Permit2Authorization memory auth = _authorizationFull(
            SIGNER2_PK,
            signer,
            address(core4Mica),
            address(usdc),
            AMOUNT,
            block.timestamp + 1 hours,
            23
        );

        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("Permit2: invalid signature"));
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT, auth);
    }

    /// A permit signed for a different spender cannot be redeemed through Core4Mica (spender is bound).
    function test_DepositWithPermit2_RevertWrongSpender() public {
        address otherSpender = address(0xBEEF);
        Permit2Authorization memory auth = _authorizationFull(
            SIGNER_PK,
            signer,
            otherSpender,
            address(usdc),
            AMOUNT,
            block.timestamp + 1 hours,
            24
        );

        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("Permit2: invalid signature"));
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT, auth);
    }

    /// Two independent signers keep isolated balances.
    function test_DepositWithPermit2_TwoSignersIsolated() public {
        address signer2 = vm.addr(SIGNER2_PK);
        usdc.mint(signer2, 10_000 ether);
        vm.prank(signer2);
        usdc.approve(PERMIT2, type(uint256).max);

        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithPermit2(
            address(usdc),
            AMOUNT,
            _validAuthorization(AMOUNT, 25)
        );

        Permit2Authorization memory auth2 = _authorizationFull(
            SIGNER2_PK,
            signer2,
            address(core4Mica),
            address(usdc),
            300 ether,
            block.timestamp + 1 hours,
            26
        );
        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithPermit2(address(usdc), 300 ether, auth2);

        assertEq(
            core4Mica.collateral(signer, address(usdc)),
            AMOUNT,
            "signer 1 isolated"
        );
        assertEq(
            core4Mica.collateral(signer2, address(usdc)),
            300 ether,
            "signer 2 isolated"
        );
    }

    /// A deadline exactly equal to the current timestamp is still valid (`now <= deadline`).
    function test_DepositWithPermit2_DeadlineExactBoundarySucceeds() public {
        Permit2Authorization memory auth = _authorizationFull(
            SIGNER_PK,
            signer,
            address(core4Mica),
            address(usdc),
            AMOUNT,
            block.timestamp,
            27
        );

        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithPermit2(address(usdc), AMOUNT, auth);
        assertEq(
            core4Mica.collateral(signer, address(usdc)),
            AMOUNT,
            "deposit at deadline boundary"
        );
    }

    /// A dust permit that mints zero scaled aTokens is rejected (audit L-1) on the Permit2 path too.
    function test_DepositWithPermit2_RevertZeroScaledCredit() public {
        mockPool.setNormalizedIncome(address(usdc), 2e27);
        Permit2Authorization memory auth = _validAuthorization(1, 28);

        vm.prank(FACILITATOR);
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.ZeroCollateralCredit.selector,
                address(usdc),
                1
            )
        );
        core4Mica.depositStablecoinWithPermit2(address(usdc), 1, auth);
    }

    /// A token that reports success while delivering less than the requested amount (fee-on-transfer)
    /// is rejected by the balance-delta check, so no unbacked principal is ever credited.
    function test_DepositWithPermit2_RevertShortDelivery() public {
        MockERC20FeeOnTransfer feeToken = new MockERC20FeeOnTransfer(
            "USD Coin",
            "USDC",
            6,
            100
        ); // 1% fee
        MockAToken feeAToken = new MockAToken(
            address(feeToken),
            address(mockPool),
            "Aave USDC",
            "aUSDC"
        );
        mockPool.setReserve(address(feeToken), address(feeAToken), 1e27);
        mockDataProvider.setReserveAToken(
            address(feeToken),
            address(feeAToken)
        );
        core4Mica.addStablecoinAsset(address(feeToken), address(feeAToken));
        feeToken.mint(signer, 10_000 ether);
        vm.prank(signer);
        feeToken.approve(PERMIT2, type(uint256).max);

        Permit2Authorization memory auth = _authorization(
            address(feeToken),
            AMOUNT,
            block.timestamp + 1 hours,
            30
        );

        uint256 received = AMOUNT - (AMOUNT * 100) / 10_000;
        vm.prank(FACILITATOR);
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.ValueMismatch.selector,
                AMOUNT,
                received
            )
        );
        core4Mica.depositStablecoinWithPermit2(address(feeToken), AMOUNT, auth);
    }

    /// End-to-end: gasless Permit2 deposit, then the signer withdraws it back after the grace period.
    function test_DepositWithPermit2_ThenWithdraw() public {
        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithPermit2(
            address(usdc),
            AMOUNT,
            _validAuthorization(AMOUNT, 29)
        );

        vm.prank(signer);
        core4Mica.requestWithdrawal(address(usdc), AMOUNT);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.prank(signer);
        core4Mica.finalizeWithdrawal(address(usdc));

        assertEq(
            core4Mica.collateral(signer, address(usdc)),
            0,
            "balance drained"
        );
        assertEq(usdc.balanceOf(signer), 10_000 ether, "signer made whole");
    }
}
