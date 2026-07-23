// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Core4MicaTestBase} from "./Core4MicaTestBase.sol";
import {Core4Mica, ReceiveAuthorization} from "../src/Core4Mica.sol";
import {MockAToken} from "./helpers/MockAave.sol";

/// Minimal EIP-3009 stablecoin, mirroring USDC's FiatToken `receiveWithAuthorization`, used to
/// exercise the gasless deposit path. Signatures are real EIP-712 digests verified via `ecrecover`.
contract MockERC3009 {
    string public name;
    string public symbol;
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    uint8 public immutable decimals;
    string public constant EIP712_VERSION = "2";
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    // authorizer => nonce => used
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    // keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(EIP712_VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(to == msg.sender, "EIP3009: caller must be the payee");
        uint256 currentTime = block.timestamp;
        require(currentTime > validAfter, "EIP3009: authorization is not yet valid");
        require(currentTime < validBefore, "EIP3009: authorization is expired");
        require(!authorizationState[from][nonce], "EIP3009: authorization is used");

        bytes32 structHash =
            keccak256(abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        require(ecrecover(digest, v, r, s) == from, "EIP3009: invalid signature");

        authorizationState[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);
        _transfer(from, to, value);
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "ALLOWANCE");
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal virtual {
        require(balanceOf[from] >= amount, "BALANCE");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }
}

/// EIP-3009 stablecoin that skims a fee on every transfer, so `receiveWithAuthorization` delivers
/// less than the signed `value`. Used to prove the deposit path rejects short-delivering tokens.
contract MockERC3009FeeOnTransfer is MockERC3009 {
    uint256 internal immutable feeBps;

    constructor(string memory name_, string memory symbol_, uint8 decimals_, uint256 feeBps_)
        MockERC3009(name_, symbol_, decimals_)
    {
        feeBps = feeBps_;
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 fee = (amount * feeBps) / 10_000;
        require(balanceOf[from] >= amount, "BALANCE");
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
        totalSupply -= fee;
        emit Transfer(from, to, amount - fee);
    }
}

contract Core4MicaDepositAuthorizationTest is Core4MicaTestBase {
    MockERC3009 internal token;
    MockAToken internal tokenAToken;

    // Client that signs the EIP-3009 authorization (has a real key so we can sign).
    uint256 internal constant SIGNER_PK = 0xA11CE;
    address internal signer;
    // Third party that submits the tx and pays gas — must NOT be credited.
    address internal constant FACILITATOR = address(0xFACADE);

    uint256 internal constant AMOUNT = 1_000 ether;

    function setUp() public override {
        super.setUp();
        signer = vm.addr(SIGNER_PK);

        // Deploy an EIP-3009 stablecoin and register it as a supported asset with its own aToken.
        token = new MockERC3009("USD Coin", "USDC", 6);
        tokenAToken = new MockAToken(address(token), address(mockPool), "Aave USDC", "aUSDC");
        mockPool.setReserve(address(token), address(tokenAToken), 1e27);
        mockDataProvider.setReserveAToken(address(token), address(tokenAToken));
        core4Mica.addStablecoinAsset(address(token), address(tokenAToken));

        token.mint(signer, 10_000 ether);
    }

    function _authorization(uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce)
        internal
        view
        returns (ReceiveAuthorization memory auth)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                token.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(),
                signer,
                address(core4Mica),
                value,
                validAfter,
                validBefore,
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, digest);
        auth = ReceiveAuthorization({
            from: signer, validAfter: validAfter, validBefore: validBefore, nonce: nonce, v: v, r: r, s: s
        });
    }

    function _validAuthorization(uint256 value, bytes32 nonce) internal view returns (ReceiveAuthorization memory) {
        return _authorization(value, 0, block.timestamp + 1 hours, nonce);
    }

    /// Sign an authorization with an arbitrary key and `from`, so tests can forge wrong-signer cases.
    function _authorizationWithKey(
        uint256 pk,
        address from,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (ReceiveAuthorization memory auth) {
        bytes32 structHash = keccak256(
            abi.encode(
                token.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(),
                from,
                address(core4Mica),
                value,
                validAfter,
                validBefore,
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        auth = ReceiveAuthorization({
            from: from, validAfter: validAfter, validBefore: validBefore, nonce: nonce, v: v, r: r, s: s
        });
    }

    /// The core guarantee: a third party submits the tx, but the *signer* is credited.
    function test_DepositWithAuthorization_CreditsSignerNotSubmitter() public {
        ReceiveAuthorization memory auth = _validAuthorization(AMOUNT, bytes32(uint256(1)));

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralDeposited(signer, address(token), AMOUNT);

        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithAuthorization(address(token), AMOUNT, auth);

        // Collateral credited to the signer, not the facilitator.
        assertEq(core4Mica.collateral(signer, address(token)), AMOUNT, "signer collateral");
        assertEq(core4Mica.collateral(FACILITATOR, address(token)), 0, "facilitator must not be credited");

        // Funds pulled from the signer and supplied into Aave; facilitator balance untouched.
        assertEq(token.balanceOf(signer), 10_000 ether - AMOUNT, "signer debited");
        assertEq(token.balanceOf(FACILITATOR), 0, "facilitator balance unchanged");
        assertEq(token.balanceOf(address(core4Mica)), 0, "contract forwards to pool");
        assertEq(token.balanceOf(address(mockPool)), AMOUNT, "pool holds supply");
    }

    function test_DepositWithAuthorization_AccumulatesAcrossDeposits() public {
        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithAuthorization(
            address(token), AMOUNT, _validAuthorization(AMOUNT, bytes32(uint256(1)))
        );
        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithAuthorization(
            address(token), 500 ether, _validAuthorization(500 ether, bytes32(uint256(2)))
        );

        assertEq(core4Mica.collateral(signer, address(token)), AMOUNT + 500 ether, "accumulated collateral");
    }

    function test_DepositWithAuthorization_RevertReplayedNonce() public {
        bytes32 nonce = bytes32(uint256(7));
        ReceiveAuthorization memory auth = _validAuthorization(AMOUNT, nonce);

        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithAuthorization(address(token), AMOUNT, auth);

        // Same authorization cannot be redeemed twice — the token marks the nonce used.
        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("EIP3009: authorization is used"));
        core4Mica.depositStablecoinWithAuthorization(address(token), AMOUNT, auth);
    }

    function test_DepositWithAuthorization_RevertExpiredAuthorization() public {
        ReceiveAuthorization memory auth = _authorization(AMOUNT, 0, block.timestamp + 1, bytes32(uint256(3)));
        vm.warp(block.timestamp + 2);

        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("EIP3009: authorization is expired"));
        core4Mica.depositStablecoinWithAuthorization(address(token), AMOUNT, auth);
    }

    /// A mismatch between the on-chain `amount` and the signed `value` breaks the signature, so the
    /// token rejects it — the caller cannot inflate the deposit beyond what the user authorized.
    function test_DepositWithAuthorization_RevertAmountExceedsSignedValue() public {
        ReceiveAuthorization memory auth = _validAuthorization(AMOUNT, bytes32(uint256(4)));

        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("EIP3009: invalid signature"));
        core4Mica.depositStablecoinWithAuthorization(address(token), AMOUNT + 1, auth);
    }

    function test_DepositWithAuthorization_RevertUnsupportedAsset() public {
        MockERC3009 fake = new MockERC3009("Fake", "FAKE", 6);
        ReceiveAuthorization memory auth = _validAuthorization(AMOUNT, bytes32(uint256(5)));

        vm.prank(FACILITATOR);
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.UnsupportedAsset.selector, address(fake)));
        core4Mica.depositStablecoinWithAuthorization(address(fake), AMOUNT, auth);
    }

    function test_DepositWithAuthorization_RevertAmountZero() public {
        ReceiveAuthorization memory auth = _validAuthorization(0, bytes32(uint256(6)));

        vm.prank(FACILITATOR);
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.depositStablecoinWithAuthorization(address(token), 0, auth);
    }

    function test_DepositWithAuthorization_RevertWhenPaused() public {
        core4Mica.pause();
        ReceiveAuthorization memory auth = _validAuthorization(AMOUNT, bytes32(uint256(8)));

        vm.prank(FACILITATOR);
        vm.expectRevert();
        core4Mica.depositStablecoinWithAuthorization(address(token), AMOUNT, auth);
    }

    // ========================= Edge cases =========================

    uint256 internal constant SIGNER2_PK = 0xB0B;
    address internal constant FACILITATOR2 = address(0xCAFE);

    /// An authorization whose `validAfter` is still in the future is rejected by the token.
    function test_DepositWithAuthorization_RevertNotYetValid() public {
        ReceiveAuthorization memory auth =
            _authorization(AMOUNT, block.timestamp + 1000, block.timestamp + 2000, bytes32(uint256(11)));
        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("EIP3009: authorization is not yet valid"));
        core4Mica.depositStablecoinWithAuthorization(address(token), AMOUNT, auth);
    }

    /// `validBefore == now` is already expired (the token requires `now < validBefore`).
    function test_DepositWithAuthorization_RevertValidBeforeBoundary() public {
        ReceiveAuthorization memory auth = _authorization(AMOUNT, 0, block.timestamp, bytes32(uint256(12)));
        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("EIP3009: authorization is expired"));
        core4Mica.depositStablecoinWithAuthorization(address(token), AMOUNT, auth);
    }

    /// A tampered signature no longer recovers to `from`.
    function test_DepositWithAuthorization_RevertTamperedSignature() public {
        ReceiveAuthorization memory auth = _validAuthorization(AMOUNT, bytes32(uint256(13)));
        auth.r = bytes32(uint256(auth.r) ^ 1); // flip one bit

        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("EIP3009: invalid signature"));
        core4Mica.depositStablecoinWithAuthorization(address(token), AMOUNT, auth);
    }

    /// A signature from a key other than `from` is rejected (relayer cannot forge for a victim).
    function test_DepositWithAuthorization_RevertWrongSigner() public {
        ReceiveAuthorization memory auth =
            _authorizationWithKey(SIGNER2_PK, signer, AMOUNT, 0, block.timestamp + 1 hours, bytes32(uint256(14)));

        vm.prank(FACILITATOR);
        vm.expectRevert(bytes("EIP3009: invalid signature"));
        core4Mica.depositStablecoinWithAuthorization(address(token), AMOUNT, auth);
    }

    /// Two different relayers submit two authorizations; both credit the signer and accumulate.
    function test_DepositWithAuthorization_TwoRelayersBothCreditSigner() public {
        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithAuthorization(
            address(token), AMOUNT, _validAuthorization(AMOUNT, bytes32(uint256(15)))
        );
        vm.prank(FACILITATOR2);
        core4Mica.depositStablecoinWithAuthorization(
            address(token), 400 ether, _validAuthorization(400 ether, bytes32(uint256(16)))
        );

        assertEq(core4Mica.collateral(signer, address(token)), AMOUNT + 400 ether, "signer accumulated");
        assertEq(core4Mica.collateral(FACILITATOR, address(token)), 0, "relayer 1 not credited");
        assertEq(core4Mica.collateral(FACILITATOR2, address(token)), 0, "relayer 2 not credited");
    }

    /// Two independent signers keep isolated balances.
    function test_DepositWithAuthorization_TwoSignersIsolated() public {
        address signer2 = vm.addr(SIGNER2_PK);
        token.mint(signer2, 10_000 ether);

        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithAuthorization(
            address(token), AMOUNT, _validAuthorization(AMOUNT, bytes32(uint256(17)))
        );

        ReceiveAuthorization memory auth2 =
            _authorizationWithKey(SIGNER2_PK, signer2, 300 ether, 0, block.timestamp + 1 hours, bytes32(uint256(18)));
        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithAuthorization(address(token), 300 ether, auth2);

        assertEq(core4Mica.collateral(signer, address(token)), AMOUNT, "signer 1 isolated");
        assertEq(core4Mica.collateral(signer2, address(token)), 300 ether, "signer 2 isolated");
    }

    /// A dust authorization that mints zero scaled aTokens is rejected (audit L-1) on the gasless path too.
    function test_DepositWithAuthorization_RevertZeroScaledCredit() public {
        mockPool.setNormalizedIncome(address(token), 2e27);
        ReceiveAuthorization memory auth = _validAuthorization(1, bytes32(uint256(19)));

        vm.prank(FACILITATOR);
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.ZeroCollateralCredit.selector, address(token), 1));
        core4Mica.depositStablecoinWithAuthorization(address(token), 1, auth);
    }

    /// A token that reports success while delivering less than the signed `value` (fee-on-transfer)
    /// is rejected by the balance-delta check, so no unbacked principal is ever credited.
    function test_DepositWithAuthorization_RevertShortDelivery() public {
        MockERC3009FeeOnTransfer feeToken = new MockERC3009FeeOnTransfer("USD Coin", "USDC", 6, 100); // 1% fee
        MockAToken feeAToken = new MockAToken(address(feeToken), address(mockPool), "Aave USDC", "aUSDC");
        mockPool.setReserve(address(feeToken), address(feeAToken), 1e27);
        mockDataProvider.setReserveAToken(address(feeToken), address(feeAToken));
        core4Mica.addStablecoinAsset(address(feeToken), address(feeAToken));
        feeToken.mint(signer, 10_000 ether);

        bytes32 nonce = bytes32(uint256(21));
        bytes32 structHash = keccak256(
            abi.encode(
                feeToken.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(),
                signer,
                address(core4Mica),
                AMOUNT,
                uint256(0),
                block.timestamp + 1 hours,
                nonce
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", feeToken.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, digest);
        ReceiveAuthorization memory auth = ReceiveAuthorization({
            from: signer, validAfter: 0, validBefore: block.timestamp + 1 hours, nonce: nonce, v: v, r: r, s: s
        });

        uint256 received = AMOUNT - (AMOUNT * 100) / 10_000;
        vm.prank(FACILITATOR);
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.ValueMismatch.selector, AMOUNT, received));
        core4Mica.depositStablecoinWithAuthorization(address(feeToken), AMOUNT, auth);
    }

    /// End-to-end: gasless deposit, then the signer withdraws it back after the grace period.
    function test_DepositWithAuthorization_ThenWithdraw() public {
        vm.prank(FACILITATOR);
        core4Mica.depositStablecoinWithAuthorization(
            address(token), AMOUNT, _validAuthorization(AMOUNT, bytes32(uint256(20)))
        );

        vm.prank(signer);
        core4Mica.requestWithdrawal(address(token), AMOUNT);
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.prank(signer);
        core4Mica.finalizeWithdrawal(address(token));

        assertEq(core4Mica.collateral(signer, address(token)), 0, "balance drained");
        assertEq(token.balanceOf(signer), 10_000 ether, "signer made whole");
    }
}
