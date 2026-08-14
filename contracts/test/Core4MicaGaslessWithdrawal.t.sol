// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Core4Mica, WithdrawalRequestAuthorization, WithdrawalCancelAuthorization} from "../src/Core4Mica.sol";
import {Core4MicaTestBase} from "./Core4MicaTestBase.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// Smart account that accepts exactly one signer's ECDSA signature, so the EIP-1271 branch of
/// `SignatureChecker` can be exercised without pulling in a full account implementation.
contract MockERC1271Wallet is IERC1271 {
    address public immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        (bytes32 r, bytes32 s, uint8 v) = _split(signature);
        return ecrecover(hash, v, r, s) == owner ? IERC1271.isValidSignature.selector : bytes4(0);
    }

    function _split(bytes memory signature) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(signature.length == 65, "SIG_LENGTH");
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
    }
}

contract Core4MicaGaslessWithdrawalTest is Core4MicaTestBase {
    /// Signs the authorizations. Has a real key, unlike the base fixture's `USER1`.
    uint256 internal constant SIGNER_PK = 0xA11CE;
    address internal signer;

    /// Submits the transactions and pays the gas. Must never be credited or paid out.
    address internal constant RELAYER = address(0xFACADE);

    uint256 internal constant DEPOSIT = 1_000 ether;
    uint256 internal constant AMOUNT = 400 ether;

    function setUp() public override {
        super.setUp();
        signer = vm.addr(SIGNER_PK);

        vm.deal(signer, 10 ether);
        usdc.mint(signer, 10_000 ether);

        vm.startPrank(signer);
        usdc.approve(address(core4Mica), type(uint256).max);
        core4Mica.depositStablecoin(address(usdc), DEPOSIT);
        core4Mica.deposit{value: 5 ether}();
        vm.stopPrank();
    }

    // ========= Helpers =========

    function _requestAuth(
        address user,
        address asset,
        uint256 amount,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce
    ) internal view returns (WithdrawalRequestAuthorization memory auth) {
        bytes32 structHash = keccak256(
            abi.encode(core4Mica.REQUEST_WITHDRAWAL_TYPEHASH(), user, asset, amount, validAfter, validBefore, nonce)
        );
        return WithdrawalRequestAuthorization({
            user: user,
            asset: asset,
            amount: amount,
            validAfter: validAfter,
            validBefore: validBefore,
            nonce: nonce,
            signature: _sign(structHash)
        });
    }

    function _cancelAuth(address user, address asset, uint256 validAfter, uint256 validBefore, bytes32 nonce)
        internal
        view
        returns (WithdrawalCancelAuthorization memory auth)
    {
        bytes32 structHash = keccak256(
            abi.encode(core4Mica.CANCEL_WITHDRAWAL_TYPEHASH(), user, asset, validAfter, validBefore, nonce)
        );
        return WithdrawalCancelAuthorization({
            user: user,
            asset: asset,
            validAfter: validAfter,
            validBefore: validBefore,
            nonce: nonce,
            signature: _sign(structHash)
        });
    }

    function _sign(bytes32 structHash) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", core4Mica.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    function _defaultRequest(address asset, uint256 amount)
        internal
        view
        returns (WithdrawalRequestAuthorization memory)
    {
        return _requestAuth(signer, asset, amount, 0, block.timestamp + 1 hours, bytes32(uint256(1)));
    }

    function _requestedAmount(address user, address asset) internal view returns (uint256) {
        (, uint256 amount,) = core4Mica.withdrawalRequests(user, asset);
        return amount;
    }

    // ========= Domain =========

    /// Off-chain signers derive this domain from the chain id and the contract address rather than
    /// reading it, which only holds while the name and version stay `("Core4Mica", "1")`. Changing
    /// either is a breaking change for every client that has not been rebuilt.
    function test_DomainSeparatorUsesTheDeclaredNameAndVersion() public view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Core4Mica"),
                keccak256("1"),
                block.chainid,
                address(core4Mica)
            )
        );

        assertEq(core4Mica.DOMAIN_SEPARATOR(), expected);
    }

    // ========= Request =========

    function test_RequestWithAuthorizationRecordsAgainstSignerNotSubmitter() public {
        WithdrawalRequestAuthorization memory auth = _defaultRequest(address(usdc), AMOUNT);

        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(auth);

        assertEq(_requestedAmount(signer, address(usdc)), AMOUNT);
        assertEq(_requestedAmount(RELAYER, address(usdc)), 0, "relayer must not get a request of its own");
        assertTrue(core4Mica.authorizationState(signer, bytes32(uint256(1))));
    }

    function test_RequestWithAuthorizationWorksForEth() public {
        WithdrawalRequestAuthorization memory auth = _defaultRequest(ETH_ASSET, 1 ether);

        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(auth);

        assertEq(_requestedAmount(signer, ETH_ASSET), 1 ether);
    }

    function test_RequestWithAuthorizationAcceptsAnErc1271Signer() public {
        MockERC1271Wallet wallet = new MockERC1271Wallet(signer);
        vm.deal(address(wallet), 3 ether);
        vm.prank(address(wallet));
        core4Mica.deposit{value: 3 ether}();

        // Signed by the wallet's owner key but declaring the wallet as the user: only the EIP-1271
        // branch can validate this.
        WithdrawalRequestAuthorization memory auth =
            _requestAuth(address(wallet), ETH_ASSET, 1 ether, 0, block.timestamp + 1 hours, bytes32(uint256(7)));

        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(auth);

        assertEq(_requestedAmount(address(wallet), ETH_ASSET), 1 ether);
    }

    /// The whole security claim: a relayer that edits the request produces a digest the signature no
    /// longer recovers against.
    function test_RequestRejectsATamperedAmount() public {
        WithdrawalRequestAuthorization memory auth = _defaultRequest(address(usdc), AMOUNT);
        auth.amount = DEPOSIT;

        vm.prank(RELAYER);
        vm.expectRevert(Core4Mica.InvalidSignature.selector);
        core4Mica.requestWithdrawalWithAuthorization(auth);
    }

    function test_RequestRejectsATamperedAsset() public {
        WithdrawalRequestAuthorization memory auth = _defaultRequest(address(usdc), AMOUNT);
        auth.asset = address(usdt);

        vm.prank(RELAYER);
        vm.expectRevert(Core4Mica.InvalidSignature.selector);
        core4Mica.requestWithdrawalWithAuthorization(auth);
    }

    function test_RequestRejectsATamperedUser() public {
        WithdrawalRequestAuthorization memory auth = _defaultRequest(address(usdc), AMOUNT);
        auth.user = RELAYER;

        vm.prank(RELAYER);
        vm.expectRevert(Core4Mica.InvalidSignature.selector);
        core4Mica.requestWithdrawalWithAuthorization(auth);
    }

    function test_RequestRejectsAReplayedNonce() public {
        WithdrawalRequestAuthorization memory auth = _defaultRequest(address(usdc), AMOUNT);

        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(auth);

        vm.prank(RELAYER);
        vm.expectRevert(
            abi.encodeWithSelector(Core4Mica.AuthorizationAlreadyUsed.selector, signer, bytes32(uint256(1)))
        );
        core4Mica.requestWithdrawalWithAuthorization(auth);
    }

    /// Nonces are per user, so two accounts picking the same random value do not collide.
    function test_NoncesAreScopedToTheSigner() public {
        WithdrawalRequestAuthorization memory auth = _defaultRequest(address(usdc), AMOUNT);
        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(auth);

        assertTrue(core4Mica.authorizationState(signer, bytes32(uint256(1))));
        assertFalse(core4Mica.authorizationState(USER1, bytes32(uint256(1))));
    }

    function test_RequestRejectsAnExpiredAuthorization() public {
        uint256 validBefore = block.timestamp + 1 hours;
        WithdrawalRequestAuthorization memory auth =
            _requestAuth(signer, address(usdc), AMOUNT, 0, validBefore, bytes32(uint256(2)));

        vm.warp(validBefore);
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.AuthorizationExpired.selector, validBefore));
        core4Mica.requestWithdrawalWithAuthorization(auth);
    }

    function test_RequestRejectsAnAuthorizationThatIsNotYetValid() public {
        uint256 validAfter = block.timestamp + 1 hours;
        WithdrawalRequestAuthorization memory auth =
            _requestAuth(signer, address(usdc), AMOUNT, validAfter, validAfter + 1 hours, bytes32(uint256(3)));

        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.AuthorizationNotYetValid.selector, validAfter));
        core4Mica.requestWithdrawalWithAuthorization(auth);
    }

    function test_RequestRejectsAnAmountAboveTheAvailableBalance() public {
        WithdrawalRequestAuthorization memory auth = _defaultRequest(address(usdc), DEPOSIT * 2);

        vm.prank(RELAYER);
        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.requestWithdrawalWithAuthorization(auth);
    }

    function test_RequestRejectsAZeroAmount() public {
        WithdrawalRequestAuthorization memory auth = _defaultRequest(address(usdc), 0);

        vm.prank(RELAYER);
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.requestWithdrawalWithAuthorization(auth);
    }

    function test_RequestRejectsAnUnsupportedAsset() public {
        address unsupported = address(0xDEAD);
        WithdrawalRequestAuthorization memory auth = _defaultRequest(unsupported, AMOUNT);

        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.UnsupportedAsset.selector, unsupported));
        core4Mica.requestWithdrawalWithAuthorization(auth);
    }

    function test_RequestIsBlockedWhilePaused() public {
        WithdrawalRequestAuthorization memory auth = _defaultRequest(address(usdc), AMOUNT);
        core4Mica.pause();

        vm.prank(RELAYER);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        core4Mica.requestWithdrawalWithAuthorization(auth);
    }

    // ========= Cancel =========

    function test_CancelWithAuthorizationClearsTheSignersRequest() public {
        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(_defaultRequest(address(usdc), AMOUNT));

        WithdrawalCancelAuthorization memory auth =
            _cancelAuth(signer, address(usdc), 0, block.timestamp + 1 hours, bytes32(uint256(4)));

        vm.prank(RELAYER);
        core4Mica.cancelWithdrawalWithAuthorization(auth);

        assertEq(_requestedAmount(signer, address(usdc)), 0);
    }

    function test_CancelRejectsATamperedAsset() public {
        WithdrawalCancelAuthorization memory auth =
            _cancelAuth(signer, address(usdc), 0, block.timestamp + 1 hours, bytes32(uint256(5)));
        auth.asset = address(usdt);

        vm.prank(RELAYER);
        vm.expectRevert(Core4Mica.InvalidSignature.selector);
        core4Mica.cancelWithdrawalWithAuthorization(auth);
    }

    function test_CancelRejectsAReplayedNonce() public {
        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(_defaultRequest(address(usdc), AMOUNT));

        WithdrawalCancelAuthorization memory auth =
            _cancelAuth(signer, address(usdc), 0, block.timestamp + 1 hours, bytes32(uint256(6)));
        vm.prank(RELAYER);
        core4Mica.cancelWithdrawalWithAuthorization(auth);

        vm.prank(RELAYER);
        vm.expectRevert(
            abi.encodeWithSelector(Core4Mica.AuthorizationAlreadyUsed.selector, signer, bytes32(uint256(6)))
        );
        core4Mica.cancelWithdrawalWithAuthorization(auth);
    }

    /// A request nonce and a cancel nonce share one namespace, so reusing a spent value fails
    /// whichever action spent it.
    function test_CancelCannotReuseARequestNonce() public {
        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(_defaultRequest(address(usdc), AMOUNT));

        WithdrawalCancelAuthorization memory auth =
            _cancelAuth(signer, address(usdc), 0, block.timestamp + 1 hours, bytes32(uint256(1)));

        vm.prank(RELAYER);
        vm.expectRevert(
            abi.encodeWithSelector(Core4Mica.AuthorizationAlreadyUsed.selector, signer, bytes32(uint256(1)))
        );
        core4Mica.cancelWithdrawalWithAuthorization(auth);
    }

    function test_CancelRevertsWithoutAPendingRequest() public {
        WithdrawalCancelAuthorization memory auth =
            _cancelAuth(signer, address(usdc), 0, block.timestamp + 1 hours, bytes32(uint256(8)));

        vm.prank(RELAYER);
        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        core4Mica.cancelWithdrawalWithAuthorization(auth);
    }

    // ========= Finalize =========

    function test_FinalizeForPaysTheUserNotTheSubmitter() public {
        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(_defaultRequest(address(usdc), AMOUNT));

        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());
        uint256 balanceBefore = usdc.balanceOf(signer);

        vm.prank(RELAYER);
        core4Mica.finalizeWithdrawalFor(signer, address(usdc));

        assertEq(usdc.balanceOf(signer) - balanceBefore, AMOUNT);
        assertEq(usdc.balanceOf(RELAYER), 0, "submitter must receive nothing");
        assertEq(_requestedAmount(signer, address(usdc)), 0);
    }

    function test_FinalizeForPaysOutEthToTheUser() public {
        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(_defaultRequest(ETH_ASSET, 1 ether));

        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());
        uint256 balanceBefore = signer.balance;

        vm.prank(RELAYER);
        core4Mica.finalizeWithdrawalFor(signer, ETH_ASSET);

        assertEq(signer.balance - balanceBefore, 1 ether);
    }

    function test_FinalizeForRespectsTheGracePeriod() public {
        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(_defaultRequest(address(usdc), AMOUNT));

        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod() - 1);
        vm.prank(RELAYER);
        vm.expectRevert(Core4Mica.GracePeriodNotElapsed.selector);
        core4Mica.finalizeWithdrawalFor(signer, address(usdc));
    }

    function test_FinalizeForRevertsWithoutAPendingRequest() public {
        vm.prank(RELAYER);
        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        core4Mica.finalizeWithdrawalFor(signer, address(usdc));
    }

    function test_FinalizeForIsBlockedWhilePaused() public {
        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(_defaultRequest(address(usdc), AMOUNT));
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());
        core4Mica.pause();

        vm.prank(RELAYER);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        core4Mica.finalizeWithdrawalFor(signer, address(usdc));
    }

    // ========= Full sponsored round trip =========

    /// The point of the feature: a user with no native balance at all completes a withdrawal.
    function test_AGaslessUserCanCompleteAWithdrawal() public {
        address poor = vm.addr(0xB0B);
        usdc.mint(poor, DEPOSIT);
        vm.startPrank(poor);
        usdc.approve(address(core4Mica), type(uint256).max);
        core4Mica.depositStablecoin(address(usdc), DEPOSIT);
        vm.stopPrank();
        vm.deal(poor, 0);

        bytes32 structHash = keccak256(
            abi.encode(
                core4Mica.REQUEST_WITHDRAWAL_TYPEHASH(),
                poor,
                address(usdc),
                DEPOSIT,
                uint256(0),
                block.timestamp + 1 hours,
                bytes32(uint256(99))
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", core4Mica.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, digest);

        vm.prank(RELAYER);
        core4Mica.requestWithdrawalWithAuthorization(
            WithdrawalRequestAuthorization({
                user: poor,
                asset: address(usdc),
                amount: DEPOSIT,
                validAfter: 0,
                validBefore: block.timestamp + 1 hours,
                nonce: bytes32(uint256(99)),
                signature: abi.encodePacked(r, s, v)
            })
        );

        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());
        vm.prank(RELAYER);
        core4Mica.finalizeWithdrawalFor(poor, address(usdc));

        assertEq(usdc.balanceOf(poor), DEPOSIT);
        assertEq(poor.balance, 0, "the user never needed native balance");
    }
}
