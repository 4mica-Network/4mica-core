// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {ClearingHouse} from "../src/ClearingHouse.sol";
import {Permit2Authorization} from "../src/Core4Mica.sol";
import {MockERC20} from "./Core4MicaTestBase.sol";
import {MockCore4Mica} from "./ClearingHouse.t.sol";
import {MockPermit2} from "./helpers/MockPermit2.sol";

/// The Permit2 half of sponsored debit payments, mirroring the EIP-3009 suite in
/// `ClearingHouse.t.sol`: same trust model, different signature scheme — any ERC-20 works, but
/// the debtor must have granted the one-time ERC-20 approval to Permit2.
contract ClearingHousePayPermit2Test is Test {
    // Canonical Permit2 address, matching `ClearingHouse.PERMIT2`.
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    ClearingHouse internal clearingHouse;
    AccessManager internal manager;
    MockCore4Mica internal core4Mica;
    MockERC20 internal usdc;

    uint256 internal constant DEBTOR_PK = 0xA11CE;
    address internal debtor;
    address internal constant CREDITOR = address(0x222);
    address internal constant OPERATOR = address(0x333);
    address internal constant FACILITATOR = address(0xFACADE);
    uint64 internal constant OPERATOR_ROLE = 9;

    bytes32 internal constant CYCLE_ID = keccak256("cycle-1");
    uint256 internal constant NET_AMOUNT = 100 ether;

    function setUp() public {
        manager = new AccessManager(address(this));
        core4Mica = new MockCore4Mica();
        clearingHouse = new ClearingHouse(address(manager), address(core4Mica));
        usdc = new MockERC20("USD Coin", "USDC", 6);

        bytes4[] memory operatorSelectors = new bytes4[](1);
        operatorSelectors[0] = ClearingHouse.commitCycle.selector;
        manager.setTargetFunctionRole(address(clearingHouse), operatorSelectors, OPERATOR_ROLE);
        manager.grantRole(OPERATOR_ROLE, OPERATOR, 0);

        // Place the Permit2 mock at the canonical address the contract calls into.
        vm.etch(PERMIT2, address(new MockPermit2()).code);

        debtor = vm.addr(DEBTOR_PK);
        usdc.mint(debtor, NET_AMOUNT);
        // The one-time ERC-20 approval Permit2 requires (the single on-chain step for the payer).
        vm.prank(debtor);
        usdc.approve(PERMIT2, type(uint256).max);
    }

    /// The core guarantee: a third party submits, but the *signer's* funds pay the signer's debt.
    function test_PayNetDebitWithPermit2_SettlesTheSignerNotSubmitter() public {
        bytes32[] memory debtorProof = _commitUsdcCycle();
        Permit2Authorization memory auth = _validAuthorization();

        vm.expectEmit(true, true, false, true);
        emit ClearingHouse.DebtorPaid(CYCLE_ID, debtor, NET_AMOUNT);

        vm.prank(FACILITATOR);
        clearingHouse.payNetDebitWithPermit2(CYCLE_ID, NET_AMOUNT, debtorProof, auth);

        assertEq(usdc.balanceOf(debtor), 0, "net debit pulled from the signer");
        assertEq(core4Mica.escrowOf(address(usdc)), NET_AMOUNT, "paid-in funds escrowed");
        assertTrue(clearingHouse.getParticipantState(CYCLE_ID, debtor).paid);
        assertFalse(clearingHouse.getParticipantState(CYCLE_ID, FACILITATOR).paid, "no state against the submitter");
    }

    function test_PayNetDebitWithPermit2_RejectsWrongSigner() public {
        bytes32[] memory debtorProof = _commitUsdcCycle();
        // Signed by another key but claiming `from = debtor`.
        Permit2Authorization memory auth =
            _authorization(0xBAD, debtor, NET_AMOUNT, block.timestamp + 1 hours, uint256(CYCLE_ID));

        vm.expectRevert(bytes("Permit2: invalid signature"));
        clearingHouse.payNetDebitWithPermit2(CYCLE_ID, NET_AMOUNT, debtorProof, auth);
    }

    function test_PayNetDebitWithPermit2_RejectsValueNotMatchingDebit() public {
        bytes32[] memory debtorProof = _commitUsdcCycle();

        // The signature covers `permitted.amount`; the contract passes `netDebit` there, so an
        // authorization signed over any other amount fails Permit2's signature check.
        Permit2Authorization memory auth =
            _authorization(DEBTOR_PK, debtor, NET_AMOUNT - 1, block.timestamp + 1 hours, uint256(CYCLE_ID));

        vm.expectRevert(bytes("Permit2: invalid signature"));
        clearingHouse.payNetDebitWithPermit2(CYCLE_ID, NET_AMOUNT, debtorProof, auth);
    }

    function test_PayNetDebitWithPermit2_RejectsForeignNonce() public {
        bytes32[] memory debtorProof = _commitUsdcCycle();

        bytes32 otherCycle = keccak256("cycle-2");
        Permit2Authorization memory auth =
            _authorization(DEBTOR_PK, debtor, NET_AMOUNT, block.timestamp + 1 hours, uint256(otherCycle));

        vm.expectRevert(abi.encodeWithSelector(ClearingHouse.AuthorizationCycleMismatch.selector, otherCycle, CYCLE_ID));
        clearingHouse.payNetDebitWithPermit2(CYCLE_ID, NET_AMOUNT, debtorProof, auth);
    }

    function test_PayNetDebitWithPermit2_RejectsExpiredDeadline() public {
        bytes32[] memory debtorProof = _commitUsdcCycle();

        Permit2Authorization memory auth =
            _authorization(DEBTOR_PK, debtor, NET_AMOUNT, block.timestamp, uint256(CYCLE_ID));
        vm.warp(block.timestamp + 1);

        vm.expectRevert(bytes("Permit2: signature expired"));
        clearingHouse.payNetDebitWithPermit2(CYCLE_ID, NET_AMOUNT, debtorProof, auth);
    }

    function test_PayNetDebitWithPermit2_RejectsReplay() public {
        usdc.mint(debtor, NET_AMOUNT); // enough for two pulls, so only the state check can stop it
        bytes32[] memory debtorProof = _commitUsdcCycle();
        Permit2Authorization memory auth = _validAuthorization();

        clearingHouse.payNetDebitWithPermit2(CYCLE_ID, NET_AMOUNT, debtorProof, auth);

        vm.expectRevert(abi.encodeWithSelector(ClearingHouse.AlreadyPaid.selector, CYCLE_ID, debtor));
        clearingHouse.payNetDebitWithPermit2(CYCLE_ID, NET_AMOUNT, debtorProof, auth);

        assertEq(usdc.balanceOf(debtor), NET_AMOUNT, "funds pulled exactly once");
    }

    function test_PayNetDebitWithPermit2_RejectsNativeCycle() public {
        bytes32[] memory debtorProof = _commitCycle(address(0), debtor);

        // The native check fires before any signature use, so a dummy signature suffices.
        Permit2Authorization memory auth = Permit2Authorization({
            from: debtor, nonce: uint256(CYCLE_ID), deadline: block.timestamp + 1 hours, signature: new bytes(65)
        });

        vm.expectRevert(ClearingHouse.NativeAssetUnsupported.selector);
        clearingHouse.payNetDebitWithPermit2(CYCLE_ID, NET_AMOUNT, debtorProof, auth);
    }

    /// Without the one-time ERC-20 approval to Permit2, the pull fails at the token allowance
    /// check — the missing prerequisite that separates Permit2 from EIP-3009.
    function test_PayNetDebitWithPermit2_RejectsWithoutPermit2Approval() public {
        uint256 pk = 0xC0DE;
        address noApprove = vm.addr(pk);
        usdc.mint(noApprove, NET_AMOUNT); // has balance, but never approved Permit2
        bytes32[] memory debtorProof = _commitCycle(address(usdc), noApprove);

        Permit2Authorization memory auth =
            _authorization(pk, noApprove, NET_AMOUNT, block.timestamp + 1 hours, uint256(CYCLE_ID));

        vm.expectRevert(bytes("ALLOWANCE"));
        clearingHouse.payNetDebitWithPermit2(CYCLE_ID, NET_AMOUNT, debtorProof, auth);
    }

    function _validAuthorization() internal view returns (Permit2Authorization memory) {
        return _authorization(DEBTOR_PK, debtor, NET_AMOUNT, block.timestamp + 1 hours, uint256(CYCLE_ID));
    }

    function _authorization(uint256 pk, address from, uint256 permittedAmount, uint256 deadline, uint256 nonce)
        internal
        view
        returns (Permit2Authorization memory auth)
    {
        bytes32 tokenPermissions = keccak256(
            abi.encode(keccak256("TokenPermissions(address token,uint256 amount)"), address(usdc), permittedAmount)
        );
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
                ),
                tokenPermissions,
                address(clearingHouse), // spender
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", MockPermit2(PERMIT2).DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        auth =
            Permit2Authorization({from: from, nonce: nonce, deadline: deadline, signature: abi.encodePacked(r, s, v)});
    }

    function _commitUsdcCycle() internal returns (bytes32[] memory debtorProof) {
        return _commitCycle(address(usdc), debtor);
    }

    function _commitCycle(address asset, address debtor_) internal returns (bytes32[] memory debtorProof) {
        bytes32 debtorLeaf = clearingHouse.participantLeaf(
            CYCLE_ID, asset, debtor_, NET_AMOUNT, ClearingHouse.ParticipantRole.NetDebtor
        );
        bytes32 creditorLeaf = clearingHouse.participantLeaf(
            CYCLE_ID, asset, CREDITOR, NET_AMOUNT, ClearingHouse.ParticipantRole.NetCreditor
        );
        bytes32 root = _hashPair(debtorLeaf, creditorLeaf);
        debtorProof = new bytes32[](1);
        debtorProof[0] = creditorLeaf;

        vm.prank(OPERATOR);
        clearingHouse.commitCycle(
            CYCLE_ID,
            asset,
            root,
            NET_AMOUNT,
            NET_AMOUNT,
            uint64(block.timestamp + 1 hours),
            uint64(block.timestamp + 2 hours)
        );
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }
}
