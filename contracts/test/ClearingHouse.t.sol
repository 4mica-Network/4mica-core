// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {ClearingHouse} from "../src/ClearingHouse.sol";
import {MockERC20} from "./Core4MicaTestBase.sol";

contract ClearingHouseTest is Test {
    ClearingHouse internal clearingHouse;
    AccessManager internal manager;
    MockERC20 internal usdc;

    address internal constant DEBTOR = address(0x111);
    address internal constant CREDITOR = address(0x222);
    address internal constant OPERATOR = address(0x333);
    address internal constant ETH_ASSET = address(0);
    uint64 internal constant OPERATOR_ROLE = 9;

    bytes32 internal constant CYCLE_ID = keccak256("cycle-1");
    uint256 internal constant NET_AMOUNT = 100 ether;

    function setUp() public {
        manager = new AccessManager(address(this));
        clearingHouse = new ClearingHouse(address(manager));
        usdc = new MockERC20("USD Coin", "USDC");

        bytes4[] memory operatorSelectors = new bytes4[](2);
        operatorSelectors[0] = ClearingHouse.commitCycle.selector;
        operatorSelectors[1] = ClearingHouse.settleDefaultFromCollateral.selector;
        manager.setTargetFunctionRole(address(clearingHouse), operatorSelectors, OPERATOR_ROLE);
        manager.grantRole(OPERATOR_ROLE, OPERATOR, 0);

        vm.deal(DEBTOR, 1_000 ether);
        vm.deal(OPERATOR, 1_000 ether);
        usdc.mint(DEBTOR, 1_000 ether);
    }

    function test_CommitCycleStoresCycle() public {
        (bytes32 root,,) = _rootAndProofs(ETH_ASSET, NET_AMOUNT, NET_AMOUNT);
        uint64 submissionDeadline = uint64(block.timestamp + 1 hours);
        uint64 finalityDeadline = uint64(block.timestamp + 2 hours);

        vm.expectEmit(true, true, false, true);
        emit ClearingHouse.CycleCommitted(
            CYCLE_ID, ETH_ASSET, root, NET_AMOUNT, NET_AMOUNT, submissionDeadline, finalityDeadline
        );

        vm.prank(OPERATOR);
        clearingHouse.commitCycle(
            CYCLE_ID, ETH_ASSET, root, NET_AMOUNT, NET_AMOUNT, submissionDeadline, finalityDeadline
        );

        ClearingHouse.OnchainCycle memory cycle = clearingHouse.getCycle(CYCLE_ID);
        assertEq(cycle.asset, ETH_ASSET);
        assertEq(cycle.merkleRoot, root);
        assertEq(cycle.totalNetDebit, NET_AMOUNT);
        assertEq(cycle.totalNetCredit, NET_AMOUNT);
        assertEq(uint8(cycle.status), uint8(ClearingHouse.CycleStatus.PaymentWindowOpen));
        assertTrue(cycle.exists);
    }

    function test_PayNetDebitRequiresExactNativePayment() public {
        (, bytes32[] memory debtorProof,) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);

        vm.prank(DEBTOR);
        vm.expectRevert(abi.encodeWithSelector(ClearingHouse.ExactPaymentRequired.selector, NET_AMOUNT, NET_AMOUNT - 1));
        clearingHouse.payNetDebit{value: NET_AMOUNT - 1}(CYCLE_ID, NET_AMOUNT, debtorProof);

        vm.expectEmit(true, true, false, true);
        emit ClearingHouse.DebtorPaid(CYCLE_ID, DEBTOR, NET_AMOUNT);

        vm.prank(DEBTOR);
        clearingHouse.payNetDebit{value: NET_AMOUNT}(CYCLE_ID, NET_AMOUNT, debtorProof);

        ClearingHouse.ParticipantState memory debtor = clearingHouse.getParticipantState(CYCLE_ID, DEBTOR);
        assertEq(debtor.netDebit, NET_AMOUNT);
        assertTrue(debtor.paid);

        ClearingHouse.OnchainCycle memory cycle = clearingHouse.getCycle(CYCLE_ID);
        assertEq(cycle.totalPaidIn, NET_AMOUNT);
        assertEq(cycle.totalResolvedDebit, NET_AMOUNT);
    }

    function test_ClaimNetCreditRejectsUnderfundedClaim() public {
        (,, bytes32[] memory creditorProof) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);

        vm.prank(CREDITOR);
        vm.expectRevert(abi.encodeWithSelector(ClearingHouse.ClaimExceedsFundedLiquidity.selector, 0, NET_AMOUNT));
        clearingHouse.claimNetCredit(CYCLE_ID, NET_AMOUNT, creditorProof);
    }

    function test_PayClaimAndFinalizeNativeCycle() public {
        (, bytes32[] memory debtorProof, bytes32[] memory creditorProof) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);

        uint256 creditorBalanceBefore = CREDITOR.balance;

        vm.prank(DEBTOR);
        clearingHouse.payNetDebit{value: NET_AMOUNT}(CYCLE_ID, NET_AMOUNT, debtorProof);

        vm.expectEmit(true, true, false, true);
        emit ClearingHouse.CreditorClaimed(CYCLE_ID, CREDITOR, NET_AMOUNT);

        vm.prank(CREDITOR);
        clearingHouse.claimNetCredit(CYCLE_ID, NET_AMOUNT, creditorProof);

        assertEq(CREDITOR.balance, creditorBalanceBefore + NET_AMOUNT);

        vm.warp(block.timestamp + 2 hours + 1);

        vm.expectEmit(true, false, false, true);
        emit ClearingHouse.CycleFinalized(CYCLE_ID);

        clearingHouse.finalizeCycle(CYCLE_ID);

        ClearingHouse.OnchainCycle memory cycle = clearingHouse.getCycle(CYCLE_ID);
        assertEq(uint8(cycle.status), uint8(ClearingHouse.CycleStatus.Finalized));
        assertEq(cycle.totalClaimedOut, NET_AMOUNT);
    }

    function test_DefaultedCycleRequiresCoverageBeforeFinalization() public {
        (, bytes32[] memory debtorProof, bytes32[] memory creditorProof) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);

        vm.warp(block.timestamp + 2 hours + 1);

        vm.expectEmit(true, true, false, true);
        emit ClearingHouse.DebtorDefaulted(CYCLE_ID, DEBTOR, NET_AMOUNT);
        clearingHouse.markDefaulted(CYCLE_ID, DEBTOR, NET_AMOUNT, debtorProof);

        vm.expectRevert(abi.encodeWithSelector(ClearingHouse.CycleUnderfunded.selector, 0, NET_AMOUNT));
        clearingHouse.finalizeCycle(CYCLE_ID);

        vm.expectEmit(true, true, false, true);
        emit ClearingHouse.DefaultCovered(CYCLE_ID, DEBTOR, NET_AMOUNT);

        vm.prank(OPERATOR);
        clearingHouse.settleDefaultFromCollateral{value: NET_AMOUNT}(CYCLE_ID, DEBTOR, NET_AMOUNT, "");

        vm.prank(CREDITOR);
        clearingHouse.claimNetCredit(CYCLE_ID, NET_AMOUNT, creditorProof);

        clearingHouse.finalizeCycle(CYCLE_ID);

        ClearingHouse.OnchainCycle memory cycle = clearingHouse.getCycle(CYCLE_ID);
        assertEq(uint8(cycle.status), uint8(ClearingHouse.CycleStatus.Finalized));
        assertEq(cycle.totalDefaultCovered, NET_AMOUNT);
    }

    function test_ERC20DebtorPaymentAndCreditorClaim() public {
        (, bytes32[] memory debtorProof, bytes32[] memory creditorProof) =
            _commitTokenCycle(address(usdc), NET_AMOUNT, NET_AMOUNT);

        vm.startPrank(DEBTOR);
        usdc.approve(address(clearingHouse), NET_AMOUNT);
        clearingHouse.payNetDebit(CYCLE_ID, NET_AMOUNT, debtorProof);
        vm.stopPrank();

        uint256 creditorBalanceBefore = usdc.balanceOf(CREDITOR);

        vm.prank(CREDITOR);
        clearingHouse.claimNetCredit(CYCLE_ID, NET_AMOUNT, creditorProof);

        assertEq(usdc.balanceOf(CREDITOR), creditorBalanceBefore + NET_AMOUNT);
    }

    function _commitEthCycle(uint256 netDebit, uint256 netCredit)
        internal
        returns (bytes32 root, bytes32[] memory debtorProof, bytes32[] memory creditorProof)
    {
        (root, debtorProof, creditorProof) = _rootAndProofs(ETH_ASSET, netDebit, netCredit);
        vm.prank(OPERATOR);
        clearingHouse.commitCycle(
            CYCLE_ID,
            ETH_ASSET,
            root,
            netDebit,
            netCredit,
            uint64(block.timestamp + 1 hours),
            uint64(block.timestamp + 2 hours)
        );
    }

    function _commitTokenCycle(address asset, uint256 netDebit, uint256 netCredit)
        internal
        returns (bytes32 root, bytes32[] memory debtorProof, bytes32[] memory creditorProof)
    {
        (root, debtorProof, creditorProof) = _rootAndProofs(asset, netDebit, netCredit);
        vm.prank(OPERATOR);
        clearingHouse.commitCycle(
            CYCLE_ID,
            asset,
            root,
            netDebit,
            netCredit,
            uint64(block.timestamp + 1 hours),
            uint64(block.timestamp + 2 hours)
        );
    }

    function _rootAndProofs(address asset, uint256 netDebit, uint256 netCredit)
        internal
        view
        returns (bytes32 root, bytes32[] memory debtorProof, bytes32[] memory creditorProof)
    {
        bytes32 debtorLeaf = clearingHouse.participantLeaf(
            CYCLE_ID, asset, DEBTOR, netDebit, ClearingHouse.ParticipantRole.NetDebtor
        );
        bytes32 creditorLeaf = clearingHouse.participantLeaf(
            CYCLE_ID, asset, CREDITOR, netCredit, ClearingHouse.ParticipantRole.NetCreditor
        );

        root = _hashPair(debtorLeaf, creditorLeaf);
        debtorProof = new bytes32[](1);
        debtorProof[0] = creditorLeaf;
        creditorProof = new bytes32[](1);
        creditorProof[0] = debtorLeaf;
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }
}
