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

    function test_ClaimNetCreditRejectsUnfundedClaim() public {
        (,, bytes32[] memory creditorProof) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);

        // Nothing paid in yet: the pool is empty, so the claim is rejected as
        // underfunded regardless of timing.
        vm.prank(CREDITOR);
        vm.expectRevert(abi.encodeWithSelector(ClearingHouse.CycleUnderfunded.selector, 0, NET_AMOUNT));
        clearingHouse.claimNetCredit(CYCLE_ID, NET_AMOUNT, creditorProof);
    }

    function test_ClaimNetCreditRejectedWhenPartiallyFunded() public {
        // Two debtors each owe half; a single creditor is owed the whole sum.
        address d1 = address(0xD1);
        address d2 = address(0xD2);
        address creditor = address(0xC0);
        uint256 half = NET_AMOUNT;
        uint256 total = NET_AMOUNT * 2;

        vm.deal(d1, half);

        bytes32[] memory leaves = new bytes32[](3);
        leaves[0] =
            clearingHouse.participantLeaf(CYCLE_ID, ETH_ASSET, d1, half, ClearingHouse.ParticipantRole.NetDebtor);
        leaves[1] =
            clearingHouse.participantLeaf(CYCLE_ID, ETH_ASSET, d2, half, ClearingHouse.ParticipantRole.NetDebtor);
        leaves[2] = clearingHouse.participantLeaf(
            CYCLE_ID, ETH_ASSET, creditor, total, ClearingHouse.ParticipantRole.NetCreditor
        );

        (bytes32 root,) = _merkle(leaves, leaves[0]);
        (, bytes32[] memory p1) = _merkle(leaves, leaves[0]);
        (, bytes32[] memory pc) = _merkle(leaves, leaves[2]);

        vm.prank(OPERATOR);
        clearingHouse.commitCycle(
            CYCLE_ID,
            ETH_ASSET,
            root,
            total,
            total,
            uint64(block.timestamp + 1 hours),
            uint64(block.timestamp + 2 hours)
        );

        // Only one of the two debtors pays: pool holds `half`, creditor is owed
        // `total`. The claim must wait until the other debt is covered, even
        // though some liquidity is present.
        vm.prank(d1);
        clearingHouse.payNetDebit{value: half}(CYCLE_ID, half, p1);

        vm.prank(creditor);
        vm.expectRevert(abi.encodeWithSelector(ClearingHouse.CycleUnderfunded.selector, half, total));
        clearingHouse.claimNetCredit(CYCLE_ID, total, pc);
    }

    function test_PayClaimAndFinalizeNativeCycle() public {
        (, bytes32[] memory debtorProof, bytes32[] memory creditorProof) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);

        uint256 creditorBalanceBefore = CREDITOR.balance;

        vm.prank(DEBTOR);
        clearingHouse.payNetDebit{value: NET_AMOUNT}(CYCLE_ID, NET_AMOUNT, debtorProof);

        // Fully funded by the debtor's payment, so the creditor can claim right
        // away — no need to wait for finality.
        vm.expectEmit(true, true, false, true);
        emit ClearingHouse.CreditorClaimed(CYCLE_ID, CREDITOR, NET_AMOUNT);

        vm.prank(CREDITOR);
        clearingHouse.claimNetCredit(CYCLE_ID, NET_AMOUNT, creditorProof);

        assertEq(CREDITOR.balance, creditorBalanceBefore + NET_AMOUNT);

        // Finalization still requires the finality deadline to elapse.
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
        clearingHouse.settleDefaultFromCollateral{value: NET_AMOUNT}(CYCLE_ID, DEBTOR, NET_AMOUNT);

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

    function test_MultiDebtorDefaultCanAllBeMarked() public {
        address d1 = address(0xD1);
        address d2 = address(0xD2);
        address d3 = address(0xD3);
        address creditor = address(0xC0);
        uint256 amt = 100 ether;
        uint256 total = 300 ether;

        vm.deal(d1, amt);
        vm.deal(OPERATOR, 1_000 ether);

        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = clearingHouse.participantLeaf(CYCLE_ID, ETH_ASSET, d1, amt, ClearingHouse.ParticipantRole.NetDebtor);
        leaves[1] = clearingHouse.participantLeaf(CYCLE_ID, ETH_ASSET, d2, amt, ClearingHouse.ParticipantRole.NetDebtor);
        leaves[2] = clearingHouse.participantLeaf(CYCLE_ID, ETH_ASSET, d3, amt, ClearingHouse.ParticipantRole.NetDebtor);
        leaves[3] = clearingHouse.participantLeaf(
            CYCLE_ID, ETH_ASSET, creditor, total, ClearingHouse.ParticipantRole.NetCreditor
        );

        (bytes32 root,) = _merkle(leaves, leaves[0]);
        (, bytes32[] memory p1) = _merkle(leaves, leaves[0]);
        (, bytes32[] memory p2) = _merkle(leaves, leaves[1]);
        (, bytes32[] memory p3) = _merkle(leaves, leaves[2]);
        (, bytes32[] memory pc) = _merkle(leaves, leaves[3]);

        vm.prank(OPERATOR);
        clearingHouse.commitCycle(
            CYCLE_ID,
            ETH_ASSET,
            root,
            total,
            total,
            uint64(block.timestamp + 1 hours),
            uint64(block.timestamp + 2 hours)
        );

        // One debtor pays; the other two will default.
        vm.prank(d1);
        clearingHouse.payNetDebit{value: amt}(CYCLE_ID, amt, p1);

        vm.warp(block.timestamp + 2 hours + 1);

        // Both unpaid debtors must be markable even though the first flips the
        // cycle to Defaulted. (Regression: previously only one could be marked.)
        clearingHouse.markDefaulted(CYCLE_ID, d2, amt, p2);
        clearingHouse.markDefaulted(CYCLE_ID, d3, amt, p3);

        ClearingHouse.OnchainCycle memory afterDefault = clearingHouse.getCycle(CYCLE_ID);
        assertEq(afterDefault.totalResolvedDebit, total, "all debit resolved");

        // Cover both defaults from collateral, then let the creditor claim.
        vm.startPrank(OPERATOR);
        clearingHouse.settleDefaultFromCollateral{value: amt}(CYCLE_ID, d2, amt);
        clearingHouse.settleDefaultFromCollateral{value: amt}(CYCLE_ID, d3, amt);
        vm.stopPrank();

        vm.prank(creditor);
        clearingHouse.claimNetCredit(CYCLE_ID, total, pc);

        clearingHouse.finalizeCycle(CYCLE_ID);

        ClearingHouse.OnchainCycle memory finalized = clearingHouse.getCycle(CYCLE_ID);
        assertEq(uint8(finalized.status), uint8(ClearingHouse.CycleStatus.Finalized));
        assertEq(creditor.balance, total);
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

    /// Build a sorted-pair Merkle root over `leavesInput` and the proof for
    /// `target`, mirroring the off-chain crypto::merkle tree (sorted, dedup is
    /// not exercised here, odd trailing node paired with itself).
    function _merkle(bytes32[] memory leavesInput, bytes32 target)
        internal
        pure
        returns (bytes32 root, bytes32[] memory proof)
    {
        bytes32[] memory level = _sortedCopy(leavesInput);
        uint256 index = type(uint256).max;
        for (uint256 i = 0; i < level.length; i++) {
            if (level[i] == target) index = i;
        }

        bytes32[] memory scratch = new bytes32[](level.length);
        uint256 plen = 0;
        while (level.length > 1) {
            uint256 nextLen = (level.length + 1) / 2;
            bytes32[] memory next = new bytes32[](nextLen);
            for (uint256 i = 0; i < level.length; i += 2) {
                bytes32 right = i + 1 < level.length ? level[i + 1] : level[i];
                next[i / 2] = _hashPair(level[i], right);
            }
            if (index != type(uint256).max) {
                uint256 sibling;
                if (index % 2 == 0) {
                    sibling = index + 1 < level.length ? index + 1 : index;
                } else {
                    sibling = index - 1;
                }
                scratch[plen++] = level[sibling];
                index /= 2;
            }
            level = next;
        }

        root = level[0];
        proof = new bytes32[](plen);
        for (uint256 i = 0; i < plen; i++) {
            proof[i] = scratch[i];
        }
    }

    function _sortedCopy(bytes32[] memory input) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](input.length);
        for (uint256 i = 0; i < input.length; i++) {
            out[i] = input[i];
        }
        for (uint256 i = 1; i < out.length; i++) {
            bytes32 key = out[i];
            uint256 j = i;
            while (j > 0 && out[j - 1] > key) {
                out[j] = out[j - 1];
                j -= 1;
            }
            out[j] = key;
        }
    }
}
