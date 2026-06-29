// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ClearingHouse, ICore4MicaSettlement} from "../src/ClearingHouse.sol";
import {MockERC20} from "./Core4MicaTestBase.sol";

/// Minimal Core4Mica stand-in for ClearingHouse unit tests: tracks per-user
/// collateral, releases seized funds to the pool, and records credited funding.
contract MockCore4Mica is ICore4MicaSettlement {
    mapping(address => mapping(address => uint256)) public collateralOf;
    mapping(address => mapping(address => uint256)) public creditedOf;
    // Stablecoin settlement escrow (underlying-equivalent), mirroring Core4Mica's scaled escrow.
    mapping(address => uint256) public escrowOf;
    // Optional per-asset liquidity shortfall to exercise partial-fill cash-out.
    mapping(address => uint256) public withdrawShortfall;

    function setCollateral(address user, address asset, uint256 amount) external {
        collateralOf[user][asset] = amount;
    }

    function setWithdrawShortfall(address asset, uint256 amount) external {
        withdrawShortfall[asset] = amount;
    }

    function seizeCollateral(address debtor, address asset, uint256 amount) external returns (uint256) {
        require(collateralOf[debtor][asset] >= amount, "insufficient collateral");
        collateralOf[debtor][asset] -= amount;
        if (asset == address(0)) {
            (bool ok,) = payable(msg.sender).call{value: amount}("");
            require(ok, "eth send failed");
        } else {
            // Stablecoin seizures stay in escrow (no underlying released), mirroring Core4Mica.
            escrowOf[asset] += amount;
        }
        return amount;
    }

    function seizeUpTo(address debtor, address asset, uint256 amount) external returns (uint256) {
        uint256 available = collateralOf[debtor][asset];
        uint256 take = amount < available ? amount : available;
        if (take == 0) return 0;
        collateralOf[debtor][asset] = available - take;
        if (asset == address(0)) {
            (bool ok,) = payable(msg.sender).call{value: take}("");
            require(ok, "eth send failed");
        } else {
            escrowOf[asset] += take;
        }
        return take;
    }

    function creditCollateral(address creditor, address asset, uint256 amount) external payable {
        if (asset == address(0)) {
            require(msg.value == amount, "value mismatch");
        } else {
            require(msg.value == 0, "value mismatch");
            require(IERC20(asset).transferFrom(msg.sender, address(this), amount), "transferFrom failed");
        }
        creditedOf[creditor][asset] += amount;
    }

    function depositToEscrow(address asset, uint256 amount) external {
        require(IERC20(asset).transferFrom(msg.sender, address(this), amount), "transferFrom failed");
        escrowOf[asset] += amount;
    }

    function creditFromEscrowScaled(address creditor, address asset, uint256 amount) external {
        require(escrowOf[asset] >= amount, "escrow underflow");
        escrowOf[asset] -= amount;
        creditedOf[creditor][asset] += amount;
    }

    function withdrawFromEscrow(address asset, uint256 amount, address recipient)
        external
        returns (uint256 actualWithdrawn)
    {
        uint256 shortfall = withdrawShortfall[asset];
        actualWithdrawn = amount > shortfall ? amount - shortfall : 0;
        require(escrowOf[asset] >= actualWithdrawn, "escrow underflow");
        escrowOf[asset] -= actualWithdrawn;
        require(IERC20(asset).transfer(recipient, actualWithdrawn), "transfer failed");
    }

    receive() external payable {}
}

contract ClearingHouseTest is Test {
    ClearingHouse internal clearingHouse;
    AccessManager internal manager;
    MockCore4Mica internal core4Mica;
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
        core4Mica = new MockCore4Mica();
        clearingHouse = new ClearingHouse(address(manager), address(core4Mica));
        usdc = new MockERC20("USD Coin", "USDC", 6);

        bytes4[] memory operatorSelectors = new bytes4[](4);
        operatorSelectors[0] = ClearingHouse.commitCycle.selector;
        operatorSelectors[1] = ClearingHouse.settleDefaultsFromCollateralBatch.selector;
        operatorSelectors[2] = ClearingHouse.fundCreditorsFromPoolBatch.selector;
        operatorSelectors[3] = ClearingHouse.markCycleShortfall.selector;
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
        vm.expectEmit(true, true, true, true);
        emit ClearingHouse.CreditorClaimed(CYCLE_ID, CREDITOR, ETH_ASSET, NET_AMOUNT);

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

    function test_DefaultedCycleRequiresResolutionBeforeFinalization() public {
        (, bytes32[] memory debtorProof, bytes32[] memory creditorProof) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);

        core4Mica.setCollateral(DEBTOR, ETH_ASSET, NET_AMOUNT);
        vm.deal(address(core4Mica), NET_AMOUNT);

        vm.warp(block.timestamp + 2 hours + 1);

        // Before any settlement the debt is unresolved, so finalization reverts.
        vm.expectRevert(abi.encodeWithSelector(ClearingHouse.CycleDebtUnresolved.selector, 0, NET_AMOUNT));
        clearingHouse.finalizeCycle(CYCLE_ID);

        // Seizing the debtor's collateral both resolves and funds the debt.
        ClearingHouse.DebtorEntry[] memory debtors = new ClearingHouse.DebtorEntry[](1);
        debtors[0] = ClearingHouse.DebtorEntry({debtor: DEBTOR, netDebit: NET_AMOUNT, proof: debtorProof});
        vm.prank(OPERATOR);
        clearingHouse.settleDefaultsFromCollateralBatch(CYCLE_ID, debtors);

        // The pool is funded but the creditor has not been paid out yet.
        vm.expectRevert(abi.encodeWithSelector(ClearingHouse.CycleClaimsUnresolved.selector, 0, NET_AMOUNT));
        clearingHouse.finalizeCycle(CYCLE_ID);

        ClearingHouse.CreditorEntry[] memory creditors = new ClearingHouse.CreditorEntry[](1);
        creditors[0] = ClearingHouse.CreditorEntry({creditor: CREDITOR, netCredit: NET_AMOUNT, proof: creditorProof});
        vm.prank(OPERATOR);
        clearingHouse.fundCreditorsFromPoolBatch(CYCLE_ID, creditors);

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

    function test_MultiDebtorDefaultSettledInOneBatch() public {
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

        // One debtor pays; the other two will default and be seized from collateral.
        vm.prank(d1);
        clearingHouse.payNetDebit{value: amt}(CYCLE_ID, amt, p1);

        core4Mica.setCollateral(d2, ETH_ASSET, amt);
        core4Mica.setCollateral(d3, ETH_ASSET, amt);
        vm.deal(address(core4Mica), 2 * amt);

        vm.warp(block.timestamp + 2 hours + 1);

        // Both unpaid debtors are settled in a single batch even though the first
        // entry flips the cycle to Defaulted. (Regression: previously only one could be marked.)
        ClearingHouse.DebtorEntry[] memory debtors = new ClearingHouse.DebtorEntry[](2);
        debtors[0] = ClearingHouse.DebtorEntry({debtor: d2, netDebit: amt, proof: p2});
        debtors[1] = ClearingHouse.DebtorEntry({debtor: d3, netDebit: amt, proof: p3});
        vm.prank(OPERATOR);
        clearingHouse.settleDefaultsFromCollateralBatch(CYCLE_ID, debtors);

        ClearingHouse.OnchainCycle memory afterDefault = clearingHouse.getCycle(CYCLE_ID);
        assertEq(afterDefault.totalResolvedDebit, total, "all debit resolved");

        vm.prank(creditor);
        clearingHouse.claimNetCredit(CYCLE_ID, total, pc);

        clearingHouse.finalizeCycle(CYCLE_ID);

        ClearingHouse.OnchainCycle memory finalized = clearingHouse.getCycle(CYCLE_ID);
        assertEq(uint8(finalized.status), uint8(ClearingHouse.CycleStatus.Finalized));
        assertEq(creditor.balance, total);
    }

    function test_BatchSettlesEthDefaultsAndFundsCreditor() public {
        (, bytes32[] memory debtorProof, bytes32[] memory creditorProof) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);

        // The vault holds the debtor's collateral, ready to be seized into the pool.
        core4Mica.setCollateral(DEBTOR, ETH_ASSET, NET_AMOUNT);
        vm.deal(address(core4Mica), NET_AMOUNT);

        vm.warp(block.timestamp + 2 hours + 1);

        ClearingHouse.DebtorEntry[] memory debtors = new ClearingHouse.DebtorEntry[](1);
        debtors[0] = ClearingHouse.DebtorEntry({debtor: DEBTOR, netDebit: NET_AMOUNT, proof: debtorProof});

        vm.expectEmit(true, true, true, true);
        emit ClearingHouse.DebtorDefaulted(CYCLE_ID, DEBTOR, ETH_ASSET, NET_AMOUNT);
        vm.prank(OPERATOR);
        clearingHouse.settleDefaultsFromCollateralBatch(CYCLE_ID, debtors);

        ClearingHouse.OnchainCycle memory cycle = clearingHouse.getCycle(CYCLE_ID);
        assertEq(uint8(cycle.status), uint8(ClearingHouse.CycleStatus.Defaulted));
        assertEq(cycle.totalResolvedDebit, NET_AMOUNT);
        assertEq(cycle.totalDefaultCovered, NET_AMOUNT);
        assertEq(core4Mica.collateralOf(DEBTOR, ETH_ASSET), 0);
        assertEq(address(clearingHouse).balance, NET_AMOUNT);

        ClearingHouse.CreditorEntry[] memory creditors = new ClearingHouse.CreditorEntry[](1);
        creditors[0] = ClearingHouse.CreditorEntry({creditor: CREDITOR, netCredit: NET_AMOUNT, proof: creditorProof});

        vm.expectEmit(true, true, true, true);
        emit ClearingHouse.CreditorClaimed(CYCLE_ID, CREDITOR, ETH_ASSET, NET_AMOUNT);
        vm.prank(OPERATOR);
        clearingHouse.fundCreditorsFromPoolBatch(CYCLE_ID, creditors);

        assertEq(core4Mica.creditedOf(CREDITOR, ETH_ASSET), NET_AMOUNT);
        assertEq(address(clearingHouse).balance, 0);

        clearingHouse.finalizeCycle(CYCLE_ID);
        assertEq(uint8(clearingHouse.getCycle(CYCLE_ID).status), uint8(ClearingHouse.CycleStatus.Finalized));
    }

    function test_BatchSettleRevertsBeforeFinality() public {
        (, bytes32[] memory debtorProof,) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);

        ClearingHouse.DebtorEntry[] memory debtors = new ClearingHouse.DebtorEntry[](1);
        debtors[0] = ClearingHouse.DebtorEntry({debtor: DEBTOR, netDebit: NET_AMOUNT, proof: debtorProof});

        vm.prank(OPERATOR);
        vm.expectRevert(
            abi.encodeWithSelector(ClearingHouse.PaymentFinalityPending.selector, uint64(block.timestamp + 2 hours))
        );
        clearingHouse.settleDefaultsFromCollateralBatch(CYCLE_ID, debtors);
    }

    function test_BatchSkipsInvalidEntriesAndSettlesValidOnes() public {
        address d1 = address(0xD1);
        address d2 = address(0xD2);
        address d3 = address(0xD3);
        address creditor = address(0xC0);
        uint256 amt = 100 ether;
        uint256 total = 300 ether;

        vm.deal(d1, amt);

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

        // d1 pays voluntarily; d3 has collateral to seize; d2 has none (seize will fail).
        vm.prank(d1);
        clearingHouse.payNetDebit{value: amt}(CYCLE_ID, amt, p1);

        core4Mica.setCollateral(d3, ETH_ASSET, amt);
        vm.deal(address(core4Mica), amt);

        vm.warp(block.timestamp + 2 hours + 1);

        ClearingHouse.DebtorEntry[] memory debtors = new ClearingHouse.DebtorEntry[](3);
        debtors[0] = ClearingHouse.DebtorEntry({debtor: d1, netDebit: amt, proof: p1}); // already paid
        debtors[1] = ClearingHouse.DebtorEntry({debtor: d2, netDebit: amt, proof: p2}); // seize fails
        debtors[2] = ClearingHouse.DebtorEntry({debtor: d3, netDebit: amt, proof: p3}); // settles

        vm.expectEmit(true, true, false, true);
        emit ClearingHouse.SettlementSkipped(CYCLE_ID, d1, "already resolved");
        // d2 has no collateral: it is resolved as a zero-recovery default rather than skipped,
        // so the cycle can terminate via Shortfall instead of wedging.
        vm.expectEmit(true, true, true, true);
        emit ClearingHouse.DebtorDefaulted(CYCLE_ID, d2, ETH_ASSET, 0);
        vm.expectEmit(true, true, true, true);
        emit ClearingHouse.DebtorDefaulted(CYCLE_ID, d3, ETH_ASSET, amt);
        vm.prank(OPERATOR);
        clearingHouse.settleDefaultsFromCollateralBatch(CYCLE_ID, debtors);

        ClearingHouse.OnchainCycle memory cycle = clearingHouse.getCycle(CYCLE_ID);
        // All three debtors resolved; only d1 (paid) and d3 (seized) actually funded the pool.
        assertEq(cycle.totalResolvedDebit, total);
        assertEq(cycle.totalPaidIn, amt);
        assertEq(cycle.totalDefaultCovered, amt);
        // Funded (200) < total (300): the cycle is under-collateralised and Shortfall-eligible.
        assertTrue(clearingHouse.getParticipantState(CYCLE_ID, d2).defaulted);
        assertTrue(clearingHouse.getParticipantState(CYCLE_ID, d3).defaulted);
    }

    function test_BatchSkipsInvalidProof() public {
        (, bytes32[] memory debtorProof,) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);
        core4Mica.setCollateral(DEBTOR, ETH_ASSET, NET_AMOUNT);
        vm.deal(address(core4Mica), NET_AMOUNT);
        vm.warp(block.timestamp + 2 hours + 1);

        ClearingHouse.DebtorEntry[] memory debtors = new ClearingHouse.DebtorEntry[](1);
        // Wrong amount makes the proof fail to verify against the committed leaf.
        debtors[0] = ClearingHouse.DebtorEntry({debtor: DEBTOR, netDebit: NET_AMOUNT - 1, proof: debtorProof});

        vm.expectEmit(true, true, false, true);
        emit ClearingHouse.SettlementSkipped(CYCLE_ID, DEBTOR, "invalid proof");
        vm.prank(OPERATOR);
        clearingHouse.settleDefaultsFromCollateralBatch(CYCLE_ID, debtors);

        assertEq(clearingHouse.getCycle(CYCLE_ID).totalResolvedDebit, 0);
    }

    function test_FundCreditorsRevertsWhenUnderfunded() public {
        (,, bytes32[] memory creditorProof) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);
        vm.warp(block.timestamp + 2 hours + 1);

        ClearingHouse.CreditorEntry[] memory creditors = new ClearingHouse.CreditorEntry[](1);
        creditors[0] = ClearingHouse.CreditorEntry({creditor: CREDITOR, netCredit: NET_AMOUNT, proof: creditorProof});

        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(ClearingHouse.CycleUnderfunded.selector, 0, NET_AMOUNT));
        clearingHouse.fundCreditorsFromPoolBatch(CYCLE_ID, creditors);
    }

    function test_BatchSettlesErc20Default() public {
        (, bytes32[] memory debtorProof, bytes32[] memory creditorProof) =
            _commitTokenCycle(address(usdc), NET_AMOUNT, NET_AMOUNT);

        core4Mica.setCollateral(DEBTOR, address(usdc), NET_AMOUNT);
        usdc.mint(address(core4Mica), NET_AMOUNT);

        vm.warp(block.timestamp + 2 hours + 1);

        ClearingHouse.DebtorEntry[] memory debtors = new ClearingHouse.DebtorEntry[](1);
        debtors[0] = ClearingHouse.DebtorEntry({debtor: DEBTOR, netDebit: NET_AMOUNT, proof: debtorProof});
        vm.prank(OPERATOR);
        clearingHouse.settleDefaultsFromCollateralBatch(CYCLE_ID, debtors);

        // Seized stablecoin is held in escrow, never released to the pool contract.
        assertEq(core4Mica.escrowOf(address(usdc)), NET_AMOUNT);
        assertEq(usdc.balanceOf(address(clearingHouse)), 0);

        ClearingHouse.CreditorEntry[] memory creditors = new ClearingHouse.CreditorEntry[](1);
        creditors[0] = ClearingHouse.CreditorEntry({creditor: CREDITOR, netCredit: NET_AMOUNT, proof: creditorProof});
        vm.prank(OPERATOR);
        clearingHouse.fundCreditorsFromPoolBatch(CYCLE_ID, creditors);

        // Creditor is made whole in collateral form straight from escrow — no Aave round trip.
        assertEq(core4Mica.creditedOf(CREDITOR, address(usdc)), NET_AMOUNT);
        assertEq(core4Mica.escrowOf(address(usdc)), 0);
        assertEq(usdc.balanceOf(address(clearingHouse)), 0);
    }

    function test_Erc20ClaimRetriesAfterLiquidityShortfall() public {
        (, bytes32[] memory debtorProof, bytes32[] memory creditorProof) =
            _commitTokenCycle(address(usdc), NET_AMOUNT, NET_AMOUNT);

        vm.startPrank(DEBTOR);
        usdc.approve(address(clearingHouse), NET_AMOUNT);
        clearingHouse.payNetDebit(CYCLE_ID, NET_AMOUNT, debtorProof);
        vm.stopPrank();

        // Aave can't fully convert: the cash-out reverts atomically (no partial claim recorded).
        core4Mica.setWithdrawShortfall(address(usdc), 1);
        vm.prank(CREDITOR);
        vm.expectRevert(
            abi.encodeWithSelector(ClearingHouse.ClaimConversionShortfall.selector, NET_AMOUNT, NET_AMOUNT - 1)
        );
        clearingHouse.claimNetCredit(CYCLE_ID, NET_AMOUNT, creditorProof);

        // Liquidity returns; the same creditor retries successfully.
        core4Mica.setWithdrawShortfall(address(usdc), 0);
        uint256 before = usdc.balanceOf(CREDITOR);
        vm.prank(CREDITOR);
        clearingHouse.claimNetCredit(CYCLE_ID, NET_AMOUNT, creditorProof);
        assertEq(usdc.balanceOf(CREDITOR), before + NET_AMOUNT);
    }

    function test_UnderCollateralizedCycleEntersShortfallAndPaysProRata() public {
        address d1 = address(0xD1);
        address d2 = address(0xD2);
        address c1 = address(0xC1);
        address c2 = address(0xC2);
        uint256 amt = 100 ether;
        uint256 total = 200 ether;

        vm.deal(d1, amt);

        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = clearingHouse.participantLeaf(CYCLE_ID, ETH_ASSET, d1, amt, ClearingHouse.ParticipantRole.NetDebtor);
        leaves[1] = clearingHouse.participantLeaf(CYCLE_ID, ETH_ASSET, d2, amt, ClearingHouse.ParticipantRole.NetDebtor);
        leaves[2] =
            clearingHouse.participantLeaf(CYCLE_ID, ETH_ASSET, c1, amt, ClearingHouse.ParticipantRole.NetCreditor);
        leaves[3] =
            clearingHouse.participantLeaf(CYCLE_ID, ETH_ASSET, c2, amt, ClearingHouse.ParticipantRole.NetCreditor);

        (bytes32 root,) = _merkle(leaves, leaves[0]);
        (, bytes32[] memory p1) = _merkle(leaves, leaves[0]);
        (, bytes32[] memory p2) = _merkle(leaves, leaves[1]);
        (, bytes32[] memory pc1) = _merkle(leaves, leaves[2]);
        (, bytes32[] memory pc2) = _merkle(leaves, leaves[3]);

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

        // d1 pays in full; d2 defaults with only 40 of its 100 collateral -> funded = 140 < 200.
        vm.prank(d1);
        clearingHouse.payNetDebit{value: amt}(CYCLE_ID, amt, p1);
        core4Mica.setCollateral(d2, ETH_ASSET, 40 ether);
        vm.deal(address(core4Mica), 40 ether);

        vm.warp(block.timestamp + 2 hours + 1);

        ClearingHouse.DebtorEntry[] memory debtors = new ClearingHouse.DebtorEntry[](1);
        debtors[0] = ClearingHouse.DebtorEntry({debtor: d2, netDebit: amt, proof: p2});
        vm.prank(OPERATOR);
        clearingHouse.settleDefaultsFromCollateralBatch(CYCLE_ID, debtors);

        // Cannot finalize (under-funded); operator drives it terminal instead.
        vm.expectEmit(true, false, false, true);
        emit ClearingHouse.CycleShortfall(CYCLE_ID, 140 ether, total);
        vm.prank(OPERATOR);
        clearingHouse.markCycleShortfall(CYCLE_ID);

        assertEq(uint8(clearingHouse.getCycle(CYCLE_ID).status), uint8(ClearingHouse.CycleStatus.Shortfall));

        // Each creditor receives a pro-rata share: 100 * 140/200 = 70.
        vm.prank(c1);
        clearingHouse.claimNetCredit(CYCLE_ID, amt, pc1);
        vm.prank(c2);
        clearingHouse.claimNetCredit(CYCLE_ID, amt, pc2);

        assertEq(c1.balance, 70 ether);
        assertEq(c2.balance, 70 ether);
        assertEq(clearingHouse.getCycle(CYCLE_ID).totalClaimedOut, 140 ether);
    }

    function test_MarkShortfallRevertsWhenFullyFunded() public {
        (, bytes32[] memory debtorProof,) = _commitEthCycle(NET_AMOUNT, NET_AMOUNT);
        vm.prank(DEBTOR);
        clearingHouse.payNetDebit{value: NET_AMOUNT}(CYCLE_ID, NET_AMOUNT, debtorProof);
        vm.warp(block.timestamp + 2 hours + 1);

        vm.prank(OPERATOR);
        vm.expectRevert(abi.encodeWithSelector(ClearingHouse.CycleFullyFunded.selector, NET_AMOUNT, NET_AMOUNT));
        clearingHouse.markCycleShortfall(CYCLE_ID);
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
