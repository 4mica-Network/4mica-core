// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Core4MicaTestBase} from "./Core4MicaTestBase.sol";
import {Core4Mica} from "../src/Core4Mica.sol";
import {ClearingHouse} from "../src/ClearingHouse.sol";

/// End-to-end settlement against the real Core4Mica + ClearingHouse + mock Aave, proving the
/// fix: a stablecoin default can be seized and the creditor made whole even when Aave
/// has zero withdrawable liquidity at the settlement instant.
contract ClearingHouseEscrowIntegrationTest is Core4MicaTestBase {
    ClearingHouse internal clearingHouse;

    uint64 internal constant CLEARING_HOUSE_ROLE = 10;
    bytes32 internal constant CYCLE_ID = keccak256("escrow-cycle");
    uint256 internal constant AMOUNT = 100e6;

    address internal constant DEBTOR = USER1; // funded + approved in the base setUp
    address internal constant CREDITOR = USER2;

    function setUp() public override {
        super.setUp();

        clearingHouse = new ClearingHouse(address(manager), address(core4Mica));

        // ClearingHouse may drive the Core4Mica settlement hooks.
        bytes4[] memory collateralSelectors = new bytes4[](6);
        collateralSelectors[0] = Core4Mica.seizeCollateral.selector;
        collateralSelectors[1] = Core4Mica.creditCollateral.selector;
        collateralSelectors[2] = Core4Mica.depositToEscrow.selector;
        collateralSelectors[3] = Core4Mica.creditFromEscrowScaled.selector;
        collateralSelectors[4] = Core4Mica.withdrawFromEscrow.selector;
        collateralSelectors[5] = Core4Mica.seizeUpTo.selector;
        for (uint256 i = 0; i < collateralSelectors.length; i++) {
            manager.setTargetFunctionRole(
                address(core4Mica), _asSingletonArray(collateralSelectors[i]), CLEARING_HOUSE_ROLE
            );
        }
        manager.grantRole(CLEARING_HOUSE_ROLE, address(clearingHouse), 0);

        // OPERATOR drives the cycle lifecycle.
        bytes4[] memory ops = new bytes4[](3);
        ops[0] = ClearingHouse.commitCycle.selector;
        ops[1] = ClearingHouse.settleDefaultsFromCollateralBatch.selector;
        ops[2] = ClearingHouse.fundCreditorsFromPoolBatch.selector;
        for (uint256 i = 0; i < ops.length; i++) {
            manager.setTargetFunctionRole(address(clearingHouse), _asSingletonArray(ops[i]), OPERATOR_ROLE);
        }
    }

    function _leaf(address participant, uint256 amount, ClearingHouse.ParticipantRole role)
        internal
        view
        returns (bytes32)
    {
        return clearingHouse.participantLeaf(CYCLE_ID, address(usdc), participant, amount, role);
    }

    function _commutativeRoot(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function test_DefaultSeizedAndCreditorFundedWithZeroAaveLiquidity() public {
        // Debtor posts stablecoin collateral, then never pays its net debit.
        vm.prank(DEBTOR);
        core4Mica.depositStablecoin(address(usdc), AMOUNT);

        bytes32 debtorLeaf = _leaf(DEBTOR, AMOUNT, ClearingHouse.ParticipantRole.NetDebtor);
        bytes32 creditorLeaf = _leaf(CREDITOR, AMOUNT, ClearingHouse.ParticipantRole.NetCreditor);
        bytes32 root = _commutativeRoot(debtorLeaf, creditorLeaf);

        bytes32[] memory debtorProof = new bytes32[](1);
        debtorProof[0] = creditorLeaf;
        bytes32[] memory creditorProof = new bytes32[](1);
        creditorProof[0] = debtorLeaf;

        vm.prank(OPERATOR);
        clearingHouse.commitCycle(
            CYCLE_ID,
            address(usdc),
            root,
            AMOUNT,
            AMOUNT,
            uint64(block.timestamp + 1 hours),
            uint64(block.timestamp + 2 hours)
        );

        vm.warp(block.timestamp + 2 hours + 1);

        // The C03 condition: Aave has no withdrawable liquidity at the settlement instant.
        mockPool.setAvailableLiquidity(address(usdc), 0);

        // Seizing the defaulter still succeeds — it re-attributes scaled aTokens into escrow
        // rather than withdrawing underlying, so it does not touch Aave liquidity.
        ClearingHouse.DebtorEntry[] memory debtors = new ClearingHouse.DebtorEntry[](1);
        debtors[0] = ClearingHouse.DebtorEntry({debtor: DEBTOR, netDebit: AMOUNT, proof: debtorProof});
        vm.prank(OPERATOR);
        clearingHouse.settleDefaultsFromCollateralBatch(CYCLE_ID, debtors);

        ClearingHouse.OnchainCycle memory afterSeize = clearingHouse.getCycle(CYCLE_ID);
        assertEq(afterSeize.totalResolvedDebit, AMOUNT, "debt resolved despite zero liquidity");
        assertEq(afterSeize.totalDefaultCovered, AMOUNT, "default covered");
        assertGt(core4Mica.escrowScaledBalance(address(usdc)), 0, "value held in escrow");

        // Creditor is made whole in collateral form straight from escrow — also no Aave needed.
        ClearingHouse.CreditorEntry[] memory creditors = new ClearingHouse.CreditorEntry[](1);
        creditors[0] = ClearingHouse.CreditorEntry({creditor: CREDITOR, netCredit: AMOUNT, proof: creditorProof});
        vm.prank(OPERATOR);
        clearingHouse.fundCreditorsFromPoolBatch(CYCLE_ID, creditors);

        assertEq(core4Mica.collateral(CREDITOR, address(usdc)), AMOUNT, "creditor made whole");

        clearingHouse.finalizeCycle(CYCLE_ID);
        ClearingHouse.OnchainCycle memory finalized = clearingHouse.getCycle(CYCLE_ID);
        assertEq(uint8(finalized.status), uint8(ClearingHouse.CycleStatus.Finalized), "cycle finalized");
    }
}
