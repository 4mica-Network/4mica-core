// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Core4MicaTestBase} from "./Core4MicaTestBase.sol";
import {Core4Mica} from "../src/Core4Mica.sol";

/// Regression tests for the stablecoin seizure dust edge.
///
/// A scaled aToken position can back up to ~1 base unit less than its recorded principal: Aave
/// mints scaled by rounding `amount / index` DOWN at deposit, while `principal` is stored at face
/// value and the withdrawable bound floors net yield at 0. In that state `seizeUpTo` used to round
/// the scaled deduction UP past the user's scaled balance and revert (`UserScaledBalanceUnderflow`),
/// which left the debtor unresolved and wedged the whole settlement cycle. `seizeUpTo` must now
/// clamp to the position and resolve the debtor; the strict `seizeCollateral` keeps reverting.
contract Core4MicaSeizeDustTest is Core4MicaTestBase {
    uint256 internal constant DEPOSIT = 100e6;
    // index = 3.0: deposit 100e6 mints scaled floor(100e6/3) = 33_333_333, which backs
    // floor(33_333_333 * 3) = 99_999_999 = DEPOSIT - 1. Seizing DEPOSIT rounds scaled up to
    // 33_333_334 > 33_333_333, the exact underflow the fix guards against.
    uint256 internal constant DUST_INDEX = 3e27;
    uint256 internal constant DUST_SCALED = 33_333_333;
    uint256 internal constant DUST_BACKED = 99_999_999;

    function setUp() public override {
        super.setUp();
        // Grant both seize hooks to OPERATOR, which stands in for the ClearingHouse.
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = Core4Mica.seizeUpTo.selector;
        selectors[1] = Core4Mica.seizeCollateral.selector;
        for (uint256 i = 0; i < selectors.length; i++) {
            manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(selectors[i]), OPERATOR_ROLE);
        }
    }

    function _assertReconciled(address asset) internal view {
        uint256 observed = core4Mica.contractScaledATokenBalance(asset);
        uint256 tracked = core4Mica.totalUserScaledBalance(asset) + core4Mica.protocolScaledBalance(asset)
            + core4Mica.escrowScaledBalance(asset) + core4Mica.surplusScaledBalance(asset);
        uint256 diff = observed > tracked ? observed - tracked : tracked - observed;
        assertLe(diff, core4Mica.reconciliationDustToleranceScaled(), "reconciliation drift");
    }

    function _depositDust() internal {
        // Set the reserve index before the deposit so the mint rounds down into the dust state.
        mockPool.setNormalizedIncome(address(usdc), DUST_INDEX);
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), DEPOSIT);

        // Sanity: principal is the face value, but the position backs one base unit less, and the
        // withdrawable bound still optimistically reports the full principal.
        assertEq(core4Mica.principalBalance(USER1, address(usdc)), DEPOSIT, "principal");
        assertEq(core4Mica.totalUserScaledBalance(address(usdc)), DUST_SCALED, "scaled");
        assertEq(core4Mica.withdrawableBalance(USER1, address(usdc)), DEPOSIT, "withdrawable overstates by 1");
    }

    /// The fix: seizing the full (overstated) withdrawable no longer reverts; it takes the whole
    /// position, reports what it truly backs (principal - 1), and fully resolves the debtor.
    function test_SeizeUpTo_DustPosition_DoesNotRevert() public {
        _depositDust();

        uint256 escrowBefore = core4Mica.escrowScaledBalance(address(usdc));

        vm.prank(OPERATOR);
        uint256 seized = core4Mica.seizeUpTo(USER1, address(usdc), DEPOSIT);

        // Recovered the true backed value, not the fictional face value.
        assertEq(seized, DUST_BACKED, "seized backs principal - 1");

        // Debtor fully resolved: position wiped on both ledgers, nothing left to claim.
        assertEq(core4Mica.principalBalance(USER1, address(usdc)), 0, "principal zeroed");
        assertEq(core4Mica.withdrawableBalance(USER1, address(usdc)), 0, "withdrawable zeroed");
        assertEq(core4Mica.totalUserScaledBalance(address(usdc)), 0, "user scaled zeroed");

        // The whole scaled position moved into escrow.
        assertEq(
            core4Mica.escrowScaledBalance(address(usdc)) - escrowBefore, DUST_SCALED, "escrow took full position"
        );
        _assertReconciled(address(usdc));
    }

    /// Demonstrates that the dust state genuinely triggers the underflow on the strict path, so
    /// `seizeUpTo`'s success above is the clamp at work, not a benign state. `seizeCollateral`
    /// keeps its revert-on-shortfall contract.
    function test_SeizeCollateral_DustPosition_StillReverts() public {
        _depositDust();

        vm.prank(OPERATOR);
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UserScaledBalanceUnderflow.selector,
                address(usdc),
                USER1,
                DUST_SCALED + 1, // round-up of DEPOSIT = 33_333_334
                DUST_SCALED
            )
        );
        core4Mica.seizeCollateral(USER1, address(usdc), DEPOSIT);
    }

    /// Property: for any deposit and reserve index, seizing up to the reported withdrawable never
    /// reverts and always fully resolves the debtor, leaving the ledger reconciled.
    function testFuzz_SeizeUpTo_WithinWithdrawable_NeverReverts(uint256 depositAmt, uint256 indexNum) public {
        depositAmt = bound(depositAmt, 1e6, 1_000_000e6);
        uint256 index = bound(indexNum, 1e27, 5e27);

        mockPool.setNormalizedIncome(address(usdc), index);
        vm.prank(USER1);
        core4Mica.depositStablecoin(address(usdc), depositAmt);

        uint256 withdrawable = core4Mica.withdrawableBalance(USER1, address(usdc));

        // Must not revert for any amount within the reported withdrawable.
        vm.prank(OPERATOR);
        uint256 seized = core4Mica.seizeUpTo(USER1, address(usdc), withdrawable);

        assertLe(seized, withdrawable, "never over-reports recovery");
        // Seizing the full withdrawable resolves the debtor entirely.
        assertEq(core4Mica.principalBalance(USER1, address(usdc)), 0, "principal zeroed");
        assertEq(core4Mica.totalUserScaledBalance(address(usdc)), 0, "user scaled zeroed");
        _assertReconciled(address(usdc));
    }
}
