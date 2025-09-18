// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
import "../src/Core4Mica.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {IAccessManaged} from "@openzeppelin/contracts/access/manager/IAccessManaged.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";
import {BlsHelper} from "../src/BlsHelpers.sol";

contract Core4MicaTest is Test {
    Core4Mica core4Mica;
    AccessManager manager;
    address user1 = address(0x111);
    address user2 = address(0x222);
    address operator = address(0x333);

    uint64 public constant OPERATOR_ROLE = 9;

    bytes32 public TEST_PRIVATE_KEY = bytes32(0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3);
    BLS.G1Point public TEST_PUBLIC_KEY = BlsHelper.getPublicKey(TEST_PRIVATE_KEY);

    function setUp() public {
        manager = new AccessManager(address(this));
        core4Mica = new Core4Mica(address(manager), TEST_PUBLIC_KEY);

        // always deal user1 5 ether
        vm.deal(user1, 5 ether);

        // grant operator the OPERATOR_ROLE so we can record Payments
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.recordPayment.selector),
            OPERATOR_ROLE
        );
        manager.grantRole(OPERATOR_ROLE, address(operator), 0);
    }

    // helpers

    function _asSingletonArray(
        bytes4 selector
    ) internal pure returns (bytes4[] memory arr) {
        arr = new bytes4[](1);
        arr[0] = selector;
    }

    // === Admin Config ===

    function AccessUnauthorizedError(address accessor) public returns (bytes memory) {
        return abi.encodeWithSelector(IAccessManaged.AccessManagedUnauthorized.selector, address(accessor));
    }

    function test_SetWithdrawalGracePeriod() public {
        uint256 newGrace = 23 days;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.WithdrawalGracePeriodUpdated(newGrace);
        core4Mica.setWithdrawalGracePeriod(newGrace);

        assertEq(core4Mica.withdrawalGracePeriod(), newGrace);
    }

    function test_SetWithdrawalGracePeriod_Revert_Zero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setWithdrawalGracePeriod(0);
    }

    function test_SetWithdrawalGracePeriod_Revert_User_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(AccessUnauthorizedError(user1));
        core4Mica.setWithdrawalGracePeriod(2 days);
    }

    function test_SetWithdrawalGracePeriod_Revert_Operator_Unauthorized() public {
        vm.prank(operator);
        vm.expectRevert(AccessUnauthorizedError(operator));
        core4Mica.setWithdrawalGracePeriod(2 days);
    }

    function test_SetWithdrawalGracePeriod_Revert_IllegalValue() public {
        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setWithdrawalGracePeriod(21 days + 6 hours);
    }

    function test_SetRemunerationGracePeriod() public {
        uint256 newGrace = 2 days;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.RemunerationGracePeriodUpdated(newGrace);
        core4Mica.setRemunerationGracePeriod(newGrace);

        assertEq(core4Mica.remunerationGracePeriod(), newGrace);
    }

    function test_SetRemunerationGracePeriod_Revert_Zero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setRemunerationGracePeriod(0);
    }

    function test_SetRemunerationGracePeriod_Revert_User_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(AccessUnauthorizedError(user1));
        core4Mica.setRemunerationGracePeriod(2 days);
    }

    function test_SetRemunerationGracePeriod_Revert_Operator_Unauthorized() public {
        vm.prank(operator);
        vm.expectRevert(AccessUnauthorizedError(operator));
        core4Mica.setRemunerationGracePeriod(2 days);
    }

    function test_SetRemunerationGracePeriod_Revert_IllegalValue() public {
        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setRemunerationGracePeriod(21 days + 6 hours);
    }

    function test_SetTabExpirationTime() public {
        uint256 newGrace = 20 days;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.TabExpirationTimeUpdated(newGrace);
        core4Mica.setTabExpirationTime(newGrace);

        assertEq(core4Mica.tabExpirationTime(), newGrace);
    }

    function test_SetTabExpirationTime_Revert_Zero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setTabExpirationTime(0);
    }

    function test_SetTabExpirationTime_Revert_User_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(AccessUnauthorizedError(user1));
        core4Mica.setTabExpirationTime(2 days);
    }

    function test_SetTabExpirationTime_Revert_Operator_Unauthorized() public {
        vm.prank(operator);
        vm.expectRevert(AccessUnauthorizedError(operator));
        core4Mica.setTabExpirationTime(2 days);
    }

    function test_SetTabExpirationTime_Revert_IllegalValue() public {
        // tabExpirationTime < remunerationGracePeriod
        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setTabExpirationTime(14 days);

        // tabExpirationTime + synchronizationDelay > withdrawalGracePeriod
        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setTabExpirationTime(21 days + 18 hours);
    }

    function test_SetSynchronizationDelay() public {
        uint256 newGrace = 5 hours;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.SynchronizationDelayUpdated(newGrace);
        core4Mica.setSynchronizationDelay(newGrace);

        assertEq(core4Mica.synchronizationDelay(), newGrace);
    }

    function test_SetSynchronizationDelay_Revert_Zero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setSynchronizationDelay(0);
    }

    function test_SetSynchronizationDelay_Revert_User_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(AccessUnauthorizedError(user1));
        core4Mica.setSynchronizationDelay(5 hours);
    }

    function test_SetSynchronizationDelay_Revert_Operator_Unauthorized() public {
        vm.prank(operator);
        vm.expectRevert(AccessUnauthorizedError(operator));
        core4Mica.setSynchronizationDelay(5 hours);
    }

    function test_SetSynchronizationDelay_Revert_IllegalValue() public {
        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setSynchronizationDelay(1 days);
    }

    function newKey() public returns (BLS.G1Point memory) {
        return BLS.G1Point(
            bytes32(0x1000000000000000000000000000000000000000000000000000000000000001),
            bytes32(0x0100000000000000000000000000000000000000000000000000000000000010),
            bytes32(0x0010000000000000000000000000000000000000000000000000000000000100),
            bytes32(0x0001000000000000000000000000000000000000000000000000000000001000)
        );
    }

    function test_SetVerificationKey() public {
        BLS.G1Point memory key = newKey();
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.VerificationKeyUpdated(key);

        core4Mica.setGuaranteeVerificationKey(key);

        (bytes32 x_a, bytes32 x_b, bytes32 y_a, bytes32 y_b) = core4Mica.GUARANTEE_VERIFICATION_KEY();
        assertEq(x_a, key.x_a);
        assertEq(x_b, key.x_b);
        assertEq(y_a, key.y_a);
        assertEq(x_b, key.x_b);
    }

    function test_SetVerificationKey_Revert_User_Unauthorized() public {
        BLS.G1Point memory key = newKey();
        vm.expectRevert(AccessUnauthorizedError(user1));
        vm.prank(user1);
        core4Mica.setGuaranteeVerificationKey(key);
    }

    function test_SetVerificationKey_Revert_Operator_Unauthorized() public {
        BLS.G1Point memory key = newKey();
        vm.expectRevert(AccessUnauthorizedError(operator));
        vm.prank(operator);
        core4Mica.setGuaranteeVerificationKey(key);
    }

    // === Deposit ===

    function test_Deposit() public {
        vm.startPrank(user1);

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.CollateralDeposited(user1, 1 ether);

        core4Mica.deposit{value: 1 ether}();

        (uint256 collateral, uint256 withdrawTimestamp, uint256 withdrawAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 1 ether, "Total collateral mismatch");
        assertEq(withdrawTimestamp, 0, "Withdrawal timestamp should be 0");
        assertEq(withdrawAmount, 0, "Withdrawal amount should be 0");
    }

    function test_Deposit_MultipleDepositsAccumulate() public {
        vm.startPrank(user1);
        core4Mica.deposit{value: 1 ether}();
        core4Mica.deposit{value: 1 ether}();
        core4Mica.deposit{value: 3 ether}();

        (uint256 collateral, uint256 withdrawTimestamp, uint256 withdrawAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 5 ether, "Total collateral mismatch");
        assertEq(withdrawTimestamp, 0, "Withdrawal timestamp should be 0");
        assertEq(withdrawAmount, 0, "Withdrawal amount should be 0");
    }

    // === Request Withdrawal ===

    function test_RequestWithdrawal() public {
        vm.startPrank(user1);
        core4Mica.deposit{value: 2 ether}();

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.WithdrawalRequested(user1, block.timestamp, 1 ether);

        core4Mica.requestWithdrawal(1 ether);

        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 2 ether);
        assertEq(withdrawalTimestamp, block.timestamp);
        assertEq(withdrawalAmount, 1 ether);
    }

    function test_RequestWithdrawal_OverwritesPrevious() public {
        vm.startPrank(user1);
        core4Mica.deposit{value: 5 ether}();

        core4Mica.requestWithdrawal(1 ether);

        vm.warp(block.timestamp + 2500);

        core4Mica.requestWithdrawal(3 ether);

        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 5 ether);
        assertEq(withdrawalTimestamp, block.timestamp);
        assertEq(withdrawalAmount, 3 ether);
    }

    // === Request Withdrawal: Failure cases ===

    function test_RequestWithdrawal_Revert_AmountZero() public {
        vm.startPrank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.requestWithdrawal(0);
    }

    function test_RequestWithdrawal_Revert_TooMuch() public {
        vm.startPrank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.expectRevert(Core4Mica.InsufficientAvailable.selector);
        core4Mica.requestWithdrawal(2 ether);
    }

    // === Cancel Withdrawal ===

    function test_CancelWithdrawal() public {
        vm.startPrank(user1);
        core4Mica.deposit{value: 2 ether}();
        core4Mica.requestWithdrawal(1 ether);

        vm.expectEmit(false, false, false, true);
        emit Core4Mica.WithdrawalCanceled(user1);

        core4Mica.cancelWithdrawal();
        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 2 ether);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    // === Cancel Withdrawal: Failure cases ===

    function test_CancelWithdrawal_Revert_NoWithdrawalRequested() public {
        vm.startPrank(user1);
        core4Mica.deposit{value: 2 ether}();

        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        core4Mica.cancelWithdrawal();
    }

    // === Finalize Withdrawal ===

    function test_FinalizeWithdrawal_FullAmount() public {
        vm.startPrank(user1);
        core4Mica.deposit{value: 2 ether}();
        core4Mica.requestWithdrawal(1 ether);

        // fast forward > grace period
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.CollateralWithdrawn(user1, 1 ether);

        assertEq(user1.balance, 3 ether);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, 4 ether);

        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 1 ether);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    function test_FinalizeWithdrawal_NotFullAmount() public {
        vm.prank(user1);
        core4Mica.deposit{value: 5 ether}();

        uint256 tab_timestamp = 1;
        uint256 withdrawal_timestamp = 1;
        vm.prank(user1);
        core4Mica.requestWithdrawal(4 ether);

        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, tab_timestamp, user1, user2, 17, 3 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        core4Mica.remunerate(g, signature);
        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 2 ether);
        assertEq(withdrawalTimestamp, withdrawal_timestamp);
        assertEq(withdrawalAmount, 1 ether);

        // fast forward > grace period
        vm.warp(tab_timestamp + core4Mica.withdrawalGracePeriod());

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.CollateralWithdrawn(user1, 1 ether);

        assertEq(user1.balance, 0 ether);
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, 1 ether);

        (collateral, withdrawalTimestamp, withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 1 ether);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    function test_FinalizeWithdrawal_CollateralGone() public {
        vm.prank(user1);
        core4Mica.deposit{value: 5 ether}();

        // user promised something to recipient as part of tab
        uint256 tab_timestamp = 1;

        // user requests withdrawal
        vm.prank(user1);
        core4Mica.requestWithdrawal(2 ether);

        // fast forward > remuneration period
        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);

        // user did not pay their promise, so
        // recipient comes to collect remuneration
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, tab_timestamp, user1, user2, 17, 5 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        core4Mica.remunerate(g, signature);

        // fast forward > grace period
        vm.warp(tab_timestamp + core4Mica.withdrawalGracePeriod());

        // user gets nothing because their balance was used during remuneration
        assertEq(user1.balance, 0 ether);
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, 0 ether);

        (uint256 collateral, uint256 withdrawalTimestamp, uint256 withdrawalAmount) = core4Mica.getUser(user1);
        assertEq(collateral, 0);
        assertEq(withdrawalTimestamp, 0);
        assertEq(withdrawalAmount, 0);
    }

    function test_FinalizeWithdrawal_FullCollateral() public {
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.prank(user1);
        core4Mica.requestWithdrawal(1 ether);

        // Fast-forward past withdrawalGracePeriod
        vm.warp(block.timestamp + core4Mica.withdrawalGracePeriod());

        // Expect event
        vm.expectEmit(true, true, false, true);
        emit Core4Mica.CollateralWithdrawn(user1, 1 ether);

        vm.prank(user1);
        core4Mica.finalizeWithdrawal();

        (uint256 collateral,,) = core4Mica.getUser(user1);
        assertEq(collateral, 0, "Collateral not deleted");
        assertEq(address(user1).balance, 5 ether, "User did not receive full collateral");
    }

    // === Finalize Withdrawal: Failure cases ===

    function test_FinalizeWithdrawal_Revert_NoWithdrawalRequested() public {
        vm.startPrank(user1);
        core4Mica.deposit{value: 2 ether}();

        vm.expectRevert(Core4Mica.NoWithdrawalRequested.selector);
        core4Mica.finalizeWithdrawal();
    }

    function test_FinalizeWithdrawal_Revert_GracePeriodNotElapsed() public {
        vm.startPrank(user1);
        core4Mica.deposit{value: 4 ether}();
        core4Mica.requestWithdrawal(2 ether);

        vm.expectRevert(Core4Mica.GracePeriodNotElapsed.selector);
        core4Mica.finalizeWithdrawal();
    }

    // === Record payment ===

    function test_RecordPayment() public {
        (uint256 paid, bool remunerated) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 0);
        assertFalse(remunerated);

        vm.prank(operator);
        core4Mica.recordPayment(0x1234, 1 ether);

        (paid, remunerated) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 1 ether);
        assertFalse(remunerated);

        vm.prank(operator);
        core4Mica.recordPayment(0x1234, 2 ether);

        (paid, remunerated) = core4Mica.getPaymentStatus(0x1234);
        assertEq(paid, 3 ether);
        assertFalse(remunerated);
    }

    // === Record payment: failure cases ===

    function test_RecordPayment_Revert_Unauthorized() public {
        vm.prank(user1);
        vm.expectRevert(AccessUnauthorizedError(user1));
        core4Mica.recordPayment(0x1234, 0);
    }

    function test_RecordPayment_Revert_AmountZero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        vm.prank(operator);
        core4Mica.recordPayment(0x1234, 0);
    }

    // === Remuneration ===

    function test_Remunerate() public {
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tab_id = 0x1234;
        uint256 req_id = 17;
        uint256 tab_timestamp = 1;
        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);

        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, tab_timestamp, user1, user2, req_id, 0.5 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(tab_id, 0.5 ether);

        vm.prank(user2);
        core4Mica.remunerate(g, signature);

        assertEq(user2.balance, 0.5 ether);
        (uint256 collateral,, ) = core4Mica.getUser(user1);
        assertEq(collateral, 0.5 ether);

        (uint256 paid, bool remunerated) = core4Mica.getPaymentStatus(tab_id);
        assertEq(paid, 0);
        assertEq(remunerated, true);
    }

    function test_Remunerate_PartiallyPaidTab() public {
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tab_id = 0x1234;
        uint256 req_id = 17;

        // core contract is informed that user1 paid user2 half of the tab
        vm.prank(operator);
        core4Mica.recordPayment(tab_id, 0.25 ether);

        uint256 tab_timestamp = 1;
        vm.warp(tab_timestamp + core4Mica.remunerationGracePeriod() + 5);

        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, tab_timestamp, user1, user2, req_id, 0.5 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(tab_id, 0.5 ether);

        vm.prank(user2);
        core4Mica.remunerate(g, signature);

        // check: user2 is still remunerated for the full amount
        assertEq(user2.balance, 0.5 ether);
        (uint256 collateral,, ) = core4Mica.getUser(user1);
        assertEq(collateral, 0.5 ether);
    }

    function test_Remunerate_GuaranteeIssuedBeforeWithdrawalRequestSynchronization() public {
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        // One day later, user requests a withdrawal
        vm.warp(vm.getBlockTimestamp() + 1 days);
        vm.prank(user1);
        core4Mica.requestWithdrawal(0.75 ether);

        // Less than synchronizationDelay time later, a guarantee is issued.
        vm.warp(vm.getBlockTimestamp() + core4Mica.synchronizationDelay() - 1);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, vm.getBlockTimestamp(), user1, user2, 17, 0.5 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        // user does not pay their tab; 15 days later recipient requests remuneration
        vm.warp(vm.getBlockTimestamp() + 15 days);
        vm.prank(user2);
        core4Mica.remunerate(g, signature);

        // because the guarantee was issued less than synchronizationDelay after the withdrawal request, the amount
        // is deducted from the request amount
        (uint256 collateral,, uint256 withdrawal_amount) = core4Mica.getUser(user1);
        assertEq(collateral, 0.5 ether);
        assertEq(withdrawal_amount, 0.25 ether);

        // Then a couple days later, user can withdraw the remainder
        vm.warp(vm.getBlockTimestamp() + 7 days);
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, 4.25 ether);
        (collateral,,) = core4Mica.getUser(user1);
        assertEq(collateral, 0.25 ether);
    }

    function test_Remunerate_GuaranteeIssuedAfterWithdrawalRequestSynchronization() public {
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        // One day later, user requests a withdrawal
        vm.warp(vm.getBlockTimestamp() + 1 days);
        vm.prank(user1);
        core4Mica.requestWithdrawal(0.75 ether);

        // More than synchronizationDelay time later, a guarantee is issued.
        // The amount must be less than or equal to the total collateral minus the withdrawal amount.
        // This should be guaranteed by the guarantee issuing party.
        vm.warp(vm.getBlockTimestamp() + core4Mica.synchronizationDelay() + 1);
        uint256 amount = 0.24 ether;
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, vm.getBlockTimestamp(), user1, user2, 17, amount);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        (uint256 collateral,, uint256 withdrawal_amount) = core4Mica.getUser(user1);
        assertLe(amount, collateral - withdrawal_amount);

        // user does not pay their tab; 15 days later recipient requests remuneration
        vm.warp(vm.getBlockTimestamp() + 15 days);
        vm.prank(user2);
        core4Mica.remunerate(g, signature);
        assertEq(user2.balance, 0.24 ether);

        // because the guarantee was issued more than synchronizationDelay after the withdrawal request, the amount
        // is NOT deducted from the request amount
        (collateral,, withdrawal_amount) = core4Mica.getUser(user1);
        assertEq(collateral, 0.76 ether);
        assertEq(withdrawal_amount, 0.75 ether);

        // Then a couple days later, user can withdraw the full amount
        vm.warp(vm.getBlockTimestamp() + 7 days);
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        assertEq(user1.balance, 4.75 ether);
        (collateral,, withdrawal_amount) = core4Mica.getUser(user1);
        assertEq(collateral, 0.01 ether);
    }

    // === Remunerate: Failure cases ===

    function test_Remunerate_Revert_AmountZero() public {
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        vm.expectRevert(Core4Mica.AmountZero.selector);
        vm.prank(user2);
        core4Mica.remunerate(g, signature);
    }

    function test_Remunerate_Revert_InvalidRecipient() public {
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, address(0), 17, 0.5 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        vm.expectRevert(Core4Mica.InvalidRecipient.selector);
        vm.prank(user2);
        core4Mica.remunerate(g, signature);
    }

    function test_Remunerate_Revert_NotYetOverdue() public {
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0.5 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        vm.expectRevert(Core4Mica.TabNotYetOverdue.selector);
        vm.prank(user2);
        core4Mica.remunerate(g, signature);
    }

    function test_Remunerate_Revert_TabExpired() public {
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.tabExpirationTime() + 5);

        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0.5 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        vm.expectRevert(Core4Mica.TabExpired.selector);
        vm.prank(user2);
        core4Mica.remunerate(g, signature);
    }

    function test_Remunerate_Revert_PreviouslyRemunerated() public {
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        uint256 tab_id = 0x1234;
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, 0, user1, user2, 17, 0.5 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);
        core4Mica.remunerate(g, signature);

        vm.expectRevert(Core4Mica.TabPreviouslyRemunerated.selector);

        // second remuneration attempt on the same tab
        g = Core4Mica.Guarantee(tab_id, 0, user1, user2, 37, 0.75 ether);
        vm.prank(user2);
        core4Mica.remunerate(g, signature);
    }

    function test_Remunerate_Revert_TabAlreadyPaid() public {
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        uint256 tab_id = 0x1234;
        vm.prank(operator);
        core4Mica.recordPayment(tab_id, 0.6 ether);

        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(tab_id, 0, user1, user2, 17, 0.5 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        vm.expectRevert(Core4Mica.TabAlreadyPaid.selector);
        vm.prank(user2);
        core4Mica.remunerate(g, signature);
    }

    function test_Remunerate_Revert_InvalidSignature() public {
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0.5 ether);
        bytes32 invalid_key = bytes32(0x1234123412341234123412341234123412341234123412341234123412341234);
        BLS.G2Point memory invalid_signature = BlsHelper.signGuarantee(g, invalid_key);

        vm.expectRevert(Core4Mica.InvalidSignature.selector);
        vm.prank(user2);
        core4Mica.remunerate(g, invalid_signature);
    }

    function test_Remunerate_Revert_DoubleSpending() public {
        // user1 deposits fewer than the later remuneration claim
        vm.prank(user1);
        core4Mica.deposit{value: 0.25 ether}();

        vm.warp(core4Mica.remunerationGracePeriod() + 5);

        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, 0, user1, user2, 17, 0.5 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        vm.expectRevert(Core4Mica.DoubleSpendingDetected.selector);
        vm.prank(user2);
        core4Mica.remunerate(g, signature);
    }

    // === Double spend prevention tests ===

    function test_DoubleSpend_IllegalGuarantee() public {
        // User deposits collateral
        vm.prank(user1);
        core4Mica.deposit{value: 1 ether}();

        // Later, user requests withdrawal
        vm.warp(vm.getBlockTimestamp() + 5 days);
        vm.prank(user1);
        core4Mica.requestWithdrawal(0.75 ether);

        (uint256 initial_collateral, uint256 withdrawal_timestamp, uint256 withdrawal_amount) = core4Mica.getUser(user1);

        // Quite some time after the withdrawal request, a guarantee is signed.
        uint256 delay = 2 days;
        vm.warp(vm.getBlockTimestamp() + delay);
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, vm.getBlockTimestamp(), user1, user2, 17, 0.5 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);

        // The user does not pay this.
        // Also, the recipient (user2) has not requested remuneration yet.
        vm.warp(vm.getBlockTimestamp() + 20 days);

        // Now user withdraws their funds, equal to all funds initially requested be released.
        vm.prank(user1);
        core4Mica.finalizeWithdrawal();
        (uint256 collateral,,) = core4Mica.getUser(user1);
        assertEq(collateral, 0.25 ether);
        assertEq(user1.balance, 4.75 ether);

        // some time later, recipient decides to remunerate after all
        vm.warp(vm.getBlockTimestamp() + 6 hours);
        vm.prank(user2);

        // However, this remuneration cannot take place, since insufficient user funds are available.
        // Hence, there is double spending taking place here.
        vm.expectRevert(Core4Mica.DoubleSpendingDetected.selector);
        core4Mica.remunerate(g, signature);

        // This double spend took place because
        // 1. a guarantee was issued for a tab that started more than synchronizationDelay after
        //    the withdrawal request came in, and
        assertGt(g.tab_timestamp, withdrawal_timestamp + core4Mica.synchronizationDelay());
        // 2. because the guarantee's amount exceeded the amount of collateral that would be left after the withdrawal
        assertGt(g.amount, initial_collateral - withdrawal_amount);
        // Hence, the guarantee was illegally issued.
    }

    // === Verify Guarantee Signature ===

    function test_VerifyGuaranteeSignature() public {
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, vm.getBlockTimestamp(), user1, user2, 17, 3 ether);
        BLS.G2Point memory signature = BlsHelper.signGuarantee(g, TEST_PRIVATE_KEY);
        assert(core4Mica.verifyGuaranteeSignature(g, signature));
    }

    function test_VerifyGuaranteeSignature_InvalidGuarantee() public {
        Core4Mica.Guarantee memory g1 = Core4Mica.Guarantee(0x1234, vm.getBlockTimestamp(), user1, user2, 17, 3 ether);
        BLS.G2Point memory signature_g1 = BlsHelper.signGuarantee(g1, TEST_PRIVATE_KEY);

        Core4Mica.Guarantee memory g2 = Core4Mica.Guarantee(0x1234, vm.getBlockTimestamp(), user1, user2, 17, 4 ether);
        assert(!core4Mica.verifyGuaranteeSignature(g2, signature_g1));
    }

    function test_VerifyGuaranteeSignature_InvalidSigningKey() public {
        Core4Mica.Guarantee memory g = Core4Mica.Guarantee(0x1234, vm.getBlockTimestamp(), user1, user2, 17, 3 ether);

        bytes32 otherKey = bytes32(0x5B85C3922AB2E2738F196576D00A8583CBE4A1C6BCA85DDFC65438574F42377C);
        BLS.G2Point memory signature_with_other_key = BlsHelper.signGuarantee(g, otherKey);
        assert(!core4Mica.verifyGuaranteeSignature(g, signature_with_other_key));
    }

    // === Fallback and Receive revert ===

    function test_Receive_Reverts_TransferFailed() public {
        vm.prank(user1);
        (bool ok, bytes memory mem) = address(core4Mica).call{value: 0.25 ether}("");
        assert(!ok);
        assertEq(mem, abi.encodeWithSelector(Core4Mica.DirectTransferNotAllowed.selector));
    }

    function test_Fallback_Reverts_TransferFailed() public {
        vm.prank(user1);
        (bool ok,) = address(core4Mica).call{value: 0.25 ether}(abi.encodeWithSignature("nonExistentFunction()"));
        assert(!ok);
    }
}
