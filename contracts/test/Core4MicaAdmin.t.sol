// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";

contract Core4MicaAdminTest is Core4MicaTestBase {
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
        vm.prank(USER1);
        vm.expectRevert(AccessUnauthorizedError(USER1));
        core4Mica.setWithdrawalGracePeriod(2 days);
    }

    function test_SetWithdrawalGracePeriod_Revert_Operator_Unauthorized()
        public
    {
        vm.prank(OPERATOR);
        vm.expectRevert(AccessUnauthorizedError(OPERATOR));
        core4Mica.setWithdrawalGracePeriod(2 days);
    }

    function test_SetWithdrawalGracePeriod_Revert_IllegalValue() public {
        uint256 invalid = core4Mica.synchronizationDelay() +
            core4Mica.tabExpirationTime();
        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setWithdrawalGracePeriod(invalid);
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
        vm.prank(USER1);
        vm.expectRevert(AccessUnauthorizedError(USER1));
        core4Mica.setRemunerationGracePeriod(2 days);
    }

    function test_SetRemunerationGracePeriod_Revert_Operator_Unauthorized()
        public
    {
        vm.prank(OPERATOR);
        vm.expectRevert(AccessUnauthorizedError(OPERATOR));
        core4Mica.setRemunerationGracePeriod(2 days);
    }

    function test_SetRemunerationGracePeriod_Revert_IllegalValue() public {
        uint256 invalid = core4Mica.tabExpirationTime();
        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setRemunerationGracePeriod(invalid);
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
        vm.prank(USER1);
        vm.expectRevert(AccessUnauthorizedError(USER1));
        core4Mica.setTabExpirationTime(2 days);
    }

    function test_SetTabExpirationTime_Revert_Operator_Unauthorized() public {
        vm.prank(OPERATOR);
        vm.expectRevert(AccessUnauthorizedError(OPERATOR));
        core4Mica.setTabExpirationTime(2 days);
    }

    function test_SetTabExpirationTime_Revert_IllegalValue() public {
        uint256 invalidLow = core4Mica.remunerationGracePeriod();
        uint256 invalidHigh = core4Mica.withdrawalGracePeriod() -
            core4Mica.synchronizationDelay();

        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setTabExpirationTime(invalidLow);

        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setTabExpirationTime(invalidHigh);
    }

    function test_SetSynchronizationDelay() public {
        uint256 newDelay = 5 hours;
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.SynchronizationDelayUpdated(newDelay);
        core4Mica.setSynchronizationDelay(newDelay);

        assertEq(core4Mica.synchronizationDelay(), newDelay);
    }

    function test_SetSynchronizationDelay_Revert_Zero() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setSynchronizationDelay(0);
    }

    function test_SetSynchronizationDelay_Revert_User_Unauthorized() public {
        vm.prank(USER1);
        vm.expectRevert(AccessUnauthorizedError(USER1));
        core4Mica.setSynchronizationDelay(5 hours);
    }

    function test_SetSynchronizationDelay_Revert_Operator_Unauthorized()
        public
    {
        vm.prank(OPERATOR);
        vm.expectRevert(AccessUnauthorizedError(OPERATOR));
        core4Mica.setSynchronizationDelay(5 hours);
    }

    function test_SetSynchronizationDelay_Revert_IllegalValue() public {
        uint256 invalid = core4Mica.withdrawalGracePeriod() -
            core4Mica.tabExpirationTime();
        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setSynchronizationDelay(invalid);
    }

    function test_SetVerificationKey() public {
        BLS.G1Point memory newKey = BLS.G1Point(
            bytes32(
                0x1000000000000000000000000000000000000000000000000000000000000001
            ),
            bytes32(
                0x0100000000000000000000000000000000000000000000000000000000000010
            ),
            bytes32(
                0x0010000000000000000000000000000000000000000000000000000000000100
            ),
            bytes32(
                0x0001000000000000000000000000000000000000000000000000000000001000
            )
        );
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.VerificationKeyUpdated(newKey);

        core4Mica.setGuaranteeVerificationKey(newKey);

        (
            bytes32 x_a,
            bytes32 x_b,
            bytes32 y_a,
            bytes32 y_b
        ) = core4Mica.GUARANTEE_VERIFICATION_KEY();
        assertEq(x_a, newKey.x_a);
        assertEq(x_b, newKey.x_b);
        assertEq(y_a, newKey.y_a);
        assertEq(y_b, newKey.y_b);
    }

    function test_SetVerificationKey_Revert_User_Unauthorized() public {
        BLS.G1Point memory newKey = BLS.G1Point(
            bytes32(
                0x1000000000000000000000000000000000000000000000000000000000000001
            ),
            bytes32(
                0x0100000000000000000000000000000000000000000000000000000000000010
            ),
            bytes32(
                0x0010000000000000000000000000000000000000000000000000000000000100
            ),
            bytes32(
                0x0001000000000000000000000000000000000000000000000000000000001000
            )
        );
        vm.prank(USER1);
        vm.expectRevert(AccessUnauthorizedError(USER1));
        core4Mica.setGuaranteeVerificationKey(newKey);
    }

    function test_SetVerificationKey_Revert_Operator_Unauthorized() public {
        BLS.G1Point memory newKey = BLS.G1Point(
            bytes32(
                0x1000000000000000000000000000000000000000000000000000000000000001
            ),
            bytes32(
                0x0100000000000000000000000000000000000000000000000000000000000010
            ),
            bytes32(
                0x0010000000000000000000000000000000000000000000000000000000000100
            ),
            bytes32(
                0x0001000000000000000000000000000000000000000000000000000000001000
            )
        );
        vm.prank(OPERATOR);
        vm.expectRevert(AccessUnauthorizedError(OPERATOR));
        core4Mica.setGuaranteeVerificationKey(newKey);
    }

    function test_SetTimingParameters() public {
        uint256 newRem = 10 days;
        uint256 newTab = 15 days;
        uint256 newSync = 1 days;
        uint256 newWithdrawal = 25 days;

        vm.expectEmit(false, false, false, true);
        emit Core4Mica.RemunerationGracePeriodUpdated(newRem);
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.TabExpirationTimeUpdated(newTab);
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.SynchronizationDelayUpdated(newSync);
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.WithdrawalGracePeriodUpdated(newWithdrawal);

        core4Mica.setTimingParameters(
            newRem,
            newTab,
            newSync,
            newWithdrawal
        );

        assertEq(core4Mica.remunerationGracePeriod(), newRem);
        assertEq(core4Mica.tabExpirationTime(), newTab);
        assertEq(core4Mica.synchronizationDelay(), newSync);
        assertEq(core4Mica.withdrawalGracePeriod(), newWithdrawal);
    }

    function test_SetTimingParameters_Revert_InvalidOrdering() public {
        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setTimingParameters(
            15 days,
            10 days,
            1 days,
            40 days
        );

        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setTimingParameters(
            5 days,
            10 days,
            15 days,
            20 days
        );
    }
}
