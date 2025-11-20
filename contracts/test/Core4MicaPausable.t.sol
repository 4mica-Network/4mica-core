// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";

error EnforcedPause();

contract Core4MicaPausableTest is Core4MicaTestBase {
    event Paused(address account);
    event Unpaused(address account);

    function test_UserAdminRoleCanPauseAndUnpause() public {
        address secondaryAdmin = address(0xAAA);
        manager.grantRole(USER_ADMIN_ROLE, secondaryAdmin, 0);

        vm.prank(secondaryAdmin);
        core4Mica.pause();
        assertTrue(core4Mica.paused());

        vm.prank(secondaryAdmin);
        core4Mica.unpause();
        assertFalse(core4Mica.paused());
    }

    function test_PauseBlocksDeposits_AndUnpauseRestoresFlow() public {
        vm.expectEmit(true, false, false, true);
        emit Paused(address(this));
        core4Mica.pause();
        assertTrue(core4Mica.paused());

        vm.prank(USER1);
        vm.expectRevert(EnforcedPause.selector);
        core4Mica.deposit{value: 1 ether}();

        vm.expectEmit(true, false, false, true);
        emit Unpaused(address(this));
        core4Mica.unpause();
        assertFalse(core4Mica.paused());

        (uint256 collateralBefore, , ) = core4Mica.getUser(USER1);
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();
        (uint256 collateralAfter, , ) = core4Mica.getUser(USER1);
        assertEq(collateralAfter, collateralBefore + 1 ether);
    }

    function test_Pause_Revert_UnauthorizedCallers() public {
        vm.prank(USER1);
        vm.expectRevert(AccessUnauthorizedError(USER1));
        core4Mica.pause();

        vm.prank(OPERATOR);
        vm.expectRevert(AccessUnauthorizedError(OPERATOR));
        core4Mica.pause();
    }

    function test_Unpause_Revert_UnauthorizedCallers() public {
        core4Mica.pause();

        vm.prank(USER1);
        vm.expectRevert(AccessUnauthorizedError(USER1));
        core4Mica.unpause();

        vm.prank(OPERATOR);
        vm.expectRevert(AccessUnauthorizedError(OPERATOR));
        core4Mica.unpause();

        core4Mica.unpause();
    }
}
