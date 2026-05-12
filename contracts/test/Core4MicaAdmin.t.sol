// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Core4MicaTestBase, MockERC20} from "./Core4MicaTestBase.sol";
import {Core4Mica} from "../src/Core4Mica.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";
import {MockAToken} from "./helpers/MockAave.sol";

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
        vm.expectRevert(accessUnauthorizedError(USER1));
        core4Mica.setWithdrawalGracePeriod(2 days);
    }

    function test_SetWithdrawalGracePeriod_Revert_Operator_Unauthorized() public {
        vm.prank(OPERATOR);
        vm.expectRevert(accessUnauthorizedError(OPERATOR));
        core4Mica.setWithdrawalGracePeriod(2 days);
    }

    function test_SetWithdrawalGracePeriod_Revert_IllegalValue() public {
        uint256 invalid = core4Mica.synchronizationDelay() + core4Mica.tabExpirationTime();
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
        vm.expectRevert(accessUnauthorizedError(USER1));
        core4Mica.setRemunerationGracePeriod(2 days);
    }

    function test_SetRemunerationGracePeriod_Revert_Operator_Unauthorized() public {
        vm.prank(OPERATOR);
        vm.expectRevert(accessUnauthorizedError(OPERATOR));
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
        vm.expectRevert(accessUnauthorizedError(USER1));
        core4Mica.setTabExpirationTime(2 days);
    }

    function test_SetTabExpirationTime_Revert_Operator_Unauthorized() public {
        vm.prank(OPERATOR);
        vm.expectRevert(accessUnauthorizedError(OPERATOR));
        core4Mica.setTabExpirationTime(2 days);
    }

    function test_SetTabExpirationTime_Revert_IllegalValue() public {
        uint256 invalidLow = core4Mica.remunerationGracePeriod();
        uint256 invalidHigh = core4Mica.withdrawalGracePeriod() - core4Mica.synchronizationDelay();

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
        vm.expectRevert(accessUnauthorizedError(USER1));
        core4Mica.setSynchronizationDelay(5 hours);
    }

    function test_SetSynchronizationDelay_Revert_Operator_Unauthorized() public {
        vm.prank(OPERATOR);
        vm.expectRevert(accessUnauthorizedError(OPERATOR));
        core4Mica.setSynchronizationDelay(5 hours);
    }

    function test_SetSynchronizationDelay_Revert_IllegalValue() public {
        uint256 invalid = core4Mica.withdrawalGracePeriod() - core4Mica.tabExpirationTime();
        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setSynchronizationDelay(invalid);
    }

    function test_SetVerificationKey() public {
        BLS.G1Point memory newKey = BLS.G1Point(
            bytes32(0x1000000000000000000000000000000000000000000000000000000000000001),
            bytes32(0x0100000000000000000000000000000000000000000000000000000000000010),
            bytes32(0x0010000000000000000000000000000000000000000000000000000000000100),
            bytes32(0x0001000000000000000000000000000000000000000000000000000000001000)
        );
        vm.expectEmit(false, false, false, true);
        emit Core4Mica.VerificationKeyUpdated(newKey);

        core4Mica.setGuaranteeVerificationKey(newKey);

        (bytes32 xA, bytes32 xB, bytes32 yA, bytes32 yB) = core4Mica.GUARANTEE_VERIFICATION_KEY();
        assertEq(xA, newKey.x_a);
        assertEq(xB, newKey.x_b);
        assertEq(yA, newKey.y_a);
        assertEq(yB, newKey.y_b);
    }

    function test_SetVerificationKey_Revert_User_Unauthorized() public {
        BLS.G1Point memory newKey = BLS.G1Point(
            bytes32(0x1000000000000000000000000000000000000000000000000000000000000001),
            bytes32(0x0100000000000000000000000000000000000000000000000000000000000010),
            bytes32(0x0010000000000000000000000000000000000000000000000000000000000100),
            bytes32(0x0001000000000000000000000000000000000000000000000000000000001000)
        );
        vm.prank(USER1);
        vm.expectRevert(accessUnauthorizedError(USER1));
        core4Mica.setGuaranteeVerificationKey(newKey);
    }

    function test_SetVerificationKey_Revert_Operator_Unauthorized() public {
        BLS.G1Point memory newKey = BLS.G1Point(
            bytes32(0x1000000000000000000000000000000000000000000000000000000000000001),
            bytes32(0x0100000000000000000000000000000000000000000000000000000000000010),
            bytes32(0x0010000000000000000000000000000000000000000000000000000000000100),
            bytes32(0x0001000000000000000000000000000000000000000000000000000000001000)
        );
        vm.prank(OPERATOR);
        vm.expectRevert(accessUnauthorizedError(OPERATOR));
        core4Mica.setGuaranteeVerificationKey(newKey);
    }

    function test_AddStablecoinAsset() public {
        (MockERC20 eurc, MockAToken mockEurcAToken) = _prepareNewStablecoin("Euro Coin", "EURC");

        vm.expectEmit(true, false, false, true);
        emit Core4Mica.StablecoinAssetUpdated(address(eurc), true);
        core4Mica.addStablecoinAsset(address(eurc), address(mockEurcAToken));

        address[] memory tokens = core4Mica.getERC20Tokens();
        assertEq(tokens.length, 3);
        assertEq(tokens[0], address(usdc));
        assertEq(tokens[1], address(usdt));
        assertEq(tokens[2], address(eurc));
        assertEq(core4Mica.stablecoinAToken(address(eurc)), address(mockEurcAToken));

        eurc.mint(USER1, 1_000 ether);
        vm.startPrank(USER1);
        eurc.approve(address(core4Mica), type(uint256).max);
        core4Mica.depositStablecoin(address(eurc), 100 ether);
        vm.stopPrank();

        assertEq(core4Mica.principalBalance(USER1, address(eurc)), 100 ether);
        assertEq(core4Mica.guaranteeCapacity(USER1, address(eurc)), 100 ether);
    }

    function test_AddStablecoinAsset_Revert_UserUnauthorized() public {
        (MockERC20 eurc, MockAToken mockEurcAToken) = _prepareNewStablecoin("Euro Coin", "EURC");

        vm.prank(USER1);
        vm.expectRevert(accessUnauthorizedError(USER1));
        core4Mica.addStablecoinAsset(address(eurc), address(mockEurcAToken));
    }

    function test_AddStablecoinAsset_Revert_DuplicateAsset() public {
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.InvalidAsset.selector, address(usdc)));
        core4Mica.addStablecoinAsset(address(usdc), address(mockUsdcAToken));
    }

    function test_AddStablecoinAsset_Revert_ZeroAsset() public {
        vm.expectRevert(abi.encodeWithSelector(Core4Mica.InvalidAsset.selector, address(0)));
        core4Mica.addStablecoinAsset(address(0), address(mockUsdcAToken));
    }

    function test_AddStablecoinAsset_Revert_AaveNotConfigured() public {
        MockERC20 eurc = new MockERC20("Euro Coin", "EURC");
        MockAToken mockEurcAToken = new MockAToken(address(eurc), address(mockPool), "Aave EURC", "aEURC");

        address[] memory stablecoins = new address[](1);
        stablecoins[0] = address(usdc);
        Core4Mica bareCore = new Core4Mica(address(manager), testPublicKey, stablecoins);
        manager.setTargetFunctionRole(
            address(bareCore), _asSingletonArray(Core4Mica.addStablecoinAsset.selector), USER_ADMIN_ROLE
        );

        vm.expectRevert(Core4Mica.AaveNotConfigured.selector);
        bareCore.addStablecoinAsset(address(eurc), address(mockEurcAToken));
    }

    function test_AddStablecoinAsset_Revert_ZeroAToken() public {
        MockERC20 eurc = new MockERC20("Euro Coin", "EURC");

        vm.expectRevert(Core4Mica.ZeroAddress.selector);
        core4Mica.addStablecoinAsset(address(eurc), address(0));
    }

    function test_AddStablecoinAsset_Revert_InvalidATokenUnderlying() public {
        MockERC20 eurc = new MockERC20("Euro Coin", "EURC");

        vm.expectRevert(
            abi.encodeWithSelector(Core4Mica.InvalidAToken.selector, address(eurc), address(mockUsdcAToken))
        );
        core4Mica.addStablecoinAsset(address(eurc), address(mockUsdcAToken));
    }

    function test_AddStablecoinAsset_Revert_InvalidATokenDataProvider() public {
        MockERC20 eurc = new MockERC20("Euro Coin", "EURC");
        MockAToken mockEurcAToken = new MockAToken(address(eurc), address(mockPool), "Aave EURC", "aEURC");

        vm.expectRevert(
            abi.encodeWithSelector(Core4Mica.InvalidAToken.selector, address(eurc), address(mockEurcAToken))
        );
        core4Mica.addStablecoinAsset(address(eurc), address(mockEurcAToken));
    }

    function test_SetTimingParameters_Revert_ZeroValues() public {
        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setTimingParameters(0, 15 days, 1 days, 25 days);

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setTimingParameters(10 days, 0, 1 days, 25 days);

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setTimingParameters(10 days, 15 days, 0, 25 days);

        vm.expectRevert(Core4Mica.AmountZero.selector);
        core4Mica.setTimingParameters(10 days, 15 days, 1 days, 0);
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

        core4Mica.setTimingParameters(newRem, newTab, newSync, newWithdrawal);

        assertEq(core4Mica.remunerationGracePeriod(), newRem);
        assertEq(core4Mica.tabExpirationTime(), newTab);
        assertEq(core4Mica.synchronizationDelay(), newSync);
        assertEq(core4Mica.withdrawalGracePeriod(), newWithdrawal);
    }

    function test_SetTimingParameters_Revert_InvalidOrdering() public {
        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setTimingParameters(15 days, 10 days, 1 days, 40 days);

        vm.expectRevert(Core4Mica.IllegalValue.selector);
        core4Mica.setTimingParameters(5 days, 10 days, 15 days, 20 days);
    }

    function _prepareNewStablecoin(string memory name, string memory symbol)
        internal
        returns (MockERC20 token, MockAToken aToken)
    {
        token = new MockERC20(name, symbol);
        aToken = new MockAToken(
            address(token), address(mockPool), string.concat("Aave ", symbol), string.concat("a", symbol)
        );
        mockPool.setReserve(address(token), address(aToken), 1e27);
        mockDataProvider.setReserveAToken(address(token), address(aToken));
    }
}
