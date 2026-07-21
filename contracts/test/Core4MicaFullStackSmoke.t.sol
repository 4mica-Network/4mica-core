// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";

import {Core4Mica} from "../src/Core4Mica.sol";
import {ClearingHouse} from "../src/ClearingHouse.sol";
import {BlsHelper} from "../src/BlsHelpers.sol";

contract Core4MicaFullStackSmokeTest is Test {
    uint64 private constant GOVERNANCE_ROLE = 1;
    uint64 private constant TREASURY_ROLE = 2;
    uint64 private constant GUARDIAN_ROLE = 3;
    uint64 private constant FOURMICA_OPERATOR_ROLE = 4;
    uint64 private constant CLEARING_HOUSE_ROLE = 5;
    uint32 private constant GOVERNANCE_DELAY = 72 hours;
    uint32 private constant TREASURY_DELAY = 72 hours;
    bytes32 private constant TEST_PRIVATE_KEY =
        bytes32(0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3);
    address private constant USDC = address(0xA0);
    address private constant USDT = address(0xB0);

    function test_fullStackDeploymentConfiguresTheInitialGuaranteeVersion() public {
        address deployer = address(this);
        AccessManager manager = new AccessManager(deployer);
        BLS.G1Point memory verificationKey = BlsHelper.getPublicKey(TEST_PRIVATE_KEY);

        address[] memory stablecoins = new address[](2);
        stablecoins[0] = USDC;
        stablecoins[1] = USDT;
        Core4Mica core4Mica = new Core4Mica(address(manager), verificationKey, stablecoins, 0);

        _configureCoreRoles(manager, core4Mica, deployer);

        (BLS.G1Point memory v1Key, bytes32 v1Domain, address v1Decoder, bool v1Enabled) =
            core4Mica.getGuaranteeVersionConfig(core4Mica.INITIAL_GUARANTEE_VERSION());
        assertTrue(v1Enabled);
        assertEq(v1Domain, core4Mica.guaranteeDomainSeparator());
        assertEq(v1Decoder, address(0));
        _assertSameKey(v1Key, verificationKey);
    }

    function test_accessPolicySplitsGovernanceTreasuryGuardianAnd4micaOperatorRoles() public {
        address deployer = address(this);
        AccessManager manager = new AccessManager(deployer);
        BLS.G1Point memory verificationKey = BlsHelper.getPublicKey(TEST_PRIVATE_KEY);

        address[] memory stablecoins = new address[](2);
        stablecoins[0] = USDC;
        stablecoins[1] = USDT;
        Core4Mica core4Mica = new Core4Mica(address(manager), verificationKey, stablecoins, 0);

        _configureCoreRoles(manager, core4Mica, deployer);

        assertEq(manager.getTargetFunctionRole(address(core4Mica), Core4Mica.configureAave.selector), GOVERNANCE_ROLE);
        assertEq(
            manager.getTargetFunctionRole(address(core4Mica), Core4Mica.addStablecoinAsset.selector), GOVERNANCE_ROLE
        );
        assertEq(manager.getTargetFunctionRole(address(core4Mica), Core4Mica.setYieldFeeBps.selector), GOVERNANCE_ROLE);
        assertEq(
            manager.getTargetFunctionRole(address(core4Mica), Core4Mica.claimProtocolYield.selector), TREASURY_ROLE
        );
        assertEq(
            manager.getTargetFunctionRole(address(core4Mica), Core4Mica.claimSurplusATokens.selector), TREASURY_ROLE
        );
        assertEq(manager.getTargetFunctionRole(address(core4Mica), Core4Mica.pause.selector), GUARDIAN_ROLE);
        assertEq(manager.getTargetFunctionRole(address(core4Mica), Core4Mica.unpause.selector), GOVERNANCE_ROLE);

        ClearingHouse clearingHouse = new ClearingHouse(address(manager), address(core4Mica));
        _configureClearingHouseRoles(manager, clearingHouse, core4Mica);
        assertEq(
            manager.getTargetFunctionRole(address(clearingHouse), ClearingHouse.commitCycle.selector),
            FOURMICA_OPERATOR_ROLE
        );
        assertEq(
            manager.getTargetFunctionRole(
                address(clearingHouse), ClearingHouse.settleDefaultsFromCollateralBatch.selector
            ),
            FOURMICA_OPERATOR_ROLE
        );
        _assertCanCall(manager, deployer, address(clearingHouse), ClearingHouse.commitCycle.selector, true, 0);
        _assertCanCall(
            manager, deployer, address(clearingHouse), ClearingHouse.settleDefaultsFromCollateralBatch.selector, true, 0
        );

        _assertCanCall(
            manager, deployer, address(core4Mica), Core4Mica.setYieldFeeBps.selector, false, GOVERNANCE_DELAY
        );
        _assertCanCall(
            manager, deployer, address(core4Mica), Core4Mica.claimProtocolYield.selector, false, TREASURY_DELAY
        );
        _assertCanCall(manager, deployer, address(core4Mica), Core4Mica.pause.selector, true, 0);
    }

    function _configureCoreRoles(AccessManager manager, Core4Mica core4Mica, address deployer) internal {
        bytes4[] memory governanceSelectors = new bytes4[](6);
        governanceSelectors[0] = Core4Mica.setWithdrawalGracePeriod.selector;
        governanceSelectors[1] = Core4Mica.setGuaranteeVerificationKey.selector;
        governanceSelectors[2] = Core4Mica.configureGuaranteeVersion.selector;
        governanceSelectors[3] = Core4Mica.configureAave.selector;
        governanceSelectors[4] = Core4Mica.addStablecoinAsset.selector;
        governanceSelectors[5] = Core4Mica.setYieldFeeBps.selector;

        for (uint256 i = 0; i < governanceSelectors.length; i++) {
            manager.setTargetFunctionRole(
                address(core4Mica), _asSingletonArray(governanceSelectors[i]), GOVERNANCE_ROLE
            );
        }

        manager.setTargetFunctionRole(
            address(core4Mica), _asSingletonArray(Core4Mica.claimProtocolYield.selector), TREASURY_ROLE
        );
        manager.setTargetFunctionRole(
            address(core4Mica), _asSingletonArray(Core4Mica.claimSurplusATokens.selector), TREASURY_ROLE
        );
        manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(Core4Mica.pause.selector), GUARDIAN_ROLE);
        manager.setTargetFunctionRole(
            address(core4Mica), _asSingletonArray(Core4Mica.unpause.selector), GOVERNANCE_ROLE
        );

        manager.grantRole(GOVERNANCE_ROLE, deployer, GOVERNANCE_DELAY);
        manager.grantRole(TREASURY_ROLE, deployer, TREASURY_DELAY);
        manager.grantRole(GUARDIAN_ROLE, deployer, 0);
        manager.grantRole(FOURMICA_OPERATOR_ROLE, deployer, 0);
    }

    function _configureClearingHouseRoles(AccessManager manager, ClearingHouse clearingHouse, Core4Mica core4Mica)
        internal
    {
        bytes4[] memory operatorSelectors = new bytes4[](4);
        operatorSelectors[0] = ClearingHouse.commitCycle.selector;
        operatorSelectors[1] = ClearingHouse.settleDefaultsFromCollateralBatch.selector;
        operatorSelectors[2] = ClearingHouse.fundCreditorsFromPoolBatch.selector;
        operatorSelectors[3] = ClearingHouse.markCycleShortfall.selector;
        for (uint256 i = 0; i < operatorSelectors.length; i++) {
            manager.setTargetFunctionRole(
                address(clearingHouse), _asSingletonArray(operatorSelectors[i]), FOURMICA_OPERATOR_ROLE
            );
        }

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
    }

    function _asSingletonArray(bytes4 selector) internal pure returns (bytes4[] memory arr) {
        arr = new bytes4[](1);
        arr[0] = selector;
    }

    function _assertSameKey(BLS.G1Point memory lhs, BLS.G1Point memory rhs) internal pure {
        assertEq(lhs.x_a, rhs.x_a);
        assertEq(lhs.x_b, rhs.x_b);
        assertEq(lhs.y_a, rhs.y_a);
        assertEq(lhs.y_b, rhs.y_b);
    }

    function _assertCanCall(
        AccessManager manager,
        address caller,
        address target,
        bytes4 selector,
        bool expectedImmediate,
        uint32 expectedDelay
    ) internal view {
        (bool immediate, uint32 delay) = manager.canCall(caller, target, selector);
        assertEq(immediate, expectedImmediate);
        assertEq(delay, expectedDelay);
    }
}
