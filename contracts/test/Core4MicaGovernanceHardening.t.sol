// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";

import {Core4MicaFullStackScript} from "../script/Core4MicaFullStack.s.sol";

/// @dev Minimal contract with bytecode, standing in for a multisig/timelock admin.
contract MockMultisig {}

/// @dev Exposes the deploy script's internal hardened-governance helpers for unit testing.
contract HardenedGovHarness is Core4MicaFullStackScript {
    function finalize(AccessManager manager, DeploymentConfig memory config) external {
        _finalizeHardenedGovernance(manager, config);
    }

    function validate(DeploymentConfig memory config, address deployer) external view {
        _validateHardenedGovernance(config, deployer);
    }

    function checkHolder(string memory role, address holder, address deployer) external pure {
        _requireSeparatedHolder(role, holder, deployer);
    }
}

/// @notice Covers the code-addressable half of 4MCA-H08: the deploy-time governance-topology
/// checks and the bootstrap-admin -> multisig hand-off with non-zero delays.
contract Core4MicaGovernanceHardeningTest is Test {
    uint64 private constant ADMIN_ROLE = 0;
    uint64 private constant GOVERNANCE_ROLE = 1;
    uint64 private constant CLEARING_HOUSE_ROLE = 5;

    HardenedGovHarness private harness;
    AccessManager private manager;
    MockMultisig private multisig;

    function setUp() public {
        harness = new HardenedGovHarness();
        // The harness plays the deployer / bootstrap admin, exactly as during a hardened deploy.
        manager = new AccessManager(address(harness));
        multisig = new MockMultisig();
    }

    function _baseConfig() internal view returns (Core4MicaFullStackScript.DeploymentConfig memory config) {
        config.deployer = address(harness);
        config.managerAdmin = address(multisig);
        config.hardenedGovernance = true;
        config.adminExecutionDelay = 72 hours;
        config.roleGrantDelay = 72 hours;
    }

    function test_finalizeHandsOffAdminWithDelayAndRenouncesDeployer() public {
        harness.finalize(manager, _baseConfig());

        (bool adminIsMember, uint32 adminDelay) = manager.hasRole(ADMIN_ROLE, address(multisig));
        assertTrue(adminIsMember, "admin not granted to multisig");
        assertEq(adminDelay, 72 hours, "admin execution delay missing");

        (bool deployerIsAdmin,) = manager.hasRole(ADMIN_ROLE, address(harness));
        assertFalse(deployerIsAdmin, "deployer retained admin");
    }

    function test_finalizeInstallsRoleGrantDelaysAfterSetback() public {
        harness.finalize(manager, _baseConfig());

        // A grant-delay increase engages only after AccessManager.minSetback() (5 days); the admin
        // execution delay is the immediate protection in the interim.
        assertEq(manager.getRoleGrantDelay(GOVERNANCE_ROLE), 0, "grant delay active too early");
        vm.warp(block.timestamp + manager.minSetback() + 1);
        assertEq(manager.getRoleGrantDelay(GOVERNANCE_ROLE), 72 hours, "grant delay not installed");
        // The collateral-seizing role a compromised admin would self-grant (4MCA-H02) is delayed too.
        assertEq(manager.getRoleGrantDelay(CLEARING_HOUSE_ROLE), 72 hours, "clearing-house grant delay not installed");
    }

    function test_validateRejectsDeployerAsAdmin() public {
        Core4MicaFullStackScript.DeploymentConfig memory config = _baseConfig();
        config.managerAdmin = address(harness); // == deployer
        vm.expectRevert(
            abi.encodeWithSelector(Core4MicaFullStackScript.InsecureGovernanceAdmin.selector, address(harness))
        );
        harness.validate(config, address(harness));
    }

    function test_validateRejectsEoaAdmin() public {
        address eoa = makeAddr("eoaAdmin"); // no bytecode
        Core4MicaFullStackScript.DeploymentConfig memory config = _baseConfig();
        config.managerAdmin = eoa;
        vm.expectRevert(abi.encodeWithSelector(Core4MicaFullStackScript.InsecureGovernanceAdmin.selector, eoa));
        harness.validate(config, address(harness));
    }

    function test_validateRejectsZeroAdminExecutionDelay() public {
        Core4MicaFullStackScript.DeploymentConfig memory config = _baseConfig();
        config.adminExecutionDelay = 0;
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4MicaFullStackScript.GovernanceDelayBelowMinimum.selector,
                "ADMIN_EXECUTION_DELAY",
                uint256(0),
                uint256(harness.MIN_ADMIN_EXECUTION_DELAY())
            )
        );
        harness.validate(config, address(harness));
    }

    function test_holderCheckRejectsDeployer() public {
        vm.expectRevert(
            abi.encodeWithSelector(Core4MicaFullStackScript.RoleHolderNotSeparated.selector, "GOVERNANCE_ROLE_HOLDER")
        );
        harness.checkHolder("GOVERNANCE_ROLE_HOLDER", address(harness), address(harness));
    }

    function test_holderCheckRejectsZeroAddress() public {
        vm.expectRevert(
            abi.encodeWithSelector(Core4MicaFullStackScript.RoleHolderNotSeparated.selector, "TREASURY_ROLE_HOLDER")
        );
        harness.checkHolder("TREASURY_ROLE_HOLDER", address(0), address(harness));
    }

    function test_holderCheckAcceptsDistinctHolder() public {
        harness.checkHolder("GOVERNANCE_ROLE_HOLDER", makeAddr("gov"), address(harness)); // must not revert
    }
}
