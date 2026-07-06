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

    function checkOperatorHolder(address holder, address deployer, bool allowEoa) external view {
        _requireOperatorHolder(holder, deployer, allowEoa);
    }

    function parseEnvironment(string memory raw) external pure returns (Environment) {
        return _parseEnvironment(raw);
    }
}

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

    function test_operatorHolderRejectsEoa() public {
        address eoa = makeAddr("operatorEoa"); // no bytecode
        vm.expectRevert(abi.encodeWithSelector(Core4MicaFullStackScript.InsecureOperatorHolder.selector, eoa));
        harness.checkOperatorHolder(eoa, address(harness), false);
    }

    function test_operatorHolderAcceptsContract() public view {
        // A contract-bearing holder (multisig / smart-account) is accepted without the escape hatch.
        harness.checkOperatorHolder(address(multisig), address(harness), false);
    }

    function test_operatorHolderAllowsEoaWhenAcknowledged() public {
        // Threshold/HSM signers present as an EOA on-chain; opting in accepts the single-key exposure.
        address eoa = makeAddr("operatorEoa");
        harness.checkOperatorHolder(eoa, address(harness), true); // must not revert
    }

    function test_operatorHolderRejectsDeployerEvenWhenEoaAllowed() public {
        // Separation is enforced before the contract check: the operator can never be the deployer.
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4MicaFullStackScript.RoleHolderNotSeparated.selector, "FOURMICA_OPERATOR_ROLE_HOLDER"
            )
        );
        harness.checkOperatorHolder(address(harness), address(harness), true);
    }

    // ---- DEPLOY_ENVIRONMENT parsing (mirrors core-service SERVER_ENVIRONMENT) ----

    function test_environmentParsesProduction() public view {
        assertEq(
            uint256(harness.parseEnvironment("production")), uint256(Core4MicaFullStackScript.Environment.Production)
        );
        assertEq(uint256(harness.parseEnvironment("PROD")), uint256(Core4MicaFullStackScript.Environment.Production));
        // Whitespace/casing tolerated, like the Rust FromStr.
        assertEq(
            uint256(harness.parseEnvironment("  Production ")), uint256(Core4MicaFullStackScript.Environment.Production)
        );
    }

    function test_environmentParsesDevelopment() public view {
        assertEq(
            uint256(harness.parseEnvironment("development")), uint256(Core4MicaFullStackScript.Environment.Development)
        );
        assertEq(uint256(harness.parseEnvironment("dev")), uint256(Core4MicaFullStackScript.Environment.Development));
        assertEq(uint256(harness.parseEnvironment("test")), uint256(Core4MicaFullStackScript.Environment.Development));
    }

    function test_environmentRejectsUnknown() public {
        vm.expectRevert(abi.encodeWithSelector(Core4MicaFullStackScript.InvalidEnvironment.selector, "staging"));
        harness.parseEnvironment("staging");
    }
}
