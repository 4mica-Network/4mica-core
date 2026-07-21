// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";

import {Core4Mica} from "../src/Core4Mica.sol";
import {ClearingHouse} from "../src/ClearingHouse.sol";
import {DeterministicCreate2} from "./utils/DeterministicCreate2.sol";
import {MockERC20} from "../test/Core4MicaTestBase.sol";

/// @notice Deploys full guarantee stack: AccessManager + Core4Mica + ClearingHouse.
///
/// Required env:
/// - DEPLOYER_PRIVATE_KEY
/// - VK_X0
/// - VK_X1
/// - VK_Y0
/// - VK_Y1
///
/// Stablecoin configuration (optional):
/// - STABLECOINS_COUNT=<n> and STABLECOIN_0..n-1
/// - DEPLOY_MOCK_STABLECOINS=true deploys STABLECOINS_COUNT fresh
///   ERC20s and registers those instead of reading STABLECOIN_* (local dev only).
///
/// Deterministic deployment:
/// - CREATE2_SALT (optional, default "4mica-core-v1")
/// - ACCESS_MANAGER_ADMIN (optional, default broadcaster address)
contract Core4MicaFullStackScript is Script {
    error InvalidStablecoinConfiguration();
    error PartialAaveConfiguration();
    error StablecoinReadbackMismatch();
    error AaveReadbackMismatch(string field);
    error YieldFeeReadbackMismatch(uint256 expected, uint256 actual);
    error InsecureGovernanceAdmin(address admin);
    error GovernanceDelayBelowMinimum(string field, uint256 provided, uint256 minimum);
    error RoleHolderNotSeparated(string role);
    error InsecureOperatorHolder(address operator);
    error AdminHandoffFailed(address expectedAdmin);
    error DeployerRetainedAdmin(address deployer);
    error InvalidEnvironment(string provided);

    // Deployment environment, mirroring core-service's SERVER_ENVIRONMENT. Production enforces the
    // hardened-governance requirements; development relaxes them for local/CI use.
    enum Environment {
        Development,
        Production
    }

    // Delayed governance role for protocol policy, trust roots, and Aave configuration.
    uint64 public constant GOVERNANCE_ROLE = 1;
    // Delayed governance role for any function that moves protocol-owned value out of Core4Mica.
    uint64 public constant TREASURY_ROLE = 2;
    // Fast incident-response role limited to emergency halts; cannot change protocol economics or move funds.
    uint64 public constant GUARDIAN_ROLE = 3;
    // Immediate 4mica operator role for settlement bookkeeping only.
    uint64 public constant FOURMICA_OPERATOR_ROLE = 4;
    // Immediate role held only by the ClearingHouse so it can move collateral in Core4Mica.
    uint64 public constant CLEARING_HOUSE_ROLE = 5;
    // AccessManager built-in admin role (OpenZeppelin AccessManager.ADMIN_ROLE == 0).
    uint64 public constant ADMIN_ROLE = 0;

    uint32 public constant DEFAULT_GOVERNANCE_EXECUTION_DELAY = 72 hours;
    uint32 public constant DEFAULT_TREASURY_EXECUTION_DELAY = 72 hours;
    uint32 public constant DEFAULT_GUARDIAN_EXECUTION_DELAY = 0;
    uint32 public constant DEFAULT_FOURMICA_OPERATOR_EXECUTION_DELAY = 0;

    uint32 public constant DEFAULT_ADMIN_EXECUTION_DELAY = 72 hours;
    uint32 public constant DEFAULT_ROLE_GRANT_DELAY = 72 hours;

    uint32 public constant MIN_ADMIN_EXECUTION_DELAY = 24 hours;
    uint32 public constant MIN_ROLE_GRANT_DELAY = 24 hours;
    uint32 public constant MIN_GOVERNANCE_EXECUTION_DELAY = 24 hours;
    uint32 public constant MIN_TREASURY_EXECUTION_DELAY = 24 hours;

    struct FullStackDeployment {
        AccessManager manager;
        Core4Mica core4Mica;
        ClearingHouse clearingHouse;
    }

    struct DeploymentConfig {
        address deployer;
        address managerAdmin;
        address[] stablecoins;
        bytes32 baseSalt;
        BLS.G1Point guaranteeVerificationKey;
        uint256 minWithdrawalGracePeriod;
        bool hardenedGovernance;
        uint32 adminExecutionDelay;
        uint32 roleGrantDelay;
    }

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        DeploymentConfig memory config = _loadDeploymentConfig(vm.addr(deployerPrivateKey));

        vm.startBroadcast(deployerPrivateKey);

        if (vm.envOr("DEPLOY_MOCK_STABLECOINS", false)) {
            config.stablecoins = _deployMockStablecoins();
            _validateStablecoins(config.stablecoins);
        }

        address initialAdmin = config.hardenedGovernance ? config.deployer : config.managerAdmin;

        FullStackDeployment memory deployment = _deployFullStack(
            config.baseSalt,
            initialAdmin,
            config.guaranteeVerificationKey,
            config.stablecoins,
            config.minWithdrawalGracePeriod
        );
        _configureDeployedStack(deployment, config);

        if (config.hardenedGovernance) {
            _finalizeHardenedGovernance(deployment.manager, config);
        }

        vm.stopBroadcast();

        console.log("AccessManager:", address(deployment.manager));
        console.log("Core4Mica:", address(deployment.core4Mica));
        console.log("ClearingHouse:", address(deployment.clearingHouse));
        console.log("AccessManager admin:", config.managerAdmin);
        console.log("Hardened governance:", config.hardenedGovernance);
        console.log("CREATE2 base salt:");
        console.logBytes32(config.baseSalt);
    }

    function _loadDeploymentConfig(address deployer) internal view returns (DeploymentConfig memory config) {
        // In mock mode the stablecoins are deployed after broadcast starts; leave them empty here.
        address[] memory stablecoins;
        if (!vm.envOr("DEPLOY_MOCK_STABLECOINS", false)) {
            stablecoins = _loadStablecoinAssets();
            _validateStablecoins(stablecoins);
        }

        config.deployer = deployer;
        config.managerAdmin = vm.envOr("ACCESS_MANAGER_ADMIN", deployer);
        config.stablecoins = stablecoins;
        config.baseSalt = keccak256(bytes(vm.envOr("CREATE2_SALT", string("4mica-core-v1"))));
        config.guaranteeVerificationKey = BLS.G1Point({
            x_a: vm.envBytes32("VK_X0"),
            x_b: vm.envBytes32("VK_X1"),
            y_a: vm.envBytes32("VK_Y0"),
            y_b: vm.envBytes32("VK_Y1")
        });
        // On-chain floor for withdrawalGracePeriod, set at construction so it can never be left
        // at 0. Must exceed worst-case cycle time-to-finality + seizure margin to preserve the
        // delayed-withdrawal solvency invariant; default 7 days (vs the 22-day default grace).
        config.minWithdrawalGracePeriod = vm.envOr("MIN_WITHDRAWAL_GRACE_PERIOD", uint256(7 days));
        require(config.minWithdrawalGracePeriod > 0, "MIN_WITHDRAWAL_GRACE_PERIOD must be > 0");

        // Mirror core-service's SERVER_ENVIRONMENT model: default to production (fail-safe), and gate
        // the production-only governance hardening on it. Production enforces the full hardened
        // topology (multisig/timelock admin, non-zero floored delays, separated non-deployer role
        // holders, contract operator); development skips it so local/CI anvil deploys work as a
        // single-key deployer without extra config.
        config.hardenedGovernance = _loadEnvironment() == Environment.Production;
        config.adminExecutionDelay = uint32(vm.envOr("ADMIN_EXECUTION_DELAY", uint256(DEFAULT_ADMIN_EXECUTION_DELAY)));
        config.roleGrantDelay = uint32(vm.envOr("ROLE_GRANT_DELAY", uint256(DEFAULT_ROLE_GRANT_DELAY)));
        if (config.hardenedGovernance) {
            _validateHardenedGovernance(config, deployer);
        }
    }

    /// @dev Read DEPLOY_ENVIRONMENT (default "production"), mirroring core-service's SERVER_ENVIRONMENT.
    function _loadEnvironment() internal view returns (Environment) {
        return _parseEnvironment(vm.envOr("DEPLOY_ENVIRONMENT", string("production")));
    }

    /// @dev Case- and whitespace-insensitive parse, matching the Rust `Environment` FromStr:
    /// production/prod => Production; development/dev/test => Development; anything else reverts.
    function _parseEnvironment(string memory raw) internal pure returns (Environment) {
        bytes32 h = _normalizeEnv(raw);
        if (h == keccak256("production") || h == keccak256("prod")) {
            return Environment.Production;
        }
        if (h == keccak256("development") || h == keccak256("dev") || h == keccak256("test")) {
            return Environment.Development;
        }
        revert InvalidEnvironment(raw);
    }

    /// @dev Trim ASCII spaces and lowercase A-Z, then hash, so parsing tolerates casing/whitespace.
    function _normalizeEnv(string memory s) internal pure returns (bytes32) {
        bytes memory b = bytes(s);
        uint256 start = 0;
        uint256 end = b.length;
        while (start < end && b[start] == 0x20) start++;
        while (end > start && b[end - 1] == 0x20) end--;
        bytes memory out = new bytes(end - start);
        for (uint256 i = 0; i < out.length; i++) {
            bytes1 c = b[start + i];
            if (c >= 0x41 && c <= 0x5A) {
                c = bytes1(uint8(c) + 32); // A-Z -> a-z
            }
            out[i] = c;
        }
        return keccak256(out);
    }

    /// @dev Reject the single-key / zeroable-delay topology before any state is deployed:
    /// the admin must be a non-deployer contract (multisig/timelock heuristic), the admin/grant and
    /// governance/treasury delays must clear their minimums, and each role holder must be explicitly
    /// configured and distinct from the deployer.
    function _validateHardenedGovernance(DeploymentConfig memory config, address deployer) internal view {
        if (
            config.managerAdmin == deployer || config.managerAdmin == address(0) || config.managerAdmin.code.length == 0
        ) {
            revert InsecureGovernanceAdmin(config.managerAdmin);
        }
        if (config.adminExecutionDelay < MIN_ADMIN_EXECUTION_DELAY) {
            revert GovernanceDelayBelowMinimum(
                "ADMIN_EXECUTION_DELAY", config.adminExecutionDelay, MIN_ADMIN_EXECUTION_DELAY
            );
        }
        if (config.roleGrantDelay < MIN_ROLE_GRANT_DELAY) {
            revert GovernanceDelayBelowMinimum("ROLE_GRANT_DELAY", config.roleGrantDelay, MIN_ROLE_GRANT_DELAY);
        }
        if (_governanceDelay() < MIN_GOVERNANCE_EXECUTION_DELAY) {
            revert GovernanceDelayBelowMinimum(
                "GOVERNANCE_EXECUTION_DELAY", _governanceDelay(), MIN_GOVERNANCE_EXECUTION_DELAY
            );
        }
        if (_treasuryDelay() < MIN_TREASURY_EXECUTION_DELAY) {
            revert GovernanceDelayBelowMinimum(
                "TREASURY_EXECUTION_DELAY", _treasuryDelay(), MIN_TREASURY_EXECUTION_DELAY
            );
        }
        _requireSeparatedHolder("GOVERNANCE_ROLE_HOLDER", deployer);
        _requireSeparatedHolder("TREASURY_ROLE_HOLDER", deployer);
        _requireSeparatedHolder("GUARDIAN_ROLE_HOLDER", deployer);
        _requireOperatorHolder(
            vm.envAddress("FOURMICA_OPERATOR_ROLE_HOLDER"), deployer, vm.envOr("ALLOW_EOA_OPERATOR", false)
        );
    }

    /// @dev H01: the 4mica operator drives settlement. The ClearingHouse leaf-sum and future-deadline
    /// checks bound a compromised operator to a fabricated-cycle-then-wait attack (publicly observable)
    /// rather than an atomic drain, but a single operator key is still sufficient to attempt it. Require
    /// the operator to be a contract (multisig / smart-account) so no single key suffices. Threshold/HSM
    /// signers that present as an EOA on-chain must opt out explicitly via ALLOW_EOA_OPERATOR=true,
    /// making the residual single-key exposure a conscious deployment decision rather than a silent default.
    function _requireOperatorHolder(address holder, address deployer, bool allowEoa) internal view {
        _requireSeparatedHolder("FOURMICA_OPERATOR_ROLE_HOLDER", holder, deployer);
        if (holder.code.length == 0 && !allowEoa) {
            revert InsecureOperatorHolder(holder);
        }
    }

    function _requireSeparatedHolder(string memory envKey, address deployer) internal view {
        address holder = vm.envAddress(envKey); // reverts if unset
        _requireSeparatedHolder(envKey, holder, deployer);
    }

    /// @dev Pure topology check (no env), so a role holder can never silently default to the deployer.
    function _requireSeparatedHolder(string memory role, address holder, address deployer) internal pure {
        if (holder == deployer || holder == address(0)) {
            revert RoleHolderNotSeparated(role);
        }
    }

    function _finalizeHardenedGovernance(AccessManager manager, DeploymentConfig memory config) internal {
        manager.grantRole(ADMIN_ROLE, config.managerAdmin, config.adminExecutionDelay);

        manager.setGrantDelay(GOVERNANCE_ROLE, config.roleGrantDelay);
        manager.setGrantDelay(TREASURY_ROLE, config.roleGrantDelay);
        manager.setGrantDelay(GUARDIAN_ROLE, config.roleGrantDelay);
        manager.setGrantDelay(FOURMICA_OPERATOR_ROLE, config.roleGrantDelay);
        manager.setGrantDelay(CLEARING_HOUSE_ROLE, config.roleGrantDelay);
        manager.setGrantDelay(ADMIN_ROLE, config.roleGrantDelay);

        manager.renounceRole(ADMIN_ROLE, config.deployer);

        _assertHardenedGovernance(manager, config);
    }

    function _assertHardenedGovernance(AccessManager manager, DeploymentConfig memory config) internal view {
        (bool adminIsMember, uint32 adminDelay) = manager.hasRole(ADMIN_ROLE, config.managerAdmin);
        if (!adminIsMember || adminDelay < MIN_ADMIN_EXECUTION_DELAY) {
            revert AdminHandoffFailed(config.managerAdmin);
        }
        (bool deployerIsAdmin,) = manager.hasRole(ADMIN_ROLE, config.deployer);
        if (deployerIsAdmin) {
            revert DeployerRetainedAdmin(config.deployer);
        }
    }

    function _configureDeployedStack(FullStackDeployment memory deployment, DeploymentConfig memory config) internal {
        _assertStablecoinReadback(deployment.core4Mica, config.stablecoins);
        _configureOptionalAave(deployment.core4Mica, config.stablecoins);

        _configureCoreRoles(deployment.manager, deployment.core4Mica, config.deployer);
        _configureClearingHouseRoles(deployment.manager, deployment.clearingHouse, deployment.core4Mica);
    }

    function _deployFullStack(
        bytes32 baseSalt,
        address initialAdmin,
        BLS.G1Point memory guaranteeVerificationKey,
        address[] memory stablecoins,
        uint256 minWithdrawalGracePeriod
    ) internal returns (FullStackDeployment memory deployment) {
        address managerAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "ACCESS_MANAGER"),
            abi.encodePacked(type(AccessManager).creationCode, abi.encode(initialAdmin))
        );
        address core4MicaAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "CORE4MICA"),
            abi.encodePacked(
                type(Core4Mica).creationCode,
                abi.encode(managerAddress, guaranteeVerificationKey, stablecoins, minWithdrawalGracePeriod)
            )
        );
        address clearingHouseAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "CLEARING_HOUSE"),
            abi.encodePacked(type(ClearingHouse).creationCode, abi.encode(managerAddress, core4MicaAddress))
        );

        deployment.manager = AccessManager(managerAddress);
        deployment.core4Mica = Core4Mica(payable(core4MicaAddress));
        deployment.clearingHouse = ClearingHouse(payable(clearingHouseAddress));
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

        manager.grantRole(GOVERNANCE_ROLE, _roleHolder("GOVERNANCE_ROLE_HOLDER", deployer), _governanceDelay());
        manager.grantRole(TREASURY_ROLE, _roleHolder("TREASURY_ROLE_HOLDER", deployer), _treasuryDelay());
        manager.grantRole(GUARDIAN_ROLE, _roleHolder("GUARDIAN_ROLE_HOLDER", deployer), _guardianDelay());
        manager.grantRole(
            FOURMICA_OPERATOR_ROLE, _roleHolder("FOURMICA_OPERATOR_ROLE_HOLDER", deployer), _fourmicaOperatorDelay()
        );
    }

    function _configureClearingHouseRoles(AccessManager manager, ClearingHouse clearingHouse, Core4Mica core4Mica)
        internal
    {
        // Cycle commitment and default settlement are 4mica operator-driven settlement bookkeeping.
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

        // The ClearingHouse alone may move collateral inside Core4Mica during settlement,
        // including the scaled-escrow hooks used for liquidity-free stablecoin settlement
        //.
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

    function _deriveSalt(bytes32 baseSalt, string memory label) internal pure returns (bytes32) {
        return keccak256(abi.encode(baseSalt, label));
    }

    function _loadStablecoinAssets() internal view returns (address[] memory assets) {
        uint256 count = vm.envOr("STABLECOINS_COUNT", uint256(0));
        if (count > 0) {
            assets = new address[](count);
            for (uint256 i = 0; i < count; i++) {
                string memory key = string.concat("STABLECOIN_", vm.toString(i));
                assets[i] = vm.envAddress(key);
                require(assets[i] != address(0), "stablecoin address is zero");
            }
            return assets;
        }
        revert("set STABLECOINS_COUNT and STABLECOIN_0..n");
    }

    /// @dev Local-dev only: deploys STABLECOINS_COUNT fresh ERC20 mocks
    function _deployMockStablecoins() internal returns (address[] memory assets) {
        uint256 count = vm.envOr("STABLECOINS_COUNT", uint256(0));
        require(count > 0, "set STABLECOINS_COUNT for mock stablecoins");
        assets = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            // First token is a USDC stand-in; any extras get a distinct suffixed symbol.
            string memory name = i == 0 ? "USD Coin" : string.concat("USD Coin ", vm.toString(i));
            string memory symbol = i == 0 ? "USDC" : string.concat("USDC", vm.toString(i));
            MockERC20 token = new MockERC20(name, symbol, 6);
            assets[i] = address(token);
            console.log(string.concat("MockERC20 ", symbol, " deployed:"), assets[i]);
        }
    }

    function _validateStablecoins(address[] memory assets) internal pure {
        for (uint256 i = 0; i < assets.length; i++) {
            for (uint256 j = i + 1; j < assets.length; j++) {
                if (assets[i] == assets[j]) {
                    revert InvalidStablecoinConfiguration();
                }
            }
        }
    }

    function _assertStablecoinReadback(Core4Mica core4Mica, address[] memory expectedAssets) internal view {
        address[] memory storedAssets = core4Mica.getERC20Tokens();
        if (storedAssets.length != expectedAssets.length) {
            revert StablecoinReadbackMismatch();
        }
        for (uint256 i = 0; i < expectedAssets.length; i++) {
            if (storedAssets[i] != expectedAssets[i]) {
                revert StablecoinReadbackMismatch();
            }
        }
    }

    function _configureOptionalAave(Core4Mica core4Mica, address[] memory stablecoins) internal {
        bool configureAave = vm.envOr("CONFIGURE_AAVE", false);
        address provider = vm.envOr("AAVE_POOL_ADDRESSES_PROVIDER", address(0));
        (address[] memory aTokens, bool anyATokenSet, bool allATokensSet) = _loadStablecoinATokens(stablecoins.length);

        if ((provider != address(0) || anyATokenSet) && (!configureAave || provider == address(0) || !allATokensSet)) {
            revert PartialAaveConfiguration();
        }

        if (configureAave) {
            core4Mica.configureAave(provider, aTokens);
            if (address(core4Mica.aaveAddressesProvider()) != provider) {
                revert AaveReadbackMismatch("provider");
            }
            for (uint256 i = 0; i < stablecoins.length; i++) {
                if (core4Mica.stablecoinAToken(stablecoins[i]) != aTokens[i]) {
                    revert AaveReadbackMismatch(string.concat("stablecoinAToken", vm.toString(i)));
                }
            }
        }

        bool setYieldFee = vm.envOr("SET_YIELD_FEE_BPS", false);
        uint256 yieldFeeBps = vm.envOr("YIELD_FEE_BPS", uint256(0));
        if (setYieldFee) {
            core4Mica.setYieldFeeBps(yieldFeeBps);
            uint256 storedYieldFeeBps = core4Mica.yieldFeeBps();
            if (storedYieldFeeBps != yieldFeeBps) {
                revert YieldFeeReadbackMismatch(yieldFeeBps, storedYieldFeeBps);
            }
        }
    }

    function _loadStablecoinATokens(uint256 count)
        internal
        view
        returns (address[] memory aTokens, bool anyATokenSet, bool allATokensSet)
    {
        aTokens = new address[](count);
        allATokensSet = count > 0;
        for (uint256 i = 0; i < count; i++) {
            string memory key = string.concat("STABLECOIN_ATOKEN_", vm.toString(i));
            aTokens[i] = vm.envOr(key, address(0));
            if (aTokens[i] != address(0)) {
                anyATokenSet = true;
            } else {
                allATokensSet = false;
            }
        }
    }

    function _roleHolder(string memory envKey, address fallbackAddress) internal view returns (address) {
        return vm.envOr(envKey, fallbackAddress);
    }

    function _governanceDelay() internal view returns (uint32) {
        return uint32(vm.envOr("GOVERNANCE_EXECUTION_DELAY", uint256(DEFAULT_GOVERNANCE_EXECUTION_DELAY)));
    }

    function _treasuryDelay() internal view returns (uint32) {
        return uint32(vm.envOr("TREASURY_EXECUTION_DELAY", uint256(DEFAULT_TREASURY_EXECUTION_DELAY)));
    }

    function _guardianDelay() internal view returns (uint32) {
        return uint32(vm.envOr("GUARDIAN_EXECUTION_DELAY", uint256(DEFAULT_GUARDIAN_EXECUTION_DELAY)));
    }

    function _fourmicaOperatorDelay() internal view returns (uint32) {
        return uint32(vm.envOr("FOURMICA_OPERATOR_EXECUTION_DELAY", uint256(DEFAULT_FOURMICA_OPERATOR_EXECUTION_DELAY)));
    }
}
