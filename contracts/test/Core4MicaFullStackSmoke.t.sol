// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";

import {Core4Mica} from "../src/Core4Mica.sol";
import {GuaranteeDecoderRouter} from "../src/GuaranteeDecoderRouter.sol";
import {ValidationRegistryGuaranteeDecoder} from "../src/ValidationRegistryGuaranteeDecoder.sol";
import {BlsHelper} from "../src/BlsHelpers.sol";

contract Core4MicaFullStackSmokeTest is Test {
    bytes4 private constant RECORD_PAYMENT_SELECTOR = bytes4(keccak256("recordPayment(uint256,address,uint256)"));
    bytes4 private constant SET_TIMING_PARAMETERS_SELECTOR =
        bytes4(keccak256("setTimingParameters(uint256,uint256,uint256,uint256)"));
    uint64 private constant USER_ADMIN_ROLE = 4;
    uint64 private constant OPERATOR_ROLE = 9;
    uint64 private constant GUARANTEE_V2 = 2;
    bytes32 private constant TEST_PRIVATE_KEY =
        bytes32(0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3);
    address private constant USDC = address(0xA0);
    address private constant USDT = address(0xB0);

    function test_fullStackDeploymentConfiguresV1AndV2GuaranteeVersions() public {
        address deployer = address(this);
        AccessManager manager = new AccessManager(deployer);
        BLS.G1Point memory verificationKey = BlsHelper.getPublicKey(TEST_PRIVATE_KEY);

        Core4Mica core4Mica = new Core4Mica(address(manager), verificationKey, USDC, USDT);
        GuaranteeDecoderRouter router = new GuaranteeDecoderRouter(address(manager));

        address[] memory trustedRegistries = new address[](1);
        trustedRegistries[0] = address(0x8004AA63c570c570eBF15376c0dB199918BFe9Fb);
        ValidationRegistryGuaranteeDecoder validationDecoder = new ValidationRegistryGuaranteeDecoder(trustedRegistries);

        _configureCoreRoles(manager, core4Mica, deployer);
        _configureRouterRoles(manager, router);

        bytes32 v2Domain = keccak256(abi.encode("4MICA_CORE_GUARANTEE_V2", block.chainid, address(core4Mica)));
        core4Mica.configureGuaranteeVersion(GUARANTEE_V2, verificationKey, v2Domain, address(validationDecoder), true);

        (BLS.G1Point memory v1Key, bytes32 v1Domain, address v1Decoder, bool v1Enabled) =
            core4Mica.getGuaranteeVersionConfig(core4Mica.INITIAL_GUARANTEE_VERSION());
        assertTrue(v1Enabled);
        assertEq(v1Domain, core4Mica.guaranteeDomainSeparator());
        assertEq(v1Decoder, address(0));
        _assertSameKey(v1Key, verificationKey);

        (BLS.G1Point memory v2Key, bytes32 configuredV2Domain, address v2Decoder, bool v2Enabled) =
            core4Mica.getGuaranteeVersionConfig(GUARANTEE_V2);
        assertTrue(v2Enabled);
        assertEq(configuredV2Domain, v2Domain);
        assertEq(v2Decoder, address(validationDecoder));
        _assertSameKey(v2Key, verificationKey);

        assertTrue(validationDecoder.isTrustedValidationRegistry(trustedRegistries[0]));
    }

    function _configureCoreRoles(AccessManager manager, Core4Mica core4Mica, address deployer) internal {
        manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(RECORD_PAYMENT_SELECTOR), OPERATOR_ROLE);

        bytes4[] memory adminSelectors = new bytes4[](15);
        adminSelectors[0] = Core4Mica.setWithdrawalGracePeriod.selector;
        adminSelectors[1] = Core4Mica.setRemunerationGracePeriod.selector;
        adminSelectors[2] = Core4Mica.setTabExpirationTime.selector;
        adminSelectors[3] = Core4Mica.setGuaranteeVerificationKey.selector;
        adminSelectors[4] = SET_TIMING_PARAMETERS_SELECTOR;
        adminSelectors[5] = Core4Mica.setSynchronizationDelay.selector;
        adminSelectors[6] = Core4Mica.configureGuaranteeVersion.selector;
        adminSelectors[7] = Core4Mica.pause.selector;
        adminSelectors[8] = Core4Mica.unpause.selector;
        adminSelectors[9] = Core4Mica.setStablecoinAsset.selector;
        adminSelectors[10] = Core4Mica.setStablecoinAssets.selector;
        adminSelectors[11] = Core4Mica.configureAave.selector;
        adminSelectors[12] = Core4Mica.setYieldFeeBps.selector;
        adminSelectors[13] = Core4Mica.setStablecoinDepositsEnabled.selector;
        adminSelectors[14] = Core4Mica.claimProtocolYield.selector;

        for (uint256 i = 0; i < adminSelectors.length; i++) {
            manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(adminSelectors[i]), USER_ADMIN_ROLE);
        }

        manager.grantRole(OPERATOR_ROLE, deployer, 0);
        manager.grantRole(USER_ADMIN_ROLE, deployer, 0);
    }

    function _configureRouterRoles(AccessManager manager, GuaranteeDecoderRouter router) internal {
        manager.setTargetFunctionRole(
            address(router), _asSingletonArray(router.setVersionModule.selector), USER_ADMIN_ROLE
        );
        manager.setTargetFunctionRole(
            address(router), _asSingletonArray(router.freezeVersion.selector), USER_ADMIN_ROLE
        );
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
}
