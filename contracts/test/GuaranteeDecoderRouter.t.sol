// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";
import {Guarantee} from "../src/Core4Mica.sol";
import {GuaranteeDecoderRouter} from "../src/GuaranteeDecoderRouter.sol";
import {IGuaranteeVersionModule} from "../src/interfaces/IGuaranteeVersionModule.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";
import {BlsHelper} from "../src/BlsHelpers.sol";

contract MockGuaranteeModuleV3 is IGuaranteeVersionModule {
    struct GuaranteeV3 {
        bytes32 domain;
        uint256 tab_id;
        uint256 req_id;
        address client;
        address recipient;
        uint256 amount;
        uint256 total_amount;
        address asset;
        uint64 timestamp;
        uint64 version;
        bytes32 jobHash;
        uint256 qosScore;
    }

    function decodeModule(bytes calldata payload) external pure override returns (Guarantee memory) {
        GuaranteeV3 memory g = abi.decode(payload, (GuaranteeV3));
        return Guarantee({
            domain: g.domain,
            tab_id: g.tab_id,
            req_id: g.req_id,
            client: g.client,
            recipient: g.recipient,
            amount: g.amount,
            total_amount: g.total_amount,
            asset: g.asset,
            timestamp: g.timestamp,
            version: g.version
        });
    }
}

contract VersionMismatchModule is IGuaranteeVersionModule {
    function decodeModule(bytes calldata) external pure override returns (Guarantee memory) {
        return Guarantee({
            domain: bytes32(uint256(1)),
            tab_id: 1,
            req_id: 1,
            client: address(0x111),
            recipient: address(0x222),
            amount: 1,
            total_amount: 1,
            asset: address(0),
            timestamp: 1,
            version: 99
        });
    }
}

contract RevertingModule is IGuaranteeVersionModule {
    function decodeModule(bytes calldata) external pure override returns (Guarantee memory) {
        revert("MODULE_REVERT");
    }
}

contract GuaranteeDecoderRouterTest is Core4MicaTestBase {
    uint64 internal constant ROUTED_VERSION = 3;
    bytes32 internal constant TEST_PRIVATE_KEY_V3 =
        bytes32(0xA7FD35CF3AC80A878577D5EF07A420FC7D8A53CE6A22B483D659E5EFD1A2C7D1);

    GuaranteeDecoderRouter internal router;
    MockGuaranteeModuleV3 internal moduleV3;
    VersionMismatchModule internal mismatchModule;
    RevertingModule internal revertingModule;

    function setUp() public override {
        super.setUp();

        router = new GuaranteeDecoderRouter(address(manager));
        moduleV3 = new MockGuaranteeModuleV3();
        mismatchModule = new VersionMismatchModule();
        revertingModule = new RevertingModule();

        manager.setTargetFunctionRole(
            address(router), _asSingletonArray(router.setVersionModule.selector), USER_ADMIN_ROLE
        );
        manager.setTargetFunctionRole(
            address(router), _asSingletonArray(router.freezeVersion.selector), USER_ADMIN_ROLE
        );
    }

    function test_setVersionModule_andDecode_success() public {
        router.setVersionModule(ROUTED_VERSION, address(moduleV3));

        MockGuaranteeModuleV3.GuaranteeV3 memory g3 = _g3(bytes32(uint256(1)), ROUTED_VERSION);
        bytes memory routedPayload = abi.encode(ROUTED_VERSION, abi.encode(g3));
        Guarantee memory decoded = router.decode(routedPayload);

        assertEq(decoded.version, ROUTED_VERSION);
        assertEq(decoded.domain, g3.domain);
        assertEq(decoded.tab_id, g3.tab_id);
        assertEq(decoded.req_id, g3.req_id);
        assertEq(decoded.client, g3.client);
        assertEq(decoded.recipient, g3.recipient);
        assertEq(decoded.amount, g3.amount);
        assertEq(decoded.total_amount, g3.total_amount);
        assertEq(decoded.asset, g3.asset);
        assertEq(decoded.timestamp, g3.timestamp);
    }

    function test_setVersionModule_revertUnauthorized() public {
        vm.prank(USER1);
        vm.expectRevert(AccessUnauthorizedError(USER1));
        router.setVersionModule(ROUTED_VERSION, address(moduleV3));
    }

    function test_setVersionModule_revertInvalidVersion() public {
        vm.expectRevert(abi.encodeWithSelector(GuaranteeDecoderRouter.InvalidVersion.selector, uint64(0)));
        router.setVersionModule(0, address(moduleV3));
    }

    function test_setVersionModule_revertInvalidModule() public {
        vm.expectRevert(abi.encodeWithSelector(GuaranteeDecoderRouter.InvalidModule.selector, address(0)));
        router.setVersionModule(ROUTED_VERSION, address(0));

        vm.expectRevert(abi.encodeWithSelector(GuaranteeDecoderRouter.InvalidModule.selector, USER1));
        router.setVersionModule(ROUTED_VERSION, USER1);
    }

    function test_decode_revertUnknownVersion() public {
        bytes memory routedPayload = abi.encode(ROUTED_VERSION, bytes("does-not-matter"));
        vm.expectRevert(abi.encodeWithSelector(GuaranteeDecoderRouter.UnknownVersion.selector, ROUTED_VERSION));
        router.decode(routedPayload);
    }

    function test_freezeVersion_locksConfiguration() public {
        router.setVersionModule(ROUTED_VERSION, address(moduleV3));
        router.freezeVersion(ROUTED_VERSION);
        assertTrue(router.isVersionFrozen(ROUTED_VERSION));

        vm.expectRevert(abi.encodeWithSelector(GuaranteeDecoderRouter.FrozenVersion.selector, ROUTED_VERSION));
        router.setVersionModule(ROUTED_VERSION, address(mismatchModule));
    }

    function test_freezeVersion_revertUnknownVersion() public {
        vm.expectRevert(abi.encodeWithSelector(GuaranteeDecoderRouter.UnknownVersion.selector, ROUTED_VERSION));
        router.freezeVersion(ROUTED_VERSION);
    }

    function test_decode_revertOnModuleVersionMismatch() public {
        router.setVersionModule(ROUTED_VERSION, address(mismatchModule));
        bytes memory routedPayload = abi.encode(ROUTED_VERSION, bytes("x"));

        vm.expectRevert(
            abi.encodeWithSelector(GuaranteeDecoderRouter.ModuleVersionMismatch.selector, ROUTED_VERSION, uint64(99))
        );
        router.decode(routedPayload);
    }

    function test_decode_bubblesModuleRevert() public {
        router.setVersionModule(ROUTED_VERSION, address(revertingModule));
        bytes memory routedPayload = abi.encode(ROUTED_VERSION, bytes("x"));

        vm.expectRevert(bytes("MODULE_REVERT"));
        router.decode(routedPayload);
    }

    function test_core4Mica_verifyAndDecodeGuarantee_withRouterVersion() public {
        BLS.G1Point memory publicKeyV3 = BlsHelper.getPublicKey(TEST_PRIVATE_KEY_V3);
        bytes32 domainV3 = keccak256(abi.encode("4MICA_CORE_GUARANTEE_V3", block.chainid, address(core4Mica)));

        router.setVersionModule(ROUTED_VERSION, address(moduleV3));
        core4Mica.configureGuaranteeVersion(ROUTED_VERSION, publicKeyV3, domainV3, address(router), true);

        MockGuaranteeModuleV3.GuaranteeV3 memory g3 = _g3(domainV3, ROUTED_VERSION);
        bytes memory outerGuarantee = abi.encode(ROUTED_VERSION, abi.encode(ROUTED_VERSION, abi.encode(g3)));
        BLS.G2Point memory signature = BlsHelper.blsSign(outerGuarantee, TEST_PRIVATE_KEY_V3);

        Guarantee memory decoded = core4Mica.verifyAndDecodeGuarantee(outerGuarantee, signature);
        assertEq(decoded.version, ROUTED_VERSION);
        assertEq(decoded.domain, domainV3);
        assertEq(decoded.tab_id, g3.tab_id);
        assertEq(decoded.req_id, g3.req_id);
    }

    function test_core4Mica_verifyAndDecodeGuarantee_withRouterMissingModule_reverts() public {
        BLS.G1Point memory publicKeyV3 = BlsHelper.getPublicKey(TEST_PRIVATE_KEY_V3);
        bytes32 domainV3 = keccak256(abi.encode("4MICA_CORE_GUARANTEE_V3", block.chainid, address(core4Mica)));

        core4Mica.configureGuaranteeVersion(ROUTED_VERSION, publicKeyV3, domainV3, address(router), true);

        MockGuaranteeModuleV3.GuaranteeV3 memory g3 = _g3(domainV3, ROUTED_VERSION);
        bytes memory outerGuarantee = abi.encode(ROUTED_VERSION, abi.encode(ROUTED_VERSION, abi.encode(g3)));
        BLS.G2Point memory signature = BlsHelper.blsSign(outerGuarantee, TEST_PRIVATE_KEY_V3);

        vm.expectRevert(abi.encodeWithSelector(GuaranteeDecoderRouter.UnknownVersion.selector, ROUTED_VERSION));
        core4Mica.verifyAndDecodeGuarantee(outerGuarantee, signature);
    }

    function _g3(bytes32 domain, uint64 version) internal view returns (MockGuaranteeModuleV3.GuaranteeV3 memory) {
        return MockGuaranteeModuleV3.GuaranteeV3({
            domain: domain,
            tab_id: 77,
            req_id: 11,
            client: USER1,
            recipient: USER2,
            amount: 450 ether,
            total_amount: 800 ether,
            asset: address(usdc),
            timestamp: uint64(block.timestamp),
            version: version,
            jobHash: keccak256("job-hash"),
            qosScore: 97
        });
    }
}
