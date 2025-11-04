// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";
import {IGuaranteeDecoder, Guarantee} from "../src/Core4Mica.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";
import {BlsHelper} from "../src/BlsHelpers.sol";

contract MockGuaranteeDecoder is IGuaranteeDecoder {
    struct GuaranteeV2 {
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
        bytes32 memo;
    }

    function encode(GuaranteeV2 memory g) external pure returns (bytes memory) {
        return abi.encode(g);
    }

    function decode(
        bytes calldata data
    ) external pure override returns (Guarantee memory) {
        GuaranteeV2 memory g = abi.decode(data, (GuaranteeV2));
        return
            Guarantee({
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

contract Core4MicaGuaranteeVersionsTest is Core4MicaTestBase {
    MockGuaranteeDecoder internal decoder;
    bytes32 internal constant TEST_PRIVATE_KEY_V2 =
        bytes32(
            0x9373427D6A25FD7C4CD1D286B1E9630FF4F95C5A625CB9974630FA2B5311AEE3
        );

    function setUp() public override {
        super.setUp();
        decoder = new MockGuaranteeDecoder();
    }

    function test_configureGuaranteeVersion_setsAndUsesNewVersion() public {
        vm.warp(100);

        bytes32 domainV2 = keccak256(
            abi.encode("4MICA_CORE_GUARANTEE_V2", block.chainid, address(core4Mica))
        );
        BLS.G1Point memory publicKeyV2 = BlsHelper.getPublicKey(
            TEST_PRIVATE_KEY_V2
        );

        core4Mica.configureGuaranteeVersion(
            2,
            publicKeyV2,
            domainV2,
            address(decoder),
            true
        );

        (
            BLS.G1Point memory storedKey,
            bytes32 storedDomain,
            address storedDecoder,
            bool enabled
        ) = core4Mica.getGuaranteeVersionConfig(2);

        assertTrue(enabled);
        assertEq(storedDomain, domainV2);
        assertEq(storedDecoder, address(decoder));
        assertEq(storedKey.x_a, publicKeyV2.x_a);
        assertEq(storedKey.x_b, publicKeyV2.x_b);
        assertEq(storedKey.y_a, publicKeyV2.y_a);
        assertEq(storedKey.y_b, publicKeyV2.y_b);

        MockGuaranteeDecoder.GuaranteeV2 memory g2 = _guaranteeV2(
            domainV2,
            101,
            11,
            USER1,
            USER2,
            500 ether,
            address(usdc),
            uint64(block.timestamp),
            2
        );

        bytes memory encodedGuarantee = abi.encode(g2);
        BLS.G2Point memory signature = _signGuaranteeV2(g2, TEST_PRIVATE_KEY_V2);
        Guarantee memory decoded = core4Mica.verifyAndDecodeGuarantee(
            abi.encode(uint64(2), encodedGuarantee),
            signature
        );

        assertEq(decoded.version, 2);
        assertEq(decoded.domain, domainV2);
        assertEq(decoded.tab_id, g2.tab_id);
        assertEq(decoded.req_id, g2.req_id);
        assertEq(decoded.client, g2.client);
        assertEq(decoded.recipient, g2.recipient);
        assertEq(decoded.amount, g2.amount);
        assertEq(decoded.total_amount, g2.total_amount);
        assertEq(decoded.asset, g2.asset);
        assertEq(decoded.timestamp, g2.timestamp);
    }

    function test_configureGuaranteeVersion_revertWhenMissingDecoder() public {
        bytes32 domainV2 = keccak256("DOMAIN_V2");
        BLS.G1Point memory publicKeyV2 = BlsHelper.getPublicKey(
            TEST_PRIVATE_KEY_V2
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.MissingGuaranteeDecoder.selector,
                uint64(2)
            )
        );
        core4Mica.configureGuaranteeVersion(
            2,
            publicKeyV2,
            domainV2,
            address(0),
            true
        );
    }

    function test_configureGuaranteeVersion_revertUnauthorizedCaller() public {
        bytes32 domainV2 = keccak256("DOMAIN_V2");
        BLS.G1Point memory publicKeyV2 = BlsHelper.getPublicKey(
            TEST_PRIVATE_KEY_V2
        );

        vm.prank(USER1);
        vm.expectRevert(AccessUnauthorizedError(USER1));
        core4Mica.configureGuaranteeVersion(
            2,
            publicKeyV2,
            domainV2,
            address(decoder),
            true
        );
    }

    function test_configureGuaranteeVersion_revertVersionZero() public {
        BLS.G1Point memory publicKey = BlsHelper.getPublicKey(TEST_PRIVATE_KEY_V2);
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UnsupportedGuaranteeVersion.selector,
                uint64(0)
            )
        );
        core4Mica.configureGuaranteeVersion(
            0,
            publicKey,
            keccak256("DOMAIN_V2"),
            address(decoder),
            true
        );
    }

    function test_configureGuaranteeVersion_revertVersionOneWithDecoder() public {
        BLS.G1Point memory newKey = BlsHelper.getPublicKey(TEST_PRIVATE_KEY_V2);
        uint64 initialVersion = core4Mica.INITIAL_GUARANTEE_VERSION();
        bytes32 currentDomain = core4Mica.guaranteeDomainSeparator();
        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UnsupportedGuaranteeVersion.selector,
                initialVersion
            )
        );
        core4Mica.configureGuaranteeVersion(
            initialVersion,
            newKey,
            currentDomain,
            address(0x123),
            true
        );
    }

    function test_configureGuaranteeVersion_revertMissingDomainWhenEnabled() public {
        BLS.G1Point memory publicKey = BlsHelper.getPublicKey(TEST_PRIVATE_KEY_V2);
        vm.expectRevert(Core4Mica.InvalidGuaranteeDomain.selector);
        core4Mica.configureGuaranteeVersion(
            2,
            publicKey,
            bytes32(0),
            address(decoder),
            true
        );
    }

    function test_verifyAndDecodeGuarantee_revertWhenVersionDisabled() public {
        bytes32 domainV2 = keccak256("DOMAIN_V2");
        BLS.G1Point memory publicKeyV2 = BlsHelper.getPublicKey(
            TEST_PRIVATE_KEY_V2
        );
        core4Mica.configureGuaranteeVersion(
            2,
            publicKeyV2,
            domainV2,
            address(decoder),
            true
        );

        // Disable without providing new decoder/domain (reuse stored ones)
        core4Mica.configureGuaranteeVersion(
            2,
            publicKeyV2,
            bytes32(0),
            address(0),
            false
        );

        MockGuaranteeDecoder.GuaranteeV2 memory g2 = _guaranteeV2(
            domainV2,
            7,
            3,
            USER1,
            USER2,
            100 ether,
            address(usdt),
            uint64(block.timestamp),
            2
        );
        bytes memory payload = abi.encode(uint64(2), abi.encode(g2));
        BLS.G2Point memory signature = _signGuaranteeV2(g2, TEST_PRIVATE_KEY_V2);

        vm.expectRevert(
            abi.encodeWithSelector(
                Core4Mica.UnsupportedGuaranteeVersion.selector,
                uint64(2)
            )
        );
        core4Mica.verifyAndDecodeGuarantee(payload, signature);
    }

    function test_verifyAndDecodeGuarantee_revertOnDomainMismatch() public {
        bytes32 domainV2 = keccak256("DOMAIN_V2_MATCH");
        bytes32 wrongDomain = keccak256("DOMAIN_V2_WRONG");
        BLS.G1Point memory publicKeyV2 = BlsHelper.getPublicKey(
            TEST_PRIVATE_KEY_V2
        );
        core4Mica.configureGuaranteeVersion(
            2,
            publicKeyV2,
            domainV2,
            address(decoder),
            true
        );

        MockGuaranteeDecoder.GuaranteeV2 memory g2 = _guaranteeV2(
            wrongDomain,
            12,
            9,
            USER1,
            USER2,
            200 ether,
            address(usdc),
            uint64(block.timestamp),
            2
        );
        bytes memory payload = abi.encode(uint64(2), abi.encode(g2));
        BLS.G2Point memory signature = _signGuaranteeV2(g2, TEST_PRIVATE_KEY_V2);

        vm.expectRevert(Core4Mica.InvalidGuaranteeDomain.selector);
        core4Mica.verifyAndDecodeGuarantee(payload, signature);
    }

    function test_setGuaranteeVerificationKey_updatesVersionOneConfig() public {
        BLS.G1Point memory newKey = BlsHelper.getPublicKey(TEST_PRIVATE_KEY_V2);

        core4Mica.setGuaranteeVerificationKey(newKey);

        (
            BLS.G1Point memory storedKey,
            bytes32 storedDomain,
            address storedDecoder,
            bool enabled
        ) = core4Mica.getGuaranteeVersionConfig(
                core4Mica.INITIAL_GUARANTEE_VERSION()
            );

        assertTrue(enabled);
        assertEq(storedDecoder, address(0));
        assertEq(storedDomain, core4Mica.guaranteeDomainSeparator());
        assertEq(storedKey.x_a, newKey.x_a);
        assertEq(storedKey.x_b, newKey.x_b);
        assertEq(storedKey.y_a, newKey.y_a);
        assertEq(storedKey.y_b, newKey.y_b);
    }

    function test_configureGuaranteeVersion_updatesVersionOne() public {
        bytes32 newDomain = keccak256(
            abi.encode("4MICA_DOMAIN_V1", block.chainid, address(core4Mica))
        );
        BLS.G1Point memory newKey = BlsHelper.getPublicKey(TEST_PRIVATE_KEY_V2);

        core4Mica.configureGuaranteeVersion(
            core4Mica.INITIAL_GUARANTEE_VERSION(),
            newKey,
            newDomain,
            address(0),
            true
        );

        assertEq(core4Mica.guaranteeDomainSeparator(), newDomain);

        Guarantee memory g = _guarantee(
            1,
            block.timestamp,
            USER1,
            USER2,
            1,
            50,
            address(usdc)
        );
        g.domain = newDomain;
        g.version = core4Mica.INITIAL_GUARANTEE_VERSION();

        BLS.G2Point memory sig = _signGuarantee(g, TEST_PRIVATE_KEY_V2);

        Guarantee memory decoded = core4Mica.verifyAndDecodeGuarantee(
            _encodeGuaranteeWithVersion(g),
            sig
        );
        assertEq(decoded.domain, newDomain);
    }

    function _guaranteeV2(
        bytes32 domain,
        uint256 tabId,
        uint256 reqId,
        address client,
        address recipient,
        uint256 amount,
        address asset,
        uint64 timestamp,
        uint64 version
    ) internal pure returns (MockGuaranteeDecoder.GuaranteeV2 memory) {
        return
            MockGuaranteeDecoder.GuaranteeV2({
                domain: domain,
                tab_id: tabId,
                req_id: reqId,
                client: client,
                recipient: recipient,
                amount: amount,
                total_amount: amount,
                asset: asset,
                timestamp: timestamp,
                version: version,
                memo: bytes32(uint256(123))
            });
    }

    function _signGuaranteeV2(
        MockGuaranteeDecoder.GuaranteeV2 memory g,
        bytes32 privKey
    ) internal view returns (BLS.G2Point memory) {
        bytes memory payload = abi.encode(uint64(g.version), abi.encode(g));
        return BlsHelper.blsSign(payload, privKey);
    }
}
