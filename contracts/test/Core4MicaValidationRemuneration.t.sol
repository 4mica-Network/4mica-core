// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "./Core4MicaTestBase.sol";
import {ValidationRegistryGuaranteeDecoder} from "../src/ValidationRegistryGuaranteeDecoder.sol";
import {ValidationBindingConstants} from "../src/ValidationBindingConstants.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";
import {BlsHelper} from "../src/BlsHelpers.sol";
import {MockValidationRegistry} from "./helpers/MockValidationRegistry.sol";

contract Core4MicaValidationRemunerationTest is Core4MicaTestBase, ValidationBindingConstants {
    MockValidationRegistry internal registry;
    ValidationRegistryGuaranteeDecoder internal decoder;
    bytes32 internal v2Domain;

    function setUp() public override {
        super.setUp();

        registry = new MockValidationRegistry();
        address[] memory trustedRegistries = new address[](1);
        trustedRegistries[0] = address(registry);
        decoder = new ValidationRegistryGuaranteeDecoder(trustedRegistries);

        v2Domain = keccak256(abi.encode("4MICA_CORE_GUARANTEE_V2", block.chainid, address(core4Mica)));
        core4Mica.configureGuaranteeVersion(
            GUARANTEE_CLAIMS_VERSION_V2, testPublicKey, v2Domain, address(decoder), true
        );
    }

    function test_remunerateV2_revertsWhenValidationPending() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabId = 0x9001;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g =
            _canonicalGuaranteeV2(tabId, 17, 0.5 ether, tabTimestamp);
        bytes memory guaranteeData = _encodeGuaranteeV2WithVersion(g);
        BLS.G2Point memory signature = BlsHelper.blsSign(guaranteeData, TEST_PRIVATE_KEY);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationPending.selector, g.validation_request_hash
            )
        );
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_remunerateV2_revertsWhenValidationScoreTooLow() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabId = 0x9002;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g =
            _canonicalGuaranteeV2(tabId, 18, 0.5 ether, tabTimestamp);
        registry.setStatus(
            g.validation_request_hash, g.validator_address, g.validator_agent_id, 79, bytes32(0), "hard-finality", 1
        );

        bytes memory guaranteeData = _encodeGuaranteeV2WithVersion(g);
        BLS.G2Point memory signature = BlsHelper.blsSign(guaranteeData, TEST_PRIVATE_KEY);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationScoreTooLow.selector, uint8(79), g.min_validation_score
            )
        );
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_remunerateV2_revertsWhenValidationLookupReverts() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabId = 0x9004;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g =
            _canonicalGuaranteeV2(tabId, 20, 0.5 ether, tabTimestamp);
        registry.setShouldRevert(true);

        bytes memory guaranteeData = _encodeGuaranteeV2WithVersion(g);
        BLS.G2Point memory signature = BlsHelper.blsSign(guaranteeData, TEST_PRIVATE_KEY);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationLookupFailed.selector,
                g.validation_registry_address,
                g.validation_request_hash
            )
        );
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_remunerateV2_revertsWhenValidationSubjectHashMismatches() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabId = 0x9005;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g =
            _canonicalGuaranteeV2(tabId, 21, 0.5 ether, tabTimestamp);
        g.validation_subject_hash = bytes32(uint256(0xAAAA));
        g.validation_request_hash = _computeValidationRequestHash(g);

        bytes memory guaranteeData = _encodeGuaranteeV2WithVersion(g);
        BLS.G2Point memory signature = BlsHelper.blsSign(guaranteeData, TEST_PRIVATE_KEY);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationSubjectHashMismatch.selector,
                _computeValidationSubjectHash(g),
                g.validation_subject_hash
            )
        );
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_remunerateV2_revertsWhenValidationRequestHashMismatches() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabId = 0x9006;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g =
            _canonicalGuaranteeV2(tabId, 22, 0.5 ether, tabTimestamp);
        g.validation_request_hash = bytes32(uint256(0xBBBB));

        bytes memory guaranteeData = _encodeGuaranteeV2WithVersion(g);
        BLS.G2Point memory signature = BlsHelper.blsSign(guaranteeData, TEST_PRIVATE_KEY);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationRequestHashMismatch.selector,
                _computeValidationRequestHash(g),
                g.validation_request_hash
            )
        );
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_remunerateV2_revertsWhenValidationRegistryIsUntrusted() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabId = 0x9007;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g =
            _canonicalGuaranteeV2(tabId, 23, 0.5 ether, tabTimestamp);
        g.validation_registry_address = address(0xCAFE);
        g.validation_request_hash = _computeValidationRequestHash(g);

        bytes memory guaranteeData = _encodeGuaranteeV2WithVersion(g);
        BLS.G2Point memory signature = BlsHelper.blsSign(guaranteeData, TEST_PRIVATE_KEY);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.UntrustedValidationRegistry.selector, g.validation_registry_address
            )
        );
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_remunerateV2_revertsWhenValidationTagMismatches() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabId = 0x9008;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g =
            _canonicalGuaranteeV2(tabId, 24, 0.5 ether, tabTimestamp);
        registry.setStatus(
            g.validation_request_hash, g.validator_address, g.validator_agent_id, 100, bytes32(0), "soft-finality", 1
        );

        bytes memory guaranteeData = _encodeGuaranteeV2WithVersion(g);
        BLS.G2Point memory signature = BlsHelper.blsSign(guaranteeData, TEST_PRIVATE_KEY);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationTagMismatch.selector,
                keccak256(bytes(g.required_validation_tag)),
                keccak256(bytes("soft-finality"))
            )
        );
        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);
    }

    function test_remunerateV2_succeedsWhenResponseHashIsZero() public {
        vm.prank(USER1);
        core4Mica.deposit{value: 1 ether}();

        uint256 tabId = 0x9009;
        uint256 tabTimestamp = 1;
        vm.warp(tabTimestamp + core4Mica.remunerationGracePeriod() + 5);

        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g =
            _canonicalGuaranteeV2(tabId, 25, 0.5 ether, tabTimestamp);
        registry.setStatus(
            g.validation_request_hash, g.validator_address, g.validator_agent_id, 100, bytes32(0), "hard-finality", 1
        );

        bytes memory guaranteeData = _encodeGuaranteeV2WithVersion(g);
        BLS.G2Point memory signature = BlsHelper.blsSign(guaranteeData, TEST_PRIVATE_KEY);

        vm.expectEmit(true, true, false, true);
        emit Core4Mica.RecipientRemunerated(tabId, ETH_ASSET, 0.5 ether);

        vm.prank(USER2);
        core4Mica.remunerate(guaranteeData, signature);

        assertEq(USER2.balance, 0.5 ether);
        (uint256 collateral,,) = core4Mica.getUser(USER1);
        assertEq(collateral, 0.5 ether);

        (uint256 paid, bool remunerated, address asset) = core4Mica.getPaymentStatus(tabId);
        assertEq(paid, 0);
        assertTrue(remunerated);
        assertEq(asset, ETH_ASSET);
    }

    function _canonicalGuaranteeV2(uint256 tabId, uint256 reqId, uint256 amount, uint256 timestamp)
        internal
        view
        returns (ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g)
    {
        g.domain = v2Domain;
        g.tab_id = tabId;
        g.req_id = reqId;
        g.client = USER1;
        g.recipient = USER2;
        g.amount = amount;
        g.total_amount = amount;
        g.asset = ETH_ASSET;
        g.timestamp = uint64(timestamp);
        g.version = GUARANTEE_CLAIMS_VERSION_V2;
        g.validation_registry_address = address(registry);
        g.validation_chain_id = uint64(block.chainid);
        g.validator_address = address(0x4444);
        g.validator_agent_id = 77;
        g.min_validation_score = 80;
        g.required_validation_tag = "hard-finality";
        g.job_hash = keccak256("JOB");
        g.validation_subject_hash = _computeValidationSubjectHash(g);
        g.validation_request_hash = _computeValidationRequestHash(g);
    }

    function _encodeGuaranteeV2WithVersion(ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(uint64(GUARANTEE_CLAIMS_VERSION_V2), abi.encode(g));
    }

    function _computeValidationSubjectHash(ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                VALIDATION_SUBJECT_BINDING_DOMAIN_HASH,
                g.tab_id,
                g.req_id,
                g.client,
                g.recipient,
                g.amount,
                g.asset,
                g.timestamp
            )
        );
    }

    function _computeValidationRequestHash(ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                VALIDATION_REQUEST_BINDING_DOMAIN_HASH,
                uint256(g.validation_chain_id),
                g.validation_registry_address,
                g.validator_address,
                g.validator_agent_id,
                g.validation_subject_hash,
                g.min_validation_score,
                keccak256(bytes(g.required_validation_tag)),
                g.job_hash
            )
        );
    }
}
