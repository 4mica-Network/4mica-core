// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {Guarantee} from "../src/Core4Mica.sol";
import {ValidationRegistryGuaranteeDecoder} from "../src/ValidationRegistryGuaranteeDecoder.sol";
import {ValidationBindingConstants} from "../src/ValidationBindingConstants.sol";
import {MockValidationRegistry} from "./helpers/MockValidationRegistry.sol";

contract ValidationRegistryGuaranteeDecoderTest is Test, ValidationBindingConstants {
    MockValidationRegistry internal registry;
    ValidationRegistryGuaranteeDecoder internal decoder;

    function setUp() public {
        registry = new MockValidationRegistry();

        address[] memory trustedRegistries = new address[](1);
        trustedRegistries[0] = address(registry);
        decoder = new ValidationRegistryGuaranteeDecoder(trustedRegistries);
    }

    function test_decode_revertsWhenPendingValidation() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationPending.selector, g.validationRequestHash
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidationScoreTooLow() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        _setValidationStatus(g, g.validatorAddress, g.validatorAgentId, 79, "", 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationScoreTooLow.selector, uint8(79), g.minValidationScore
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_returnsGuaranteeWhenValidationPasses() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        _setValidationStatus(g, g.validatorAddress, g.validatorAgentId, 100, "hard-finality", 1);

        Guarantee memory decoded = decoder.decode(abi.encode(g));
        assertEq(decoded.domain, g.domain);
        assertEq(decoded.tabId, g.tabId);
        assertEq(decoded.reqId, g.reqId);
        assertEq(decoded.client, g.client);
        assertEq(decoded.recipient, g.recipient);
        assertEq(decoded.amount, g.amount);
        assertEq(decoded.totalAmount, g.totalAmount);
        assertEq(decoded.asset, g.asset);
        assertEq(decoded.timestamp, g.timestamp);
        assertEq(decoded.version, g.version);
    }

    function test_decode_revertsWhenRegistryLookupReverts() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        registry.setShouldRevert(true);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationLookupFailed.selector,
                g.validationRegistryAddress,
                g.validationRequestHash
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenRegistryHasNoCode() public {
        // Use an address with no deployed code to simulate a registry that doesn't exist
        // on the local chain (e.g. a real registry deployed on mainnet but not on anvil).
        address noCodeRegistry = address(0xdead);
        address[] memory trustedRegistries = new address[](1);
        trustedRegistries[0] = noCodeRegistry;
        ValidationRegistryGuaranteeDecoder noCodeDecoder =
            new ValidationRegistryGuaranteeDecoder(trustedRegistries);

        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.validationRegistryAddress = noCodeRegistry;
        // validationSubjectHash is independent of registry address; only request hash needs recomputing.
        g.validationRequestHash = _computeValidationRequestHash(g);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationLookupFailed.selector,
                noCodeRegistry,
                g.validationRequestHash
            )
        );
        noCodeDecoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidatorAddressMismatches() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        address mismatchedValidator = address(0xBEEFCAFE);
        _setValidationStatus(g, mismatchedValidator, g.validatorAgentId, 100, "hard-finality", 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationValidatorMismatch.selector,
                g.validatorAddress,
                mismatchedValidator
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenAgentIdMismatches() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        uint256 mismatchedAgentId = g.validatorAgentId + 1;
        _setValidationStatus(g, g.validatorAddress, mismatchedAgentId, 100, "hard-finality", 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationAgentMismatch.selector,
                g.validatorAgentId,
                mismatchedAgentId
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenTagMismatchesAndRequiredTagIsSet() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        _setValidationStatus(g, g.validatorAddress, g.validatorAgentId, 100, "soft-finality", 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationTagMismatch.selector,
                keccak256(bytes(g.requiredValidationTag)),
                keccak256(bytes("soft-finality"))
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidationSubjectHashMismatches() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.validationSubjectHash = bytes32(uint256(0xAAAA));
        g.validationRequestHash = _computeValidationRequestHash(g);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationSubjectHashMismatch.selector,
                _computeValidationSubjectHash(g),
                g.validationSubjectHash
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidationRequestHashMismatches() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.validationRequestHash = bytes32(uint256(0xBBBB));

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationRequestHashMismatch.selector,
                _computeValidationRequestHash(g),
                g.validationRequestHash
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_succeedsWhenResponseHashIsZero() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        _setValidationStatus(g, g.validatorAddress, g.validatorAgentId, 100, "hard-finality", 1);

        Guarantee memory decoded = decoder.decode(abi.encode(g));
        assertEq(decoded.reqId, g.reqId);
    }

    function test_decode_revertsWhenMinValidationScoreIsZero() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.minValidationScore = 0;
        g.validationRequestHash = _computeValidationRequestHash(g);

        vm.expectRevert(
            abi.encodeWithSelector(ValidationRegistryGuaranteeDecoder.InvalidMinValidationScore.selector, uint8(0))
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidationRegistryIsUntrusted() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.validationRegistryAddress = address(0xCAFE);
        g.validationRequestHash = _computeValidationRequestHash(g);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.UntrustedValidationRegistry.selector, g.validationRegistryAddress
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidationChainIdMismatches() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.validationChainId = uint64(block.chainid + 1);
        g.validationRequestHash = _computeValidationRequestHash(g);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.InvalidValidationChainId.selector,
                uint64(block.chainid),
                g.validationChainId
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenVersionIsNotV2() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.version = 1;

        vm.expectRevert(
            abi.encodeWithSelector(ValidationRegistryGuaranteeDecoder.UnsupportedGuaranteeVersion.selector, uint64(1))
        );
        decoder.decode(abi.encode(g));
    }

    function _canonicalV2() internal view returns (ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g) {
        g.domain = keccak256("DOMAIN");
        g.tabId = 101;
        g.reqId = 1;
        g.client = address(0x1111);
        g.recipient = address(0x2222);
        g.amount = 5 ether;
        g.totalAmount = 8 ether;
        g.asset = address(0x3333);
        g.timestamp = 1_750_000_000;
        g.version = GUARANTEE_CLAIMS_VERSION_V2;
        g.validationRegistryAddress = address(registry);
        g.validationChainId = uint64(block.chainid);
        g.validatorAddress = address(0x4444);
        g.validatorAgentId = 77;
        g.minValidationScore = 80;
        g.requiredValidationTag = "hard-finality";
        g.jobHash = keccak256("JOB");

        g.validationSubjectHash = _computeValidationSubjectHash(g);
        g.validationRequestHash = _computeValidationRequestHash(g);
    }

    function _setValidationStatus(
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g,
        address validatorAddress,
        uint256 agentId,
        uint8 response,
        string memory tag,
        uint256 lastUpdate
    ) internal {
        registry.setStatus(g.validationRequestHash, validatorAddress, agentId, response, bytes32(0), tag, lastUpdate);
    }

    function _computeValidationSubjectHash(ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                VALIDATION_SUBJECT_BINDING_DOMAIN_HASH,
                g.tabId,
                g.reqId,
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
                uint256(g.validationChainId),
                g.validationRegistryAddress,
                g.validatorAddress,
                g.validatorAgentId,
                g.validationSubjectHash,
                g.minValidationScore,
                keccak256(bytes(g.requiredValidationTag)),
                g.jobHash
            )
        );
    }
}
