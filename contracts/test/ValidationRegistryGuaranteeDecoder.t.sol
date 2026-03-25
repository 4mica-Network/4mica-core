// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Test.sol";
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
                ValidationRegistryGuaranteeDecoder.ValidationPending.selector, g.validation_request_hash
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidationScoreTooLow() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        _setValidationStatus(g, g.validator_address, g.validator_agent_id, 79, "", 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationScoreTooLow.selector, uint8(79), g.min_validation_score
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_returnsGuaranteeWhenValidationPasses() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        _setValidationStatus(g, g.validator_address, g.validator_agent_id, 100, "hard-finality", 1);

        Guarantee memory decoded = decoder.decode(abi.encode(g));
        assertEq(decoded.domain, g.domain);
        assertEq(decoded.tab_id, g.tab_id);
        assertEq(decoded.req_id, g.req_id);
        assertEq(decoded.client, g.client);
        assertEq(decoded.recipient, g.recipient);
        assertEq(decoded.amount, g.amount);
        assertEq(decoded.total_amount, g.total_amount);
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
                g.validation_registry_address,
                g.validation_request_hash
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
        g.validation_registry_address = noCodeRegistry;
        // validation_subject_hash is independent of registry address; only request hash needs recomputing.
        g.validation_request_hash = _computeValidationRequestHash(g);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationLookupFailed.selector,
                noCodeRegistry,
                g.validation_request_hash
            )
        );
        noCodeDecoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidatorAddressMismatches() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        address mismatchedValidator = address(0xBEEFCAFE);
        _setValidationStatus(g, mismatchedValidator, g.validator_agent_id, 100, "hard-finality", 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationValidatorMismatch.selector,
                g.validator_address,
                mismatchedValidator
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenAgentIdMismatches() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        uint256 mismatchedAgentId = g.validator_agent_id + 1;
        _setValidationStatus(g, g.validator_address, mismatchedAgentId, 100, "hard-finality", 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationAgentMismatch.selector,
                g.validator_agent_id,
                mismatchedAgentId
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenTagMismatchesAndRequiredTagIsSet() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        _setValidationStatus(g, g.validator_address, g.validator_agent_id, 100, "soft-finality", 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationTagMismatch.selector,
                keccak256(bytes(g.required_validation_tag)),
                keccak256(bytes("soft-finality"))
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidationSubjectHashMismatches() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.validation_subject_hash = bytes32(uint256(0xAAAA));
        g.validation_request_hash = _computeValidationRequestHash(g);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationSubjectHashMismatch.selector,
                _computeValidationSubjectHash(g),
                g.validation_subject_hash
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidationRequestHashMismatches() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.validation_request_hash = bytes32(uint256(0xBBBB));

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.ValidationRequestHashMismatch.selector,
                _computeValidationRequestHash(g),
                g.validation_request_hash
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_succeedsWhenResponseHashIsZero() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        _setValidationStatus(g, g.validator_address, g.validator_agent_id, 100, "hard-finality", 1);

        Guarantee memory decoded = decoder.decode(abi.encode(g));
        assertEq(decoded.req_id, g.req_id);
    }

    function test_decode_revertsWhenMinValidationScoreIsZero() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.min_validation_score = 0;
        g.validation_request_hash = _computeValidationRequestHash(g);

        vm.expectRevert(
            abi.encodeWithSelector(ValidationRegistryGuaranteeDecoder.InvalidMinValidationScore.selector, uint8(0))
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidationRegistryIsUntrusted() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.validation_registry_address = address(0xCAFE);
        g.validation_request_hash = _computeValidationRequestHash(g);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.UntrustedValidationRegistry.selector, g.validation_registry_address
            )
        );
        decoder.decode(abi.encode(g));
    }

    function test_decode_revertsWhenValidationChainIdMismatches() public {
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g = _canonicalV2();
        g.validation_chain_id = uint64(block.chainid + 1);
        g.validation_request_hash = _computeValidationRequestHash(g);

        vm.expectRevert(
            abi.encodeWithSelector(
                ValidationRegistryGuaranteeDecoder.InvalidValidationChainId.selector,
                uint64(block.chainid),
                g.validation_chain_id
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
        g.tab_id = 101;
        g.req_id = 1;
        g.client = address(0x1111);
        g.recipient = address(0x2222);
        g.amount = 5 ether;
        g.total_amount = 8 ether;
        g.asset = address(0x3333);
        g.timestamp = 1_750_000_000;
        g.version = GUARANTEE_CLAIMS_VERSION_V2;
        g.validation_registry_address = address(registry);
        g.validation_chain_id = uint64(block.chainid);
        g.validator_address = address(0x4444);
        g.validator_agent_id = 77;
        g.min_validation_score = 80;
        g.required_validation_tag = "hard-finality";

        g.validation_subject_hash = _computeValidationSubjectHash(g);
        g.validation_request_hash = _computeValidationRequestHash(g);
    }

    function _setValidationStatus(
        ValidationRegistryGuaranteeDecoder.GuaranteeV2 memory g,
        address validatorAddress,
        uint256 agentId,
        uint8 response,
        string memory tag,
        uint256 lastUpdate
    ) internal {
        registry.setStatus(g.validation_request_hash, validatorAddress, agentId, response, bytes32(0), tag, lastUpdate);
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
                keccak256(bytes(g.required_validation_tag))
            )
        );
    }
}
