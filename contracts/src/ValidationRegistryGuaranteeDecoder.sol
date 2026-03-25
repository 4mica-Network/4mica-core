// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Guarantee, IGuaranteeDecoder} from "./Core4Mica.sol";
import {IValidationRegistry} from "./interfaces/IValidationRegistry.sol";
import {ValidationBindingConstants} from "./ValidationBindingConstants.sol";

contract ValidationRegistryGuaranteeDecoder is IGuaranteeDecoder, ValidationBindingConstants {
    error UnsupportedGuaranteeVersion(uint64 version);
    error InvalidMinValidationScore(uint8 score);
    error InvalidValidationChainId(uint64 expected, uint64 actual);
    error UntrustedValidationRegistry(address registry);
    error ValidationSubjectHashMismatch(bytes32 expected, bytes32 actual);
    error ValidationRequestHashMismatch(bytes32 expected, bytes32 actual);
    error ValidationLookupFailed(address registry, bytes32 requestHash);
    error ValidationPending(bytes32 requestHash);
    error ValidationScoreTooLow(uint8 response, uint8 minValidationScore);
    error ValidationValidatorMismatch(address expected, address actual);
    error ValidationAgentMismatch(uint256 expected, uint256 actual);
    error ValidationTagMismatch(bytes32 expectedTagHash, bytes32 actualTagHash);

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
        address validation_registry_address;
        bytes32 validation_request_hash;
        uint64 validation_chain_id;
        address validator_address;
        uint256 validator_agent_id;
        uint8 min_validation_score;
        bytes32 validation_subject_hash;
        string required_validation_tag;
    }

    mapping(address => bool) private trustedValidationRegistries;

    constructor(address[] memory trustedRegistries) {
        for (uint256 i = 0; i < trustedRegistries.length; i++) {
            trustedValidationRegistries[trustedRegistries[i]] = true;
        }
    }

    function decode(bytes calldata data) external view override returns (Guarantee memory) {
        GuaranteeV2 memory g = abi.decode(data, (GuaranteeV2));

        if (g.version != GUARANTEE_CLAIMS_VERSION_V2) {
            revert UnsupportedGuaranteeVersion(g.version);
        }

        if (g.min_validation_score == 0 || g.min_validation_score > 100) {
            revert InvalidMinValidationScore(g.min_validation_score);
        }

        uint64 currentChainId = uint64(block.chainid);
        if (g.validation_chain_id != currentChainId) {
            revert InvalidValidationChainId(currentChainId, g.validation_chain_id);
        }

        if (!trustedValidationRegistries[g.validation_registry_address]) {
            revert UntrustedValidationRegistry(g.validation_registry_address);
        }

        bytes32 expectedSubjectHash = _computeValidationSubjectHash(g);
        if (g.validation_subject_hash != expectedSubjectHash) {
            revert ValidationSubjectHashMismatch(expectedSubjectHash, g.validation_subject_hash);
        }

        bytes32 expectedRequestHash = _computeValidationRequestHash(g);
        if (g.validation_request_hash != expectedRequestHash) {
            revert ValidationRequestHashMismatch(expectedRequestHash, g.validation_request_hash);
        }

        // Explicitly guard against no-code addresses: a staticcall to an address with no
        // code succeeds with empty returndata, and the subsequent ABI-decode failure is not
        // reliably caught by try/catch (Solidity via-ir edge case), producing an empty revert
        // instead of ValidationLookupFailed.
        if (g.validation_registry_address.code.length == 0) {
            revert ValidationLookupFailed(g.validation_registry_address, g.validation_request_hash);
        }

        address validatorAddress;
        uint256 agentId;
        uint8 response;
        string memory tag;
        uint256 lastUpdate;
        try IValidationRegistry(g.validation_registry_address).getValidationStatus(g.validation_request_hash) returns (
            address validatorAddress_,
            uint256 agentId_,
            uint8 response_,
            bytes32, /* responseHash */
            string memory tag_,
            uint256 lastUpdate_
        ) {
            validatorAddress = validatorAddress_;
            agentId = agentId_;
            response = response_;
            tag = tag_;
            lastUpdate = lastUpdate_;
        } catch {
            revert ValidationLookupFailed(g.validation_registry_address, g.validation_request_hash);
        }

        if (lastUpdate == 0) {
            revert ValidationPending(g.validation_request_hash);
        }

        if (response < g.min_validation_score) {
            revert ValidationScoreTooLow(response, g.min_validation_score);
        }

        if (validatorAddress != g.validator_address) {
            revert ValidationValidatorMismatch(g.validator_address, validatorAddress);
        }

        if (agentId != g.validator_agent_id) {
            revert ValidationAgentMismatch(g.validator_agent_id, agentId);
        }

        if (bytes(g.required_validation_tag).length > 0) {
            bytes32 expectedTagHash = keccak256(bytes(g.required_validation_tag));
            bytes32 actualTagHash = keccak256(bytes(tag));
            if (actualTagHash != expectedTagHash) {
                revert ValidationTagMismatch(expectedTagHash, actualTagHash);
            }
        }

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

    function isTrustedValidationRegistry(address registry) external view returns (bool) {
        return trustedValidationRegistries[registry];
    }

    function _computeValidationSubjectHash(GuaranteeV2 memory g) internal pure returns (bytes32) {
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

    function _computeValidationRequestHash(GuaranteeV2 memory g) internal pure returns (bytes32) {
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
