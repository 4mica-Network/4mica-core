// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Guarantee, IGuaranteeDecoder} from "./Core4Mica.sol";
import {IValidationRegistry} from "./interfaces/IValidationRegistry.sol";
import {ValidationBindingConstants} from "./ValidationBindingConstants.sol";

contract ValidationRegistryGuaranteeDecoder is
    IGuaranteeDecoder,
    ValidationBindingConstants
{
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
        uint256 tabId;
        uint256 reqId;
        address client;
        address recipient;
        uint256 amount;
        uint256 totalAmount;
        address asset;
        uint64 timestamp;
        uint64 version;
        address validationRegistryAddress;
        bytes32 validationRequestHash;
        uint64 validationChainId;
        address validatorAddress;
        uint256 validatorAgentId;
        uint8 minValidationScore;
        bytes32 validationSubjectHash;
        bytes32 jobHash;
        string requiredValidationTag;
    }

    mapping(address => bool) private trustedValidationRegistries;

    constructor(address[] memory trustedRegistries) {
        for (uint256 i = 0; i < trustedRegistries.length; i++) {
            trustedValidationRegistries[trustedRegistries[i]] = true;
        }
    }

    function decode(
        bytes calldata data
    ) external view override returns (Guarantee memory) {
        GuaranteeV2 memory g = abi.decode(data, (GuaranteeV2));

        if (g.version != GUARANTEE_CLAIMS_VERSION_V2) {
            revert UnsupportedGuaranteeVersion(g.version);
        }

        if (g.minValidationScore == 0 || g.minValidationScore > 100) {
            revert InvalidMinValidationScore(g.minValidationScore);
        }

        uint64 currentChainId = uint64(block.chainid);
        if (g.validationChainId != currentChainId) {
            revert InvalidValidationChainId(
                currentChainId,
                g.validationChainId
            );
        }

        if (!trustedValidationRegistries[g.validationRegistryAddress]) {
            revert UntrustedValidationRegistry(g.validationRegistryAddress);
        }

        bytes32 expectedSubjectHash = _computeValidationSubjectHash(g);
        if (g.validationSubjectHash != expectedSubjectHash) {
            revert ValidationSubjectHashMismatch(
                expectedSubjectHash,
                g.validationSubjectHash
            );
        }

        bytes32 expectedRequestHash = _computeValidationRequestHash(g);
        if (g.validationRequestHash != expectedRequestHash) {
            revert ValidationRequestHashMismatch(
                expectedRequestHash,
                g.validationRequestHash
            );
        }

        // Explicitly guard against no-code addresses: a staticcall to an address with no
        // code succeeds with empty returndata, and the subsequent ABI-decode failure is not
        // reliably caught by try/catch (Solidity via-ir edge case), producing an empty revert
        // instead of ValidationLookupFailed.
        if (g.validationRegistryAddress.code.length == 0) {
            revert ValidationLookupFailed(
                g.validationRegistryAddress,
                g.validationRequestHash
            );
        }

        address validatorAddress;
        uint256 agentId;
        uint8 response;
        string memory tag;
        uint256 lastUpdate;
        try
            IValidationRegistry(g.validationRegistryAddress)
                .getValidationStatus(g.validationRequestHash)
        returns (
            address validatorAddress_,
            uint256 agentId_,
            uint8 response_,
            bytes32 /* responseHash */,
            string memory tag_,
            uint256 lastUpdate_
        ) {
            validatorAddress = validatorAddress_;
            agentId = agentId_;
            response = response_;
            tag = tag_;
            lastUpdate = lastUpdate_;
        } catch {
            revert ValidationLookupFailed(
                g.validationRegistryAddress,
                g.validationRequestHash
            );
        }
        if (lastUpdate == 0) {
            revert ValidationPending(g.validationRequestHash);
        }

        if (response < g.minValidationScore) {
            revert ValidationScoreTooLow(response, g.minValidationScore);
        }

        if (validatorAddress != g.validatorAddress) {
            revert ValidationValidatorMismatch(
                g.validatorAddress,
                validatorAddress
            );
        }

        if (agentId != g.validatorAgentId) {
            revert ValidationAgentMismatch(g.validatorAgentId, agentId);
        }

        if (bytes(g.requiredValidationTag).length > 0) {
            bytes32 expectedTagHash;
            bytes32 actualTagHash;
            bytes memory expectedTagBytes = bytes(g.requiredValidationTag);
            bytes memory actualTagBytes = bytes(tag);
            assembly {
                expectedTagHash := keccak256(add(expectedTagBytes, 0x20), mload(expectedTagBytes))
                actualTagHash := keccak256(add(actualTagBytes, 0x20), mload(actualTagBytes))
            }
            if (actualTagHash != expectedTagHash) {
                revert ValidationTagMismatch(expectedTagHash, actualTagHash);
            }
        }

        return
            Guarantee({
                domain: g.domain,
                tabId: g.tabId,
                reqId: g.reqId,
                client: g.client,
                recipient: g.recipient,
                amount: g.amount,
                totalAmount: g.totalAmount,
                asset: g.asset,
                timestamp: g.timestamp,
                version: g.version
            });
    }

    function isTrustedValidationRegistry(
        address registry
    ) external view returns (bool) {
        return trustedValidationRegistries[registry];
    }

    function _computeHash(
        bytes memory encoded
    ) private pure returns (bytes32 digest) {
        assembly {
            digest := keccak256(add(encoded, 0x20), mload(encoded))
        }
    }

    function _computeValidationSubjectHash(
        GuaranteeV2 memory g
    ) internal pure returns (bytes32) {
        return
            _computeHash(
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

    function _computeValidationRequestHash(
        GuaranteeV2 memory g
    ) internal pure returns (bytes32) {
        return
            _computeHash(
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
