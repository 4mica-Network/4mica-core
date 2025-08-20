// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BLSSignatureChecker} from "eigenlayer-middleware/src/BLSSignatureChecker.sol";
import {IRegistryCoordinator} from "eigenlayer-middleware/src/interfaces/IRegistryCoordinator.sol";

contract AuthorityContract is BLSSignatureChecker {
    address public owner;
    uint256 public minDepositAmount = 1 ether;

    struct User {
        bool exists;
        uint256 collateralAmount;
    }

    struct Recipient {
        bool exists;
        uint256 withdrawAmount; // Amount withdrawn to merchant if payment failed
    }

    mapping(address => User) public users;
    mapping(address => Recipient) public recipients;
    mapping(bytes32 => bool) public processedFailedTransactions;

    event UserRegistered(address indexed from, uint256 collateral);
    event UserAddDeposit(address indexed from, uint256 collateral);
    event RecipientRefunded(
        bytes32 indexed transactionHash, address indexed sender, address indexed recipient, uint256 amount
    );

    constructor(IRegistryCoordinator __registryCoordinator) BLSSignatureChecker(__registryCoordinator) {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Access Denied!");
        _;
    }

    modifier onlyUser() {
        require(users[msg.sender].exists, "User not found!");
        _;
    }

    function registerUser() public payable {
        require(msg.value >= minDepositAmount, "Insufficient funds!");
        require(!users[msg.sender].exists, "User already exists!");
        users[msg.sender] = User(true, msg.value);
        emit UserRegistered(msg.sender, msg.value);
    }

    function addDepositUser() public payable onlyUser {
        require(msg.value >= minDepositAmount, "Insufficient funds!");
        users[msg.sender].collateralAmount += msg.value;
        emit UserAddDeposit(msg.sender, msg.value);
    }

    function registerRecipient(address[] memory recipientAddresses) public onlyOwner {
        for (uint256 i = 0; i < recipientAddresses.length; i++) {
            require(!recipients[recipientAddresses[i]].exists, "Recipient already exists!");
            recipients[recipientAddresses[i]].exists = true;
        }
    }

    function verifyCertificate(string memory claims, bytes memory signature, address blsPublicKey)
        public
        pure
        returns (bool)
    {
        bytes memory claimsBytes = abi.encodePacked(claims);
        bool isValid = blsVerify(claimsBytes, signature, blsPublicKey);
        return isValid;
    }

    function blsVerify(bytes memory message, bytes memory signature, address publicKey) internal pure returns (bool) {
        // Placeholder: Replace with actual BLS logic
        bytes32 messageHash = keccak256(message);
        // Dummy check
        return signature.length > 0 && publicKey != address(0);
    }
}
