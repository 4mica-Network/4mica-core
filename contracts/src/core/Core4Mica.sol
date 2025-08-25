// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

contract Core4Mica {
    // TODO user -> collateral {locked, available}
    address public owner;
    uint256 public minDepositAmount = 1 ether;

    struct User {
        uint256 collateralAmount;
        uint256 lockedCollateral;
        uint256 availableCollateral;
    }

    struct Transaction {
        bytes32 txHash;
        uint256 amount;
    }

    mapping(address => User) public users;
    mapping(address => Transaction) public transactions;

    // Events
    event UserRegistered(address indexed user, uint256 collateral);
    event UserAddedDeposit(address indexed user, uint256 amount);
    event RecipientRegistered(address indexed recipient);

    modifier onlyOwner() {
        require(msg.sender == owner, "Access Denied");
        _;
    }

    modifier onlyUser() {
        require(users[msg.sender].collateralAmount > 0, "User not found");
        _;
    }

    modifier onlyRecipient() {
        require(recipients[msg.sender], "Not a recipient");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerUser() external payable {
        require(msg.value >= minDepositAmount, "Insufficient funds");
        require(users[msg.sender].collateralAmount == 0, "Already registered");
        users[msg.sender] = User({collateralAmount: msg.value});
        emit UserRegistered(msg.sender, msg.value);
    }

    function addDepositUser() external payable onlyUser {
        require(msg.value >= minDepositAmount, "Insufficient funds");
        users[msg.sender].collateralAmount += msg.value;
        emit UserAddedDeposit(msg.sender, msg.value);
    }

    function registerRecipient(
        address[] calldata recipientAddresses
    ) external onlyOwner {
        for (uint256 i = 0; i < recipientAddresses.length; ++i) {
            address recipient = recipientAddresses[i];
            require(!recipients[recipient], "Already registered");
            recipients[recipient] = true;
            emit RecipientRegistered(recipient);
        }
    }

    function setMinDepositAmount(uint256 _minDepositAmount) external onlyOwner {
        require(_minDepositAmount > 0, "Must be > 0");
        minDepositAmount = _minDepositAmount;
    }
}
