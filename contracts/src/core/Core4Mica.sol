// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

contract Core4Mica {
    address public owner;
    uint256 public minDepositAmount = 1 ether;

    struct User {
        uint256 collateralAmount;
    }

    struct Transaction {
        bytes32 txHash;
        uint256 amount;
    }

    struct Aggregator {
        string grpcEndpoint;
    }

    struct Operator {
        bytes blsPublicKey;
        string grpcEndpoint;
    }

    Operator[] public operators;
    mapping(address => User) public users;
    mapping(address => bool) public recipients;
    mapping(address => Transaction) public transactions;
    mapping(address => Aggregator) public aggregators;

    // Events
    event AggregatorAdded(address indexed aggregatorAddress);
    event AggregatorRemoved(address indexed aggregatorAddress);
    event OperatorRemoved(address indexed operatorAddress);
    event OperatorAdded(address indexed operatorAddress, bytes blsPublicKey);
    event UserRegistered(address indexed user, uint256 collateral);
    event UserAddedDeposit(address indexed user, uint256 amount);
    event RecipientRegistered(address indexed recipient);

    modifier onlyOwner() {
        require(msg.sender == owner, "Access Denied");
        _;
    }

    modifier onlyAggregator() {
        require(
            bytes(aggregators[msg.sender].grpcEndpoint).length > 0,
            "Not aggregator"
        );
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

    function addOperator(
        bytes calldata blsPublicKey,
        string calldata grpcEndpoint
    ) external onlyOwner {
        require(blsPublicKey.length > 0, "Invalid BLS public key");
        require(bytes(grpcEndpoint).length > 0, "Invalid gRPC endpoint");
        operators.push(
            Operator({blsPublicKey: blsPublicKey, grpcEndpoint: grpcEndpoint})
        );
        emit OperatorAdded(msg.sender, blsPublicKey);
    }

    function removeOperator(address operatorAddress) external onlyOwner {
        require(operators.length > 0, "No operators to remove");
        for (uint256 i = 0; i < operators.length; ++i) {
            if (address(operators[i]) == operatorAddress) {
                operators[i] = operators[operators.length - 1];
                operators.pop();
                emit OperatorRemoved(operatorAddress);
                return;
            }
        }
        revert("Operator not found");
    }

    function addAggregator(string calldata grpcEndpoint) external onlyOwner {
        require(bytes(grpcEndpoint).length > 0, "Invalid gRPC endpoint");
        aggregators[msg.sender] = Aggregator({grpcEndpoint: grpcEndpoint});
        emit AggregatorRegistered(msg.sender);
    }

    function removeAggregator(address aggregatorAddress) external onlyOwner {
        require(
            bytes(aggregators[aggregatorAddress].grpcEndpoint).length > 0,
            "Aggregator not found"
        );
        delete aggregators[aggregatorAddress];
        emit AggregatorRemoved(aggregatorAddress);
    }
}
