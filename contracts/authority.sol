pragma solidity 0.8.28;

contract AuthorityContract {
    address public owner;
    uint256 public minDepositAmount = 1 ether;

    struct User {
        bool exists;
        uint256 collateralAmount;
    }

    struct Recipient {
        bool exists;
        uint256 withdrawAmount /* Amount withdrawn to merchant in case that payment failed */;
    }

    mapping(address => User) public users;
    mapping(address => Recipient) public recipients;
    mapping(bytes32 => bool) public processedFailedTransactions;

    event UserRegistered(address _from, uint _collateral);
    event UserAddDeposit(address _from, uint _collateral);
    event RecipientRefunded(
        bytes32 indexed transactionHash,
        address indexed sender,
        address indexed recipient,
        uint256 amount
    );

    constructor() {
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
        users[msg.sender].collateralAmount = msg.value;
        users[msg.sender].exists = true;
        emit UserRegistered(msg.sender, msg.value);
    }

    function addDepositUser() public payable onlyUser {
        require(msg.value >= minDepositAmount, "Insufficient funds!");
        users[msg.sender].collateralAmount += msg.value;
        emit UserAddDeposit(msg.sender, msg.value);
    }

    function registerRecipient(
        address[] memory recipientAddresses
    ) public onlyOwner {
        for (uint i = 0; i < recipientAddresses.length; i++) {
            require(
                !recipients[recipientAddresses[i]].exists,
                "Recipient already exists!"
            );
            recipients[recipientAddresses[i]].exists = true;
        }
    }

    function remunerateVictim(
        address senderAddress,
        address recipientAddress,
        bytes32 transactionHash,
        uint amount
    ) public {
        require(recipients[msg.sender].exists, "Access Denied!");
        require(
            !processedFailedTransactions[transactionHash],
            "Transaction already processed"
        );
        require(recipientAddress == msg.sender, "Access Denied!");
        require(recipients[recipientAddress].exists, "Access Denied!");
        require(users[senderAddress].exists, "User not found!");
        require(
            users[senderAddress].collateralAmount >= amount,
            "Insufficient collateral!"
        );
        /* TODO: check if transaction is failed, and data of it matches */
        users[senderAddress].collateralAmount -= amount;
        processedFailedTransactions[transactionHash] = true;
        (bool success,) = payable(recipientAddress).call{value: amount}("");
        require(success, "Transfer failed");
        emit RecipientRefunded(
            transactionHash,
            senderAddress,
            recipientAddress,
            amount
        );
    }
}
