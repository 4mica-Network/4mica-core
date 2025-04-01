use alloy::sol;

sol! {
    #[derive(Debug)]
    event UserRegistered(address _from, uint _collateral);

    #[derive(Debug)]
    event UserAddDeposit(address _from, uint _collateral);

    #[derive(Debug)]
    event RecipientRefunded(
        bytes32 indexed transactionHash,
        address indexed sender,
        address indexed recipient,
        uint256 amount
    );
}
