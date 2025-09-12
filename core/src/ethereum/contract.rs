use alloy::sol;

sol! {
    #[derive(Debug)]
    event UserRegistered(address indexed user, uint256 initial_collateral);

    #[derive(Debug)]
    event CollateralDeposited(address indexed user, uint256 amount);

    #[derive(Debug)]
    event RecipientRemunerated(uint256 indexed tab_id, uint256 amount);

    #[derive(Debug)]
    event CollateralWithdrawn(address indexed user, uint256 amount);

    #[derive(Debug)]
    event WithdrawalRequested(address indexed user, uint256 when, uint256 amount);

    #[derive(Debug)]
    event WithdrawalCanceled(address indexed user);

    #[derive(Debug)]
    event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);

    #[derive(Debug)]
    event RemunerationGracePeriodUpdated(uint256 newGracePeriod);

    #[derive(Debug)]
    event TabExpirationTimeUpdated(uint256 newExpirationTime);

    #[derive(Debug)]
    event SynchronizationDelayUpdated(uint256 newSynchronizationDelay);
}
