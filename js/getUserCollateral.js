const { web3, contract } = require("./config");
async function getUserCollateral() {
  const accounts = await web3.eth.getAccounts();
  const user = accounts[1];

  try {
    const collateral = await contract.methods.users(user).call();
    console.log(`User ${user} has collateral: ${web3.utils.fromWei(collateral.collateralAmount, "ether")} ETH`);
  } catch (error) {
    console.error("Error fetching user collateral:", error);
  }
}

getUserCollateral();
