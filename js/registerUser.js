const { web3, contract } = require("./config");

async function registerUser() {
  const sender = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720" // Use first account from Ganache

  console.log(`Registering user from: ${sender}`);

  try {
    const tx = await contract.methods.registerUser().send({
      from: sender,
      value: web3.utils.toWei("1", "ether"), // 1 ETH deposit
      gas: 3000000,
    });

    console.log("User registered successfully:", tx.transactionHash);
  } catch (error) {
    console.error("Error registering user:", error);
  }
}

registerUser();
