const { web3, contract } = require("./config");

async function registerUser() {
  const sender = "0xd93a9496BF88188A57e1B25154b8D4E7e5EEf63C" // Use first account from Ganache

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
