const { web3, contract } = require("./config");

async function registerUser(sender, deposit) {
  console.log(`Registering user from: ${sender}`);

  try {
    const tx = await contract.methods.registerUser().send({
      from: sender,
      value: web3.utils.toWei(deposit, "ether"),
      gas: 3000000,
    });

    console.log("User registered successfully:", tx.transactionHash);
  } catch (error) {
    console.error("Error registering user:", error);
  }
}
const sender = process.argv[2];
const deposit = process.argv[3];

registerUser(sender, deposit);
