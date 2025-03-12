const { web3, contract } = require("./config");

async function addDepositUser(sender, deposit) {
  console.log(`Adding deposit from: ${sender}`);
  try {
    const tx = await contract.methods.addDepositUser().send({
      from: sender,
      value: web3.utils.toWei(deposit, "ether"),
      gas: 3000000,
    });

    console.log("Deposit added successfully:", tx.transactionHash);
  } catch (error) {
    console.error("Error adding deposit:", error);
  }
}

const sender = process.argv[2];
const deposit = process.argv[3];

addDepositUser(sender, deposit);

