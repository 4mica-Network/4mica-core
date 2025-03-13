const { web3, contract } = require("./config");

async function addDepositUser() {
  const sender = "0xd93a9496BF88188A57e1B25154b8D4E7e5EEf63C"

  console.log(`Adding deposit from: ${sender}`);

  try {
    const tx = await contract.methods.addDepositUser().send({
      from: sender,
      value: web3.utils.toWei("1.5", "ether"), // Add 0.5 ETH
      gas: 3000000,
    });

    console.log("Deposit added successfully:", tx.transactionHash);
  } catch (error) {
    console.error("Error adding deposit:", error);
  }
}

addDepositUser();
