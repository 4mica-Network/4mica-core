const { web3, contract } = require("./config");

async function registerRecipient() {
  const accounts = await web3.eth.getAccounts();
  const owner = accounts[0]; // Owner (deployer)
  const recipientAddresses = ["0xa0Ee7A142d267C1f36714E4a8F75612F20a79720"]; // Registering two recipients
  console.log(`Registering recipients: ${recipientAddresses}`);
  try {
    const tx = await contract.methods
      .registerRecipient(recipientAddresses)
      .send({ from: owner, gas: 3000000 });

    console.log("Recipients registered successfully:", tx.transactionHash);
  } catch (error) {
    console.error("Error registering recipients:", error);
  }
}
registerRecipient();
