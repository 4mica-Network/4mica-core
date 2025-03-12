const { web3, contract } = require("./config");
async function getRecipient() {
  const accounts = await web3.eth.getAccounts();
  const user = "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720";

  try {
    const recipients = await contract.methods.recipients(user).call();
    console.log(`Recipient ${user} is registered?: ${recipients.exists}, ${recipients.withdrawAmount}}`);
  } catch (error) {
    console.error("Error fetching recipient:", error);
  }
}

getRecipient();
