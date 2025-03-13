const { web3, contract } = require("./config");

async function remunerateVictim() {
  const accounts = await web3.eth.getAccounts();
  const sender = accounts[1]; // User with collateral
  const recipient = accounts[2]; // Registered recipient
  const transactionHash = web3.utils.keccak256("fake_tx_hash_123"); // Simulated failed TX hash

  const amount = web3.utils.toWei("0.2", "ether"); // 0.2 ETH

  console.log(`Refunding ${recipient} from ${sender}`);

  try {
    const tx = await contract.methods
      .remunerateVictim(sender, recipient, transactionHash, amount)
      .send({ from: recipient, gas: 3000000 });

    console.log("Refund processed successfully:", tx.transactionHash);
  } catch (error) {
    console.error("Error processing refund:", error);
  }
}

remunerateVictim();
