const { ethers } = require("ethers");

// Connect to the local Anvil node (default is http://127.0.0.1:8545)
const provider = new ethers.JsonRpcProvider("http://138.199.207.112:8545");

// Set the sender's private key (make sure to replace with an actual private key from one of the pre-funded accounts)
const senderPrivateKey = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const senderWallet = new ethers.Wallet(senderPrivateKey, provider);

// Set the receiver's address (replace with an actual address from the list of accounts)
const receiverAddress = "RECEIVER_ACCOUN0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65T_ADDRESS";

// Set the amount to send (in ether)
const amountToSend = ethers.parseEther("3.5"); // 1 ETH

async function sendETH() {
    const tx = await senderWallet.sendTransaction({
        to: receiverAddress,
        value: amountToSend
    });

    console.log(`Transaction hash: ${tx.hash}`);

    // Wait for the transaction to be mined
    const receipt = await tx.wait();
    console.log(`Transaction mined in block: ${receipt.blockNumber}`);
}

sendETH().catch(console.error);
