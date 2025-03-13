const { ethers } = require("ethers");
// Connect to a local Anvil instance
const provider = new ethers.WebSocketProvider("wss://hardhat.cookingwithbello.com");
const userA = "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f";
const userB = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65";
async function getPendingTransactions() {
    provider.on("pending", async (txHash) => {
        try {
            const tx = await provider.getTransaction(txHash);
            if (tx && tx.from === userA && tx.to === userB) {
                console.log("Pending Transaction:", tx);
            }
        } catch (error) {
            console.error("Error fetching transaction:", error);
        }
    });
}

getPendingTransactions();
