const { ethers } = require("ethers");

const web3 = new ethers.WebSocketProvider("wss://hardhat.cookingwithbello.com");

const userA = "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f".toLowerCase();
const userB = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65".toLowerCase();
const numberOfBlocks = 5;

async function getTransactions(userA, userB, startBlock, endBlock) {
    const transactions_list = new Set();

    // Fetch all blocks concurrently
    const blockPromises = [];
    for (let i = startBlock; i <= endBlock; i++) {
        blockPromises.push(web3.getBlock(i, true));
    }

    const blocks = await Promise.all(blockPromises);

    const txPromises = [];
    for (const block of blocks) {
        if (block && block.transactions) {
            for (const txHash of block.transactions) {
                txPromises.push(web3.getTransaction(txHash));
            }
        }
    }

    const transactions = await Promise.allSettled(txPromises);

    for (const result of transactions) {
        if (result.status === "fulfilled") {
            const tx = result.value;
            if (tx && tx.from.toLowerCase() === userA && tx.to && tx.to.toLowerCase() === userB) {
                transactions_list.add(tx.hash);
            }
        } else {
            console.error("Error fetching transaction:", result.reason);
        }
    }

    return Array.from(transactions_list);
}

async function main() {
    const latestBlock = await web3.getBlockNumber();
    const startBlock = latestBlock - numberOfBlocks;

    console.log(`Fetching transactions from block ${startBlock} to ${latestBlock}...`);
    
    const transactions = await getTransactions(userA, userB, startBlock, latestBlock);

    console.log(`Transactions from ${userA} to ${userB}:`, transactions);
    web3._websocket.terminate();
}

main();