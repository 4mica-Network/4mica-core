const { ethers } = require("hardhat");

async function main() {
  let accounts = [];
  
  for (let i = 0; i < 100; i++) {
    const wallet = ethers.Wallet.createRandom();
    accounts.push({
      address: wallet.address,
      privateKey: wallet.privateKey
    });
  }

  console.log(accounts);
}

main();
