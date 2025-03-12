require('dotenv').config();
require("@nomiclabs/hardhat-ethers");

const API_URL = 'http://127.0.0.1:8545'
const PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'

module.exports = {
  solidity: "0.8.28",
  defaultNetwork: "sepolia",
  networks: {
    hardhat: {},
    sepolia: {
      url: API_URL,
      accounts: [`0x${PRIVATE_KEY}`]
    }
  },
}
