import Web3 from "web3";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// Convert ES module paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Connect to Ganache
const web3 = new Web3("http://127.0.0.1:7545");

// Replace with your deployed contract address
const CONTRACT_ADDRESS = "0x9fF34A506B69d2C9af5B0e18b6cBCf5aB6400cEc";

// Replace with your contract ABI
const CONTRACT_ABI = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../build/contracts/AuthorityContract.json"), "utf-8")
).abi;

const contract = new web3.eth.Contract(CONTRACT_ABI, CONTRACT_ADDRESS);

export { web3, contract };
