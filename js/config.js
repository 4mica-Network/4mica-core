import Web3 from "web3";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// Convert ES module paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Connect to server
const web3 = new Web3("https://hardhat.cookingwithbello.com");

// Replace with your deployed contract address
const CONTRACT_ADDRESS = "0x9A9f2CCfdE556A7E9Ff0848998Aa4a0CFD8863AE";

// Replace with your contract ABI
const CONTRACT_ABI = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../contracts/AuthorityContract.json"), "utf-8")
).abi;

const contract = new web3.eth.Contract(CONTRACT_ABI, CONTRACT_ADDRESS);

export { web3, contract };
