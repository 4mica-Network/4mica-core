async function main() {
    const AuthorityContract = await ethers.getContractFactory("AuthorityContract");
    const authoritycontract = await AuthorityContract.deploy();
    console.log("Contract Deployed to Address:", authoritycontract.address);
  }
  main()
    .then(() => process.exit(0))
    .catch(error => {
      console.error(error);
      process.exit(1);
    });
  