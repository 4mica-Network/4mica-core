async function main() {
    const HelloWorld = await ethers.getContractFactory("AuthorityContract");
    const hello_world = await AuthorityContract.deploy();
    console.log("Contract Deployed to Address:", hello_world.address);
  }
  main()
    .then(() => process.exit(0))
    .catch(error => {
      console.error(error);
      process.exit(1);
    });
  