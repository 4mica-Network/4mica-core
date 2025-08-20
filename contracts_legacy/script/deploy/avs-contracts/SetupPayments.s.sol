// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {DeploymentLib4Mica} from "../utils/DeploymentLib4Mica.sol";
import {CoreDeploymentLib} from "../utils/CoreDeploymentLib.sol";
import {SetupPaymentsLib} from "../utils/SetupPaymentsLib.sol";
import {IRewardsCoordinator} from "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {console2} from "forge-std/console2.sol";
import {UpgradeableProxyLib} from "./utils/UpgradeableProxyLib.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {stdJson} from "forge-std/StdJson.sol";

interface Ownable {
    function owner() external view returns (address);
}

contract SetupPayments is Script {
    using stdJson for string;

    struct PaymentInfo {
        address[] earners;
        bytes32[] earnerTokenRoots;
        address recipient;
        uint256 numPayments;
        uint256 amountPerPayment;
        uint32 duration;
        uint32 startTimestamp;
        uint32 endTimestamp;
        uint256 indexToProve;
    }

    address private deployer;
    CoreDeploymentLib.DeploymentData coreDeployment;
    DeploymentLib4Mica.DeploymentData deployment4Mica;
    string internal constant paymentfilepath = "test/mockData/scratch/payments.json";
    string internal constant infoFilePath = "test/mockData/scratch/payment_info.json";

    uint256 constant NUM_TOKEN_EARNINGS = 1;
    uint256 constant DURATION = 1 weeks;

    function setUp() public {
        deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        vm.label(deployer, "Deployer");

        coreDeployment = CoreDeploymentLib.readDeploymentJson("script/deployments/core/", block.chainid);
        deployment4Mica = DeploymentLib4Mica.readDeploymentJson("script/deployments/4mica/", block.chainid);
    }

    function run() external {
        vm.startBroadcast(deployer);
        string memory json = vm.readFile(infoFilePath);
        uint256 amount_per_payment = json.readUint(".amountPerPayment");
        uint32 duration = uint32(json.readUint(".duration"));
        uint32 index_to_prove = uint32(json.readUint(".indexToProve"));
        uint256 num_payments = json.readUint(".numPayments");
        address recipient = json.readAddress(".recipient");
        address[] memory earners = json.readAddressArray(".earners");
        bytes32[] memory earner_token_roots = json.readBytes32Array(".earnerTokenRoots");
        uint32 start_time = uint32(nextDivisibleTimestamp(block.timestamp));
        createAVSRewardsSubmissions(num_payments, amount_per_payment, duration, start_time);
        submitPaymentRoot(earners, uint32(block.timestamp - 1000), uint32(num_payments), uint32(amount_per_payment));

        IRewardsCoordinator.EarnerTreeMerkleLeaf memory earnerLeaf = IRewardsCoordinator.EarnerTreeMerkleLeaf({
            earner: earners[index_to_prove],
            earnerTokenRoot: earner_token_roots[index_to_prove]
        });
        processClaim(paymentfilepath, index_to_prove, recipient, earnerLeaf);

        vm.stopBroadcast();
    }

    function nextDivisibleTimestamp(uint256 blockTimestamp) public pure returns (uint256) {
        uint256 daySeconds = 86400;

        // Calculate the remainder to check if blockTimestamp is already divisible by daySeconds
        uint256 remainder = blockTimestamp % daySeconds;

        if (remainder == 0) {
            // If blockTimestamp is already divisible by daySeconds, move to the next day
            return blockTimestamp + daySeconds;
        } else {
            // Otherwise, round up to the next multiple of daySeconds
            return blockTimestamp + (daySeconds - remainder);
        }
    }

    function createAVSRewardsSubmissions(
        uint256 numPayments,
        uint256 amountPerPayment,
        uint32 duration,
        uint32 startTimestamp
    ) public {
        SetupPaymentsLib.createAVSRewardsSubmissions(
            IRewardsCoordinator(coreDeployment.rewardsCoordinator),
            deployment4Mica.strategy,
            numPayments,
            amountPerPayment,
            duration,
            startTimestamp
        );
    }

    function processClaim(
        string memory filePath,
        uint256 indexToProve,
        address recipient,
        IRewardsCoordinator.EarnerTreeMerkleLeaf memory earnerLeaf
    ) public {
        SetupPaymentsLib.processClaim(
            IRewardsCoordinator(coreDeployment.rewardsCoordinator),
            filePath,
            indexToProve,
            recipient,
            earnerLeaf,
            NUM_TOKEN_EARNINGS,
            deployment4Mica.strategy
        );
    }

    function submitPaymentRoot(
        address[] memory earners,
        uint32 endTimestamp,
        uint32 numPayments,
        uint32 amountPerPayment
    ) public {
        bytes32[] memory tokenLeaves = SetupPaymentsLib.createTokenLeaves(
            IRewardsCoordinator(coreDeployment.rewardsCoordinator),
            NUM_TOKEN_EARNINGS,
            amountPerPayment,
            deployment4Mica.strategy
        );
        IRewardsCoordinator.EarnerTreeMerkleLeaf[] memory earnerLeaves =
            SetupPaymentsLib.createEarnerLeaves(earners, tokenLeaves);

        SetupPaymentsLib.submitRoot(
            IRewardsCoordinator(coreDeployment.rewardsCoordinator),
            tokenLeaves,
            earnerLeaves,
            deployment4Mica.strategy,
            endTimestamp,
            numPayments,
            NUM_TOKEN_EARNINGS,
            paymentfilepath
        );
    }
}
