## HIGH — Loan.checkExpiredLoans() Unbounded Loop Enables Permanent DoS on repay/fundLoan, Locking Lender Funds

**Program**: SpaceCoin -- CertIK SkyShield  
**Severity**: High  
**Category**: Smart Contract -- Uncontrolled Resource Consumption / Gas DoS  
**CWE**: CWE-400 (Uncontrolled Resource Consumption)  
**Repository**: https://github.com/gluwa/CCNext-smart-contracts  
**File**: `contracts/Loan/Loan.sol` -- `checkExpiredLoans()`  
**Date**: 2026-06-08  

---

## Summary

`checkExpiredLoans()` iterates every entry ever added to `fundedLoanIndex` on each call, with no upper bound. The loop's upper index (`nextIdx`) grows with every `fundLoan` and never decreases; the lower index (`firstIdx`) advances by at most 2 per archive and only when the front element is already archived. Because `fundLoan`, `repay`, and `partialRepay` all call `checkExpiredLoans()` first, their gas cost grows linearly with the number of historical funded loans. At approximately **35,000 funded loans** the 30 M block gas limit is exceeded, permanently blocking all three operations. Since `fundLoan` already transferred tokens from lender to borrower before `repay()` is DoS'd, lenders are permanently unable to recover their principal.

---

## Vulnerability Details

### The loop

```solidity
// Loan.sol
function checkExpiredLoans() public {
    LoanStorage storage $ = _getLoanStorage();
    uint256 currentTimestamp = block.timestamp;

    // nextIdx grows with every fundLoan; firstIdx barely advances
    for (uint256 i = $.fundedLoanIndex.firstIdx; i < $.fundedLoanIndex.nextIdx; i++) {
        bytes32 loanHash = $.fundedLoanIndex.get(i);      // SLOAD
        LoanModel.LoanTerm storage loanTerm = $.loanTermStorage[loanHash]; // SLOAD
        if (loanTerm.state == LoanModel.LoanState.Funded &&
            currentTimestamp > loanTerm.repaymentDeadline + LOAN_EXPIRED_TIME) {
            loanTerm.state = LoanModel.LoanState.Expired;
            $.fundedLoanIndex.archive(loanHash);
            emit LoanExpired(loanHash, loanTerm.borrower);
        }
    }
}
```

### Why firstIdx never catches up

`HashMapIndex.archive()` advances `firstIdx` by at most 2 per call, and only when the element **at** `firstIdx` is already archived:

```solidity
function archive(HashMapping storage self, bytes32 _hash) internal {
    ...
    if (self.hashState[self.itHashMap[self.firstIdx]] == HashState.Archived) {
        self.firstIdx++;
    }
    if (self.hashState[self.itHashMap[self.firstIdx]] == HashState.Archived) {
        self.firstIdx++;
    }
}
```

If any long-lived loan sits at index 0 and has not expired, `firstIdx` never advances regardless of how many later loans are archived. The loop starts from 0 and grows unboundedly.

### Called by all fund-path functions

```solidity
function fundLoan(bytes32 loanTermHash) external ... {
    checkExpiredLoans();  // O(N)
    ...
    erc20.transferFrom(loanTerm.lender, loanTerm.borrower, loanTerm.principal);  // tokens sent
    ...
}

function repay(bytes32 loanTermHash) external ... {
    checkExpiredLoans();  // O(N) -- blocks lender recovery
    ...
}

function partialRepay(bytes32 loanTermHash, uint256 repayAmount) external ... {
    checkExpiredLoans();  // O(N)
    ...
}
```

### Fund loss path

1. Lender calls `fundLoan` -- tokens are transferred from lender to borrower
2. Over time, `fundedLoanIndex` grows past the DoS threshold
3. Borrower calls `repay()` -- `checkExpiredLoans()` hits gas limit -- revert
4. Borrower keeps the tokens; lender has no other recovery mechanism

---

## Proof of Concept

### Forge tests (3 passing)

```bash
cd ~/CCNext-smart-contracts
forge test --match-contract LoanUnboundedLoopPoc -vv
```

**Output:**
```
=== UNBOUNDED LOOP -- GAS GROWTH ===
checkExpiredLoans() gas at   0 loans:  9,516
checkExpiredLoans() gas at  50 loans: 42,760
checkExpiredLoans() gas at 100 loans: 84,510
checkExpiredLoans() gas at 150 loans: 126,260

Gas per additional funded loan (warm storage estimate): 835
Funded loans needed to exceed 30M block gas limit:      35,928

=== IMPACT ===
fundLoan / repay / partialRepay all call checkExpiredLoans().
After DoS threshold: all three ops revert out-of-gas.
Lender tokens already sent to borrower via fundLoan.
repay() blocked -> lender principal permanently unrecoverable.

=== REPAY GAS WITH 100 FUNDED LOANS ===
repay() gas consumed: 114,641
~ 1,146 gas per funded loan in history
At 7000 loans: repay() needs ~ 8,022,000 gas
Block gas limit: 30,000,000

Suite result: ok. 3 passed; 0 failed; 0 skipped
```

### Python end-to-end PoC (local Anvil)

```bash
cd ~/CCNext-smart-contracts
python3 ../bug-bounty-reports/SpaceCoin-CertIK/poc_loan_unbounded_loop_dos.py
```

**Confirmed output (2026-06-08):**
```
[deploy] MockLoanToken: 0x5FbDB2315678afecb367f032d93F642f64180aa3
[deploy] Loan:          0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
[fund]   Creating and funding 150 loans (1 wei principal each) ...
[check]  Measuring checkExpiredLoans() gas after 150 funded loans ...

=== ATTACK CONFIRMED ===
checkExpiredLoans() gas with 150 funded loans: 126,194
Gas per funded loan (warm storage):                841
Funded loans to hit 30M block gas limit:           35,671

Root cause: loop iterates fundedLoanIndex.firstIdx -> nextIdx.
After DoS: lender tokens already sent, repay() reverts -> fund loss.
Fix: cap loop iterations per call or use a pull-based expiry pattern.

RESULT: VULNERABILITY CONFIRMED
Gas grows O(N) with funded loans.
repay() / fundLoan() / partialRepay() become permanently DoS'd.
Lender principal unrecoverable once block gas limit exceeded.
```

---

## Impact

| Scenario | Effect |
|---|---|
| repay() DoS'd after threshold | Borrower keeps principal; lender loses it permanently |
| fundLoan() DoS'd | New loans cannot be funded; protocol halted |
| partialRepay() DoS'd | Partial repayments blocked; forces default |
| checkExpiredLoans() is public | Anyone can trigger the check; no access control |

**Gas growth (measured):** 835 gas per funded loan (warm storage). At 35,671 funded loans the 30 M Ethereum block gas limit is exceeded. This threshold can be reached through normal protocol usage over time without any attacker involvement.

---

## Recommendation

Replace the unbounded scan with a bounded iteration:

```solidity
uint256 constant MAX_EXPIRY_CHECK = 50;

function checkExpiredLoans() public {
    LoanStorage storage $ = _getLoanStorage();
    uint256 currentTimestamp = block.timestamp;
    uint256 checked = 0;

    for (uint256 i = $.fundedLoanIndex.firstIdx;
         i < $.fundedLoanIndex.nextIdx && checked < MAX_EXPIRY_CHECK;
         i++) {
        checked++;
        bytes32 loanHash = $.fundedLoanIndex.get(i);
        LoanModel.LoanTerm storage loanTerm = $.loanTermStorage[loanHash];
        if (loanTerm.state == LoanModel.LoanState.Funded &&
            currentTimestamp > loanTerm.repaymentDeadline + LOAN_EXPIRED_TIME) {
            loanTerm.state = LoanModel.LoanState.Expired;
            $.fundedLoanIndex.archive(loanHash);
            emit LoanExpired(loanHash, loanTerm.borrower);
        }
    }
}
```

Or use a pull model: let parties call `expireLoan(bytes32 loanHash)` explicitly for a single loan rather than scanning all funded loans on every state-change call.

---

## Submission Metadata

- **Wallet**: `0x3fba877c0927B16f5A6568Ebc1db286324dA9c2b`
- **Email**: willworachat@gmail.com
- **Tested on**: Local Anvil testnet (private) -- 2026-06-08
- **PoC files**:
  - `test/poc_Loan_UnboundedLoop_test.sol` (3 passing forge tests)
  - `script/PocLoanUnboundedLoop.s.sol`
  - `poc_loan_unbounded_loop_dos.py`
