# MEDIUM — Staking.stakeWithPermit() Missing isLocked Check Allows Locked Accounts to Bypass Operator Restrictions

**Program**: SpaceCoin -- CertIK SkyShield  
**Severity**: Medium  
**Category**: Smart Contract -- Missing Access Control  
**CWE**: CWE-284 (Improper Access Control)  
**Contract**: `Staking.sol` at `0x01BD109532d651DD9a0BF92C2658E8cB94081c1d` (Creditcoin Testnet)  
**Date**: 2026-06-08  

---

## Summary

`stakeWithPermit()` is missing two input validation checks that `stake()` enforces:

1. **Missing `isLocked` check** — A locked account can stake tokens via the permit path, bypassing the operator's `lockOrUnlockAccount()` restriction. (Medium)
2. **Missing `amount == 0` check** — A zero-amount permit stake silently sets `firstStakeTimestamp`, corrupting the reward calculation for subsequent real stakes. (Low — included here)

---

## Vulnerability Details

### Comparison: stake() vs stakeWithPermit()

```solidity
// stake() -- correct, has both guards
function stake(uint256 amount) external onlyAllowedStakingStatus {
    if (amount == 0) revert InvalidStakingAmount();      // ← present
    address owner = msg.sender;
    if (stakeInfo[owner].isLocked) revert AccountIsLocked();  // ← present
    _stake(owner, amount);
}

// stakeWithPermit() -- missing both guards
function stakeWithPermit(
    address owner,
    uint256 amountToApprove,
    uint256 amountToStake,
    uint256 permitDeadline,
    uint8 v, bytes32 r, bytes32 s
) external onlyAllowedStakingStatus returns (bool) {
    IERC20Permit(address(token)).permit(owner, address(this), amountToApprove, permitDeadline, v, r, s);
    _stake(owner, amountToStake);   // no isLocked check, no amount==0 check
    return true;
}
```

### Attack path (isLocked bypass)

1. Operator calls `lockOrUnlockAccount(alice, true)` to restrict Alice's account (e.g., for KYC/AML compliance or dispute resolution).
2. Alice (or any relayer holding her permit signature) calls `stakeWithPermit(alice, amount, amount, deadline, v, r, s)`.
3. The `isLocked` guard is never reached; `_stake(alice, amount)` executes successfully.
4. Alice has staked tokens while locked — the operator's restriction is completely circumvented.

Note: `stakeWithPermit` takes `owner` as a parameter, not `msg.sender`. Any party holding a valid permit signature (e.g., a gasless relay service, front-runner, or the owner themselves) can call it. The lock check must therefore be on `owner`, not `msg.sender`.

### Secondary issue: zero-amount stake corrupts reward state

`stake(0)` reverts with `InvalidStakingAmount`. `stakeWithPermit(owner, 0, 0, ...)` does not. When `amount == 0` and `firstStakeTimestamp == 0`:

```solidity
function _stake(address sender, uint256 amount) internal {
    uint64 startRewardPeriod = uint64(block.timestamp) + stakingPeriod;
    token.transferFrom(sender, address(this), 0);  // no-op
    unchecked {
        if (stakeInfo[sender].firstStakeTimestamp == 0) {
            stakeInfo[sender].firstStakeTimestamp = startRewardPeriod;  // SET
        } else {
            stakeInfo[sender].totalDebt += _calculateDebt(sender, 0, startRewardPeriod);
        }
        stakeInfo[sender].stakedAmount += 0;
    }
}
```

The zero-amount call sets `firstStakeTimestamp` without staking any tokens. Every subsequent real stake then enters the `totalDebt` branch, computing debt for the period between the fake timestamp and the real stake time. This incurs an incorrect interest pre-deduction against the user.

---

## Proof of Concept

### Forge tests (2 passing)

```bash
cd ~/CCNext-smart-contracts
forge test --match-contract StakingIsLockedBypassPoc -vv
```

**Output:**
```
[PASS] test_stakeWithPermit_bypasses_isLocked()
  [setup]  Operator locked Alice's account
  [check]  stake() correctly reverts with AccountIsLocked
  [bypass] stakeWithPermit() SUCCEEDED for locked account!
  [bypass] Alice is still locked: true
  [bypass] Alice's staked principal: 1000 tokens
  === BYPASS CONFIRMED ===

[PASS] test_stakeWithPermit_allows_zero_amount()
  [check]  stake(0) correctly reverts with InvalidStakingAmount
  [bypass] stakeWithPermit(0) SUCCEEDED -- firstStakeTimestamp set
  === ZERO-AMOUNT BYPASS CONFIRMED ===

Suite result: ok. 2 passed; 0 failed
```

### Python end-to-end PoC (local Anvil)

```bash
cd ~/CCNext-smart-contracts
python3 ../bug-bounty-reports/SpaceCoin-CertIK/poc_staking_islocked_bypass.py
```

**Confirmed output (2026-06-08):**
```
[deploy] Staking:  0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
[setup]  Operator locked Alice's account
[verify] Alice isLocked: true
[expected] stake() would revert with AccountIsLocked for locked Alice
=== BYPASS: stakeWithPermit() ===
[bypass] stakeWithPermit() SUCCEEDED for locked account
[bypass] Alice still locked: true
[bypass] Alice staked principal: 1000 tokens
=== ATTACK CONFIRMED ===
```

---

## Impact

| Issue | Effect |
|---|---|
| Missing `isLocked` in `stakeWithPermit` | Locked accounts bypass operator restrictions; compliance/AML enforcement broken |
| Missing `amount == 0` in `stakeWithPermit` | Corrupts `firstStakeTimestamp`; subsequent stakes incur incorrect debt deductions |

The lock mechanism is used by the operator for regulatory compliance, account disputes, or security incidents. A bypassed lock undermines the operator's ability to restrict account activity as intended.

---

## Recommendation

Add the two missing guards to `stakeWithPermit()`:

```solidity
function stakeWithPermit(
    address owner,
    uint256 amountToApprove,
    uint256 amountToStake,
    uint256 permitDeadline,
    uint8 v, bytes32 r, bytes32 s
) external onlyAllowedStakingStatus returns (bool) {
    if (amountToStake == 0) revert InvalidStakingAmount();       // add
    if (stakeInfo[owner].isLocked) revert AccountIsLocked();     // add
    IERC20Permit(address(token)).permit(owner, address(this), amountToApprove, permitDeadline, v, r, s);
    _stake(owner, amountToStake);
    return true;
}
```

The checks must use `owner` (not `msg.sender`) since the caller may be a third-party relayer.

---

## Submission Metadata

- **Wallet**: `0x3fba877c0927B16f5A6568Ebc1db286324dA9c2b`
- **Email**: will.worachat@gmail.com
- **Tested on**: Local Anvil testnet (private) -- 2026-06-08
- **PoC files**:
  - `test/poc_Staking_isLocked_Bypass_test.sol` (2 passing forge tests)
  - `script/PocStakingIsLockedBypass.s.sol`
  - `poc_staking_islocked_bypass.py`
