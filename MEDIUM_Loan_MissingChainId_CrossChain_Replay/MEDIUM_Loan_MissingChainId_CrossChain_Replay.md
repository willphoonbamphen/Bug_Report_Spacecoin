# MEDIUM — Loan.predictLoanTermHash() Missing block.chainid Allows Cross-Chain Signature Replay

**Program**: SpaceCoin -- CertIK SkyShield  
**Severity**: Medium  
**Category**: Smart Contract -- Improper Signature Verification / Missing Input Validation  
**CWE**: CWE-347 (Improper Verification of Cryptographic Signature)  
**Repository**: https://github.com/gluwa/CCNext-smart-contracts  
**File**: `contracts/Loan/Loan.sol` -- `predictLoanTermHash()`, `_verifyLoanSignature()`  
**Date**: 2026-06-08  

---

## Summary

`predictLoanTermHash()` hashes `address(this)` along with loan parameters but does **not** include `block.chainid`. The `_verifyLoanSignature()` function uses a raw `\x19Ethereum Signed Message:\n32` prefix (personal_sign) rather than EIP-712 with a proper domain separator.

As a result, signatures produced by a lender and borrower on Chain A (e.g., Creditcoin, chainId=2370) are cryptographically valid on Chain B (e.g., Ethereum Sepolia, chainId=11155111) **without any modification**, provided the Loan contract is deployed at the same address on both chains (which is the normal outcome of deterministic deployment tools like CREATE2 / Hardhat Deploy / Foundry's `--deterministic` flag).

A malicious borrower who obtains signatures intended for Chain A can submit them to `createLoanTerm()` on Chain B and receive loan funds they never agreed to borrow on that chain.

---

## Vulnerability Details

### The hash function

```solidity
// Loan.sol  predictLoanTermHash()
function predictLoanTermHash(...) public view returns (bytes32) {
    return keccak256(
        abi.encodePacked(
            address(this),      // contract address -- same on all chains via CREATE2
            lender,
            borrower,
            principal,
            interestRate,
            interestRatePercentageBase,
            maturityTerm,
            repaymentDeadline
            // !! block.chainid is NOT included !!
        )
    );
}
```

### The signature verifier

```solidity
// Loan.sol  _verifyLoanSignature()
function _verifyLoanSignature(bytes32 loanTermHash, ...) private pure {
    bytes32 messageHash = keccak256(
        abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            loanTermHash   // no chain binding
        )
    );
    address signer  = messageHash.recover(lenderSig);
    address signer2 = messageHash.recover(borrowerSig);
    require(signer  == lender,   "Loan: Invalid lender signature");
    require(signer2 == borrower, "Loan: Invalid borrower signature");
}
```

### Why this matters on multi-chain deployments

Gluwa operates on both **Creditcoin** (chainId 2291 / 2370) and **Ethereum** (or Sepolia). Deterministic deployment (CREATE2 or a deployer contract) is standard practice and results in identical contract addresses across chains. Once two Loan deployments share the same `address(this)`, the hash is bit-for-bit identical across chains, making every signature a cross-chain replay target.

### Attack path

1. Lender and borrower agree to a loan on Chain A (e.g., 1000 USDC on Creditcoin).  
2. Both sign `loanTermHash` as computed by `predictLoanTermHash()`.  
3. Malicious borrower submits the **same** signed parameters to `createLoanTerm()` on Chain B.  
4. `_verifyLoanSignature()` passes because the hash is identical.  
5. If the lender has approved the Loan contract on Chain B (e.g., as part of a general approval), the borrower can immediately call `fundLoan()` to receive the principal on Chain B.  
6. The lender loses Chain-B tokens they did not intend to lend.

---

## Proof of Concept

### Forge tests (2 passing)

```bash
cd ~/CCNext-smart-contracts
forge test --match-contract LoanCrossChainReplayPoc -vv
```

**Key output:**
```
=== CHAIN A (chainId=2370) ===
[sign] loanTermHash (chain A): 96572066237612435739941131988061464312044564818931260126603104229373477899093
[sign] lender and borrower signed the hash on chain A

=== CHAIN B (chainId=11155111) REPLAY ===
[replay] loanTermHash (chain B): 96572066237612435739941131988061464312044564818931260126603104229373477899093
[replay] Hashes are identical -- chainId not included in hash
[replay] createLoanTerm() SUCCEEDED with chain-A signatures on chain B!
[replay] Loan lender confirmed: 1390849295786071768276380950238675083608645509734
[replay] Loan principal confirmed: 1000

=== REPLAY CONFIRMED ===
Signatures for chainId=2370 accepted on chainId=11155111
Root cause: block.chainid absent from predictLoanTermHash()
Fix: add block.chainid to the hash or adopt EIP-712 domain separator

Suite result: ok. 2 passed; 0 failed
```

### Python end-to-end PoC (local Anvil)

```bash
cd ~/CCNext-smart-contracts
python3 ../bug-bounty-reports/SpaceCoin-CertIK/poc_loan_crosschain_replay.py
```

**Confirmed output (2026-06-08):**
```
[deploy] MockLoanToken: 0x5FbDB2315678afecb367f032d93F642f64180aa3
[deploy] Loan:          0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
=== CHAIN A (chainId=2370) ===
[sign] Signatures produced on chain A
=== CHAIN B (chainId=11155111) REPLAY ===
[check] hash A == hash B: true
[replay] createLoanTerm() accepted chain-A signatures on chain B
=== ATTACK CONFIRMED ===
Signatures signed on chainId=2370 accepted on chainId=11155111.
predictLoanTermHash() uses address(this) but NOT block.chainid.
Same contract address across chains (CREATE2) = full replay attack.
Fix: include block.chainid in the hash or use EIP-712 domain separator.

RESULT: VULNERABILITY CONFIRMED
```

---

## Impact

| Scenario | Effect |
|---|---|
| Deterministic deployment (same address on 2 chains) | Signatures from chain A fully valid on chain B |
| Lender approves Loan contract on both chains | Borrower can drain chain-B principal without lender consent |
| Multi-chain protocol expansion | Every historical loan signature becomes a replay target on new chains |

The attack requires either (a) the same contract address on both chains, or (b) the lender to trust the borrower not to replay. Condition (a) is trivially satisfied by deterministic deployment — the standard approach used across DeFi. Severity is **Medium** because the prerequisite (same address + lender approval on target chain) limits immediate exploitability, but it is a latent vulnerability that activates the moment the protocol expands.

---

## Recommendation

**Option A — Minimal fix (add chainId to the existing hash):**

```solidity
function predictLoanTermHash(...) public view returns (bytes32) {
    return keccak256(
        abi.encodePacked(
            block.chainid,          // <-- add this
            address(this),
            lender,
            borrower,
            principal,
            interestRate,
            interestRatePercentageBase,
            maturityTerm,
            repaymentDeadline
        )
    );
}
```

**Option B — Full EIP-712 (recommended for off-chain wallet compatibility):**

Adopt a proper domain separator following EIP-712:

```solidity
bytes32 private constant DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);
bytes32 private constant LOAN_TERM_TYPEHASH = keccak256(
    "LoanTerm(address lender,address borrower,uint256 principal,uint32 interestRate,"
    "uint32 interestRatePercentageBase,uint256 maturityTerm,uint256 repaymentDeadline)"
);

function _domainSeparator() internal view returns (bytes32) {
    return keccak256(abi.encode(
        DOMAIN_TYPEHASH,
        keccak256("Loan"),
        keccak256("1"),
        block.chainid,
        address(this)
    ));
}

function predictLoanTermHash(...) public view returns (bytes32) {
    return keccak256(abi.encodePacked(
        "\x19\x01",
        _domainSeparator(),
        keccak256(abi.encode(LOAN_TERM_TYPEHASH, lender, borrower, principal,
                             interestRate, interestRatePercentageBase, maturityTerm, repaymentDeadline))
    ));
}
```

EIP-712 also enables wallet UIs to display human-readable signing prompts, improving UX alongside security.

---

## Submission Metadata

- **Wallet**: `0x3fba877c0927B16f5A6568Ebc1db286324dA9c2b`
- **Email**: will.worachat@gmail.com
- **Tested on**: Local Anvil testnet (private) -- 2026-06-08
- **PoC files**:
  - `test/poc_Loan_CrossChain_Replay_test.sol` (2 passing forge tests)
  - `script/PocLoanCrossChainReplay.s.sol`
  - `poc_loan_crosschain_replay.py`
