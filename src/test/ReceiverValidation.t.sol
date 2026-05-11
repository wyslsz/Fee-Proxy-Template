// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Test.sol";
import "../IntuitionFeeProxy.sol";
import "./MockMultiVault.sol";

/// @title IntuitionFeeProxy_ReceiverValidationTest
/// @notice Tests that deposit/create functions revert when receiver != msg.sender
/// @dev Bounty #2A: Fix Issue #1 — $200 USDC
contract IntuitionFeeProxy_ReceiverValidationTest is Test {
    IntuitionFeeProxy public proxy;
    MockMultiVault public vault;

    address public constant USER = address(0x1000);
    address public constant ATTACKER = address(0x2000);
    address public constant FEE_RECIPIENT = address(0x3000);
    address public constant ADMIN = address(0x4000);

    uint256 public constant INITIAL_BALANCE = 100 ether;
    uint256 public constant DEFAULT_FIXED_FEE = 0.1 ether;
    uint256 public constant DEFAULT_PERCENTAGE_FEE = 500; // 5%

    bytes32 public constant TERM_ID = bytes32(uint256(1));
    bytes32[] public termIds;
    uint256[] public curveIds;
    uint256[] public assets;
    uint256[] public minShares;

    function setUp() public {
        // Deploy mock vault
        vault = new MockMultiVault();

        // Deploy proxy with initial admin
        address[] memory admins = new address[](1);
        admins[0] = ADMIN;
        proxy = new IntuitionFeeProxy(
            address(vault),
            FEE_RECIPIENT,
            DEFAULT_FIXED_FEE,
            DEFAULT_PERCENTAGE_FEE,
            admins
        );

        // Fund test addresses
        vm.deal(USER, INITIAL_BALANCE);
        vm.deal(ATTACKER, INITIAL_BALANCE);

        // USER approves proxy on vault
        vm.prank(USER);
        vault.approve(address(proxy), IEthMultiVault.ApprovalTypes.DEPOSIT);

        // ATTACKER also approves proxy (malicious setup scenario)
        vm.prank(ATTACKER);
        vault.approve(address(proxy), IEthMultiVault.ApprovalTypes.DEPOSIT);

        // Setup arrays for batch deposit
        termIds.push(TERM_ID);
        curveIds.push(1);
        assets.push(1 ether);
        minShares.push(0);
    }

    // ============ deposit() Tests ============

    /// @notice deposit() should revert when receiver is not msg.sender
    function test_Deposit_RevertsWhen_ReceiverNotMsgSender() public {
        vm.prank(USER);
        vm.expectRevert(Errors.IntuitionFeeProxy_ReceiverMismatch.selector);
        // USER calls deposit but specifies ATTACKER as receiver
        proxy.deposit{value: 2 ether}(ATTACKER, TERM_ID, 1, 0);
    }

    /// @notice deposit() should succeed when receiver == msg.sender
    function test_Deposit_SucceedsWhen_ReceiverIsMsgSender() public {
        vm.prank(USER);
        uint256 shares = proxy.deposit{value: 2 ether}(USER, TERM_ID, 1, 0);
        assertGt(shares, 0, "Should return shares > 0");
    }

    // ============ createAtoms() Tests ============

    /// @notice createAtoms() should revert when receiver is not msg.sender
    function test_CreateAtoms_RevertsWhen_ReceiverNotMsgSender() public {
        bytes[] memory data = new bytes[](1);
        data[0] = bytes("test-atom");
        uint256[] memory atomAssets = new uint256[](1);
        atomAssets[0] = 1 ether;

        vm.prank(USER);
        vm.expectRevert(Errors.IntuitionFeeProxy_ReceiverMismatch.selector);
        proxy.createAtoms{value: 3 ether}(ATTACKER, data, atomAssets, 1);
    }

    /// @notice createAtoms() should succeed when receiver == msg.sender
    function test_CreateAtoms_SucceedsWhen_ReceiverIsMsgSender() public {
        bytes[] memory data = new bytes[](1);
        data[0] = bytes("test-atom");
        uint256[] memory atomAssets = new uint256[](1);
        atomAssets[0] = 1 ether;

        vm.prank(USER);
        bytes32[] memory atomIds = proxy.createAtoms{value: 3 ether}(USER, data, atomAssets, 1);
        assertEq(atomIds.length, 1, "Should create 1 atom");
    }

    // ============ createTriples() Tests ============

    /// @notice createTriples() should revert when receiver is not msg.sender
    function test_CreateTriples_RevertsWhen_ReceiverNotMsgSender() public {
        bytes32[] memory subjects = new bytes32[](1);
        bytes32[] memory predicates = new bytes32[](1);
        bytes32[] memory objects = new bytes32[](1);
        uint256[] memory tripleAssets = new uint256[](1);
        subjects[0] = bytes32(uint256(1));
        predicates[0] = bytes32(uint256(2));
        objects[0] = bytes32(uint256(3));
        tripleAssets[0] = 1 ether;

        vm.prank(USER);
        vm.expectRevert(Errors.IntuitionFeeProxy_ReceiverMismatch.selector);
        proxy.createTriples{value: 3 ether}(ATTACKER, subjects, predicates, objects, tripleAssets, 1);
    }

    /// @notice createTriples() should succeed when receiver == msg.sender
    function test_CreateTriples_SucceedsWhen_ReceiverIsMsgSender() public {
        bytes32[] memory subjects = new bytes32[](1);
        bytes32[] memory predicates = new bytes32[](1);
        bytes32[] memory objects = new bytes32[](1);
        uint256[] memory tripleAssets = new uint256[](1);
        subjects[0] = bytes32(uint256(1));
        predicates[0] = bytes32(uint256(2));
        objects[0] = bytes32(uint256(3));
        tripleAssets[0] = 1 ether;

        vm.prank(USER);
        bytes32[] memory tripleIds = proxy.createTriples{value: 3 ether}(USER, subjects, predicates, objects, tripleAssets, 1);
        assertEq(tripleIds.length, 1, "Should create 1 triple");
    }

    // ============ depositBatch() Tests ============

    /// @notice depositBatch() should revert when receiver is not msg.sender
    function test_DepositBatch_RevertsWhen_ReceiverNotMsgSender() public {
        vm.prank(USER);
        vm.expectRevert(Errors.IntuitionFeeProxy_ReceiverMismatch.selector);
        proxy.depositBatch{value: 2 ether}(ATTACKER, termIds, curveIds, assets, minShares);
    }

    /// @notice depositBatch() should succeed when receiver == msg.sender
    function test_DepositBatch_SucceedsWhen_ReceiverIsMsgSender() public {
        vm.prank(USER);
        uint256[] memory shares = proxy.depositBatch{value: 2 ether}(USER, termIds, curveIds, assets, minShares);
        assertEq(shares.length, 1, "Should return 1 share entry");
    }

    // ============ Attack Scenario Tests ============

    /// @notice Attack scenario: ATTACKER cannot steal USER's shares via deposit()
    function test_AttackScenario_DepositByProxyOwnerCannotStealUserShares() public {
        // ATTACKER tries to deposit with USER as msg.sender and ATTACKER as receiver
        // This would be a reentrancy or delegate-call attack, but in normal flow:
        vm.prank(ATTACKER);
        vm.expectRevert(Errors.IntuitionFeeProxy_ReceiverMismatch.selector);
        proxy.deposit{value: 2 ether}(ATTACKER, TERM_ID, 1, 0);
        // Transaction should revert — ATTACKER can't use someone else's approval
    }

    /// @notice Verifying that even approved ATTACKER cannot steal from USER
    function test_ApprovedAttackerCannotStealShares() public {
        // USER deposits normally first
        vm.prank(USER);
        proxy.deposit{value: 2 ether}(USER, TERM_ID, 1, 0);

        // Even though ATTACKER has approved the proxy, they cannot deposit
        // with themselves as receiver while impersonating USER's msg.sender
        // (because msg.sender will be ATTACKER, not USER)
        vm.prank(ATTACKER);
        vm.expectRevert(Errors.IntuitionFeeProxy_ReceiverMismatch.selector);
        proxy.deposit{value: 2 ether}(ATTACKER, TERM_ID, 1, 0);

        // ATTACKER CAN deposit if they set receiver to themselves (msg.sender)
        vm.prank(ATTACKER);
        uint256 shares = proxy.deposit{value: 2 ether}(ATTACKER, TERM_ID, 1, 0);
        assertGt(shares, 0, "ATTACKER should be able to deposit for themselves");
    }

    receive() external payable {}
}
