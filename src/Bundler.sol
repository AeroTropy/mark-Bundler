// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

import {IBundler, Call} from "./interfaces/IBundler.sol";

/// @notice Enables batching multiple calls in a single one.
/// @notice Transiently stores the initiator of the multicall.
/// @notice Can be reentered by the last unreturned callee with known data.
/// @dev Anybody can do arbitrary calls with this contract, so it should not be approved/authorized anywhere.
contract Bundler is IBundler {
    /// @notice Slot for transient storage of the initiator address
    bytes32 internal constant INITIATOR_SLOT = 0xc090fc4683624cfc3884e9d8de5eca132f2d0ec062aff75d43c0465d5ceeab23;
    
    /// @notice Slot for transient storage of the reenter hash
    bytes32 internal constant REENTER_HASH_SLOT = 0x9e5f2754593e42f9defa0478e825b7d1941e3287bea3827af5ab037c9f5a8fef;
    
    error AlreadyInitiated();
    error MissingExpectedReenter();
    error IncorrectReenterHash();
    error EmptyBundle();
    
    /* EXTERNAL */
    
    /// @notice Executes a sequence of calls.
    /// @dev Locks the initiator so that the sender can be identified by other contracts.
    /// @param bundle The ordered array of calldata to execute.
    function multicall(Call[] calldata bundle) external payable {
        // Check if initiator slot is empty
        address currentInitiator;
        assembly {
            currentInitiator := tload(INITIATOR_SLOT)
        }
        
        if (currentInitiator != address(0)) revert AlreadyInitiated();
        
        // Store the initiator (caller) in transient storage
        assembly {
            tstore(INITIATOR_SLOT, caller())
        }
        
        // Execute the calls
        _multicall(bundle);
        
        // Clear initiator slot after calls are completed
        assembly {
            tstore(INITIATOR_SLOT, 0)
        }
    }
    
    /// @notice Executes a sequence of calls.
    /// @dev Useful during callbacks.
    /// @dev Can only be called by the last unreturned callee with known data.
    /// @param bundle The ordered array of calldata to execute.
    function reenter(Call[] calldata bundle) external {
        // Get current reenterHash from transient storage
        bytes32 currentReenterHash;
        assembly {
            currentReenterHash := tload(REENTER_HASH_SLOT)
        }
        
        // Verify the caller and calldata match the expected hash
        bytes32 computedHash = keccak256(abi.encodePacked(msg.sender, keccak256(msg.data[4:])));
        if (currentReenterHash != computedHash) revert IncorrectReenterHash();
        
        // Execute the bundle
        _multicall(bundle);
        // After _multicall the value of reenterHash is bytes32(0).
    }
    
    /// @notice Returns the current initiator of the multicall
    /// @return The address that initiated the current multicall
    function initiator() external view returns (address) {
        address currentInitiator;
        assembly {
            currentInitiator := tload(INITIATOR_SLOT)
        }
        return currentInitiator;
    }
    
    /// @notice Returns the current reenter hash
    /// @return The current expected hash for reentry
    function getReenterHash() external view returns (bytes32) {
        bytes32 currentReenterHash;
        assembly {
            currentReenterHash := tload(REENTER_HASH_SLOT)
        }
        return currentReenterHash;
    }
    
    /* INTERNAL */
    
    /// @notice Executes a sequence of calls.
    function _multicall(Call[] calldata bundle) internal {
        if (bundle.length == 0) revert EmptyBundle();
        
        for (uint256 i = 0; i < bundle.length; ++i) {
            address to = bundle[i].to;
            bytes32 callbackHash = bundle[i].callbackHash;
            
            // Set reenterHash for the next potential reentry using transient storage
            if (callbackHash == bytes32(0)) {
                assembly {
                    tstore(REENTER_HASH_SLOT, 0)
                }
            } else {
                bytes32 newReenterHash = keccak256(abi.encodePacked(to, callbackHash));
                assembly {
                    tstore(REENTER_HASH_SLOT, newReenterHash)
                }
            }
            
            // Execute the call
            (bool success, bytes memory returnData) = to.call{value: bundle[i].value}(bundle[i].data);
            
            // Revert if the call failed and skipRevert is false
            if (!bundle[i].skipRevert && !success) {
                lowLevelRevert(returnData);
            }
            
            // Check if reenterHash was consumed as expected
            if (callbackHash != bytes32(0)) {
                bytes32 currentReenterHash;
                assembly {
                    currentReenterHash := tload(REENTER_HASH_SLOT)
                }
                
                if (currentReenterHash != bytes32(0)) {
                    revert MissingExpectedReenter();
                }
            }
        }
        
        // Ensure reenterHash is cleared after all calls
        assembly {
            tstore(REENTER_HASH_SLOT, 0)
        }
    }
    
    /// @notice Propagates a revert reason from a low-level call
    function lowLevelRevert(bytes memory returnData) internal pure {
        if (returnData.length > 0) {
            assembly ("memory-safe") {
                revert(add(32, returnData), mload(returnData))
            }
        } else {
            revert("Bundler: call reverted without reason");
        }
    }
}