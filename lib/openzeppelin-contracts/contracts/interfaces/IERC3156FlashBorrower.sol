// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @dev Minimal IERC3156FlashBorrower interface from OpenZeppelin.
 */
interface IERC3156FlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}
