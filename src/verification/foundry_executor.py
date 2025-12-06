"""foundry executor - execute transaction sequences on foundry forks"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import subprocess
import tempfile
import json
import re
import time

from utils.logging import ResearchLogger
from verification.mcts_node import Transaction, ContractState


@dataclass
class ExecutionResult:
    """
    Result of executing a transaction sequence

    Attributes:
        success: Did the attack succeed?
        profit: Profit in wei (negative = loss)
        gas_used: Total gas consumed
        execution_time: Seconds to execute
        final_state: Contract state after execution
        error_message: Error message if failed
        trace: Execution trace (for debugging)
    """
    success: bool
    profit: int
    gas_used: int
    execution_time: float
    final_state: ContractState
    error_message: Optional[str] = None
    trace: Optional[List[str]] = None


class FoundryExecutor:
    """
    Executes transaction sequences on Foundry forks

    Used by MCTS to simulate attack paths.
    """

    def __init__(
        self,
        logger: ResearchLogger,
        project_root: Path,
        contract_address: str,
        contract_abi: List[Dict[str, Any]],
        attacker_address: str = "0x1337000000000000000000000000000000001337",
        initial_balance: int = 100 * 10**18,  # 100 ETH
        fork_url: Optional[str] = None
    ):
        """
        Initialize Foundry executor

        Args:
            logger: Logger instance
            project_root: Foundry project root directory
            contract_address: Target contract address
            contract_abi: Contract ABI (for function signatures)
            attacker_address: Attacker's address
            initial_balance: Attacker's initial ETH balance (wei)
            fork_url: RPC URL for mainnet fork (None = local testnet)
        """
        self.logger = logger
        self.project_root = Path(project_root)
        self.contract_address = contract_address
        self.contract_abi = contract_abi
        self.attacker_address = attacker_address
        self.initial_balance = initial_balance
        self.fork_url = fork_url

        # Extract function signatures from ABI
        self.function_signatures = self._extract_function_signatures(contract_abi)

        # Execution statistics
        self.total_executions = 0
        self.successful_executions = 0
        self.failed_executions = 0
        self.total_gas_used = 0

        self.logger.info(
            f"[FoundryExecutor] Initialized for contract {contract_address} "
            f"with {len(self.function_signatures)} functions"
        )

    def _extract_function_signatures(self, abi: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """
        Extract function signatures from ABI

        Returns:
            Dictionary mapping function name → signature info
        """
        signatures = {}
        for item in abi:
            if item.get('type') == 'function':
                name = item.get('name')
                if name:
                    signatures[name] = {
                        'inputs': item.get('inputs', []),
                        'outputs': item.get('outputs', []),
                        'stateMutability': item.get('stateMutability', 'nonpayable')
                    }
        return signatures

    def execute_sequence(
        self,
        transactions: List[Transaction],
        initial_state: Optional[ContractState] = None,
        success_criteria: Optional[Dict[str, Any]] = None
    ) -> ExecutionResult:
        """
        Execute a sequence of transactions

        Args:
            transactions: Ordered list of transactions to execute
            initial_state: Initial contract state (None = default)
            success_criteria: Success conditions (profit, balance checks, etc.)

        Returns:
            ExecutionResult with success status and metrics
        """
        self.logger.info(
            f"[FoundryExecutor] Executing sequence of {len(transactions)} transactions"
        )

        start_time = time.time()
        self.total_executions += 1

        # Default success criteria: profit > 0
        if success_criteria is None:
            success_criteria = {'min_profit': 0}

        try:
            # Generate Foundry test code
            test_code = self._generate_test_code(transactions, initial_state, success_criteria)

            # Write test file
            test_file = self._write_test_file(test_code)

            # Execute test with forge
            success, stdout, stderr, gas_used = self._run_forge_test(test_file)

            # Parse results
            final_state = self._parse_final_state(stdout)
            profit = self._calculate_profit(stdout, initial_state or ContractState())

            execution_time = time.time() - start_time

            # Update statistics
            if success:
                self.successful_executions += 1
            else:
                self.failed_executions += 1
            self.total_gas_used += gas_used

            return ExecutionResult(
                success=success,
                profit=profit,
                gas_used=gas_used,
                execution_time=execution_time,
                final_state=final_state,
                error_message=stderr if not success else None,
                trace=self._parse_trace(stdout) if not success else None
            )

        except Exception as e:
            self.logger.error(f"[FoundryExecutor] Execution failed: {e}")
            self.failed_executions += 1

            return ExecutionResult(
                success=False,
                profit=-self.initial_balance,  # Total loss
                gas_used=0,
                execution_time=time.time() - start_time,
                final_state=initial_state or ContractState(),
                error_message=str(e),
                trace=None
            )

    def _generate_test_code(
        self,
        transactions: List[Transaction],
        initial_state: Optional[ContractState],
        success_criteria: Dict[str, Any]
    ) -> str:
        """
        Generate Foundry test code for transaction sequence

        Returns:
            Solidity test code
        """
        # Build transaction execution code
        tx_code = []
        for i, tx in enumerate(transactions):
            tx_code.append(f"        // Step {i+1}: {tx.description or tx.function_name}")
            tx_code.append(f"        {tx.to_foundry_call()};")

        # Build initial state setup
        setup_code = []
        if initial_state:
            for addr, balance in initial_state.balances.items():
                setup_code.append(f"        vm.deal({addr}, {balance});")

        # Build success checks
        success_checks = []
        if 'min_profit' in success_criteria:
            success_checks.append(
                f"        uint256 profit = address(attacker).balance - initialBalance;"
            )
            success_checks.append(
                f"        require(profit >= {success_criteria['min_profit']}, "
                f"\"Insufficient profit\");"
            )

        test_code = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {{ExploitTestBase}} from "poc/ExploitTestBase.sol";

contract MCTSExploitTest is ExploitTestBase {{
    address constant attacker = {self.attacker_address};
    address constant target = {self.contract_address};

    function setUp() public override {{
        super.setUp();
        // Set up initial balances
        giveETH(attacker, {self.initial_balance});

{chr(10).join(setup_code)}
    }}

    function testExploit() public {{
        startAs(attacker);
        uint256 initialBalance = address(attacker).balance;

        // Execute attack sequence
{chr(10).join(tx_code)}

        // Check success criteria
{chr(10).join(success_checks)}

        stopAs();

        // Log final state
        console.log("Final attacker balance:", address(attacker).balance);
        console.log("Profit:", address(attacker).balance - initialBalance);
    }}
}}
"""
        return test_code

    def _write_test_file(self, test_code: str) -> Path:
        """
        Write test code to temporary file

        Returns:
            Path to test file
        """
        # Create temp file in project test directory
        test_dir = self.project_root / "test" / "mcts"
        test_dir.mkdir(parents=True, exist_ok=True)

        test_file = test_dir / f"MCTSTest_{int(time.time() * 1000)}.t.sol"
        test_file.write_text(test_code)

        return test_file

    def _run_forge_test(self, test_file: Path) -> Tuple[bool, str, str, int]:
        """
        Run forge test command

        Returns:
            (success, stdout, stderr, gas_used)
        """
        cmd = [
            "forge", "test",
            "--match-path", str(test_file),
            "-vvv",  # Verbose for gas tracking
        ]

        if self.fork_url:
            cmd.extend(["--fork-url", self.fork_url])

        try:
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout
            )

            success = result.returncode == 0
            stdout = result.stdout
            stderr = result.stderr

            # Extract gas used
            gas_used = self._parse_gas_used(stdout)

            # Clean up test file
            test_file.unlink(missing_ok=True)

            return success, stdout, stderr, gas_used

        except subprocess.TimeoutExpired:
            self.logger.warning("[FoundryExecutor] Test timed out")
            test_file.unlink(missing_ok=True)
            return False, "", "Timeout", 0

        except Exception as e:
            self.logger.error(f"[FoundryExecutor] Failed to run forge: {e}")
            test_file.unlink(missing_ok=True)
            return False, "", str(e), 0

    def _parse_gas_used(self, stdout: str) -> int:
        """
        Parse gas used from forge output

        Returns:
            Total gas used
        """
        # Look for: "(gas: 123456)"
        match = re.search(r'\(gas:\s*(\d+)\)', stdout)
        if match:
            return int(match.group(1))
        return 0

    def _parse_final_state(self, stdout: str) -> ContractState:
        """
        Parse final contract state from logs

        Returns:
            ContractState
        """
        # This is simplified - in production would parse all state
        state = ContractState()

        # Look for: "Final attacker balance: 123456"
        match = re.search(r'Final attacker balance:\s*(\d+)', stdout)
        if match:
            state.balances[self.attacker_address] = int(match.group(1))

        return state

    def _calculate_profit(self, stdout: str, initial_state: ContractState) -> int:
        """
        Calculate profit from execution

        Returns:
            Profit in wei (negative = loss)
        """
        # Look for: "Profit: 123456"
        match = re.search(r'Profit:\s*(-?\d+)', stdout)
        if match:
            return int(match.group(1))

        # Fallback: calculate from balance change
        final_balance = 0
        match = re.search(r'Final attacker balance:\s*(\d+)', stdout)
        if match:
            final_balance = int(match.group(1))

        initial_balance = initial_state.balances.get(self.attacker_address, self.initial_balance)
        return final_balance - initial_balance

    def _parse_trace(self, stdout: str) -> List[str]:
        """
        Parse execution trace from output

        Returns:
            List of trace lines
        """
        trace = []
        in_trace = False

        for line in stdout.split('\n'):
            if 'Traces:' in line:
                in_trace = True
            elif in_trace:
                if line.strip():
                    trace.append(line.strip())

        return trace

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get execution statistics

        Returns:
            Statistics dictionary
        """
        success_rate = 0.0
        if self.total_executions > 0:
            success_rate = self.successful_executions / self.total_executions

        avg_gas = 0
        if self.total_executions > 0:
            avg_gas = self.total_gas_used / self.total_executions

        return {
            'total_executions': self.total_executions,
            'successful_executions': self.successful_executions,
            'failed_executions': self.failed_executions,
            'success_rate': success_rate,
            'total_gas_used': self.total_gas_used,
            'average_gas_per_execution': avg_gas
        }
