"""s for PoCExecutor"""

import unittest
from unittest.mock import MagicMock, patch, call
from pathlib import Path
from dataclasses import dataclass
import sys

# add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from agent.poc_executor import (  # noqa: E402
    PoCExecutor,
    ExecutionResult,
    _build_rich_error_context,
    MAX_FALLBACK_ATTEMPTS,
    MAX_TOTAL_ATTEMPTS,
)
from agent.poc_generator import GeneratedPoC  # noqa: E402
from agent.base_attacker import AttackHypothesis  # noqa: E402

class TestPoCExecutor(unittest.TestCase):
    """Test PoCExecutor functionality"""

    def setUp(self):
        self.mock_logger = MagicMock()
        self.mock_kb = MagicMock()
        self.project_root = Path("/tmp/test_project")

    def test_initialization_without_kb(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root,
            kb=None,
            mode="local",
            timeout=180
        )

        self.assertEqual(executor.mode, "local")
        self.assertEqual(executor.timeout, 180)
        self.assertIsNone(executor.learning_mgr)
        self.mock_logger.info.assert_called()

    def test_initialization_with_kb(self):
        with patch('kb.learning_manager.KBLearningManager') as mock_learning_mgr:
            executor = PoCExecutor(
                logger=self.mock_logger,
                project_root=self.project_root,
                kb=self.mock_kb,
                mode="local",
                timeout=180
            )

            self.assertIsNotNone(executor.learning_mgr)
            mock_learning_mgr.assert_called_once_with(self.mock_kb, self.mock_logger)

    def test_fingerprint_extraction(self):
        stderr1 = """
        Error: Compilation failed
        Compiler error: Type mismatch
        """
        stderr2 = """
        Error: Compilation failed
        Compiler error: Type mismatch
        """
        stderr3 = "Random output without errors"

        # same error should produce same fingerprint
        fp1 = PoCExecutor._fingerprint(stderr1)
        fp2 = PoCExecutor._fingerprint(stderr2)
        fp3 = PoCExecutor._fingerprint(stderr3)

        self.assertEqual(fp1, fp2)  # same error text
        self.assertNotEqual(fp1, fp3)
        self.assertIsInstance(fp1, str)
        self.assertEqual(len(fp1), 40)  # sha1 hash length

    def test_extract_contract_name(self):
        code1 = "contract TestContract is BaseContract {"
        code2 = "contract AnotherTest {"
        code3 = "// no contract here"

        name1 = PoCExecutor._extract_contract_name(code1)
        name2 = PoCExecutor._extract_contract_name(code2)
        name3 = PoCExecutor._extract_contract_name(code3)

        self.assertEqual(name1, "TestContract")
        self.assertEqual(name2, "AnotherTest")
        self.assertIsNone(name3)

    def test_dry_run_without_forge(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root,
            mode="dry-run",
            timeout=180
        )
        executor._forge_available = False

        poc = GeneratedPoC(
            hypothesis_id="test_1",
            contract_code="contract Test {}",
            test_code="contract Test {}",
            file_path=Path("/tmp/test.sol"),
            generation_method="template",
            cost=0.0
        )

        result = executor._dry_run(poc)

        self.assertTrue(result.success)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Dry-run", result.stdout)
        self.assertIsNone(result.error_message)

    def test_dry_run_with_forge_success(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root,
            mode="dry-run",
            timeout=180
        )
        executor._forge_available = True

        poc = GeneratedPoC(
            hypothesis_id="test_1",
            contract_code="contract Test {}",
            test_code="contract Test {}",
            file_path=Path("/tmp/test.sol"),
            generation_method="template",
            cost=0.0
        )

        with patch.object(executor, '_run_command') as mock_run:
            mock_run.return_value = {
                "exit_code": 0,
                "stdout": "Build successful",
                "stderr": "",
                "execution_time": 1.5
            }

            result = executor._dry_run(poc)

            self.assertTrue(result.success)
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, "Build successful")
            mock_run.assert_called_once()

    def test_dry_run_with_forge_failure(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root,
            mode="dry-run",
            timeout=180
        )
        executor._forge_available = True

        poc = GeneratedPoC(
            hypothesis_id="test_1",
            contract_code="contract Test {}",
            test_code="contract Test {}",
            file_path=Path("/tmp/test.sol"),
            generation_method="template",
            cost=0.0
        )

        with patch.object(executor, '_run_command') as mock_run:
            mock_run.return_value = {
                "exit_code": 1,
                "stdout": "",
                "stderr": "Compilation error: Type mismatch",
                "execution_time": 1.5
            }

            result = executor._dry_run(poc)

            self.assertFalse(result.success)
            self.assertEqual(result.exit_code, 1)
            self.assertIn("Type mismatch", result.error_message)

    def test_extract_gas_used(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root
        )

        stdout1 = "Test passed. gas: 123456"
        stdout2 = "No gas info here"

        gas1 = executor._extract_gas_used(stdout1)
        gas2 = executor._extract_gas_used(stdout2)

        self.assertEqual(gas1, 123456)
        self.assertIsNone(gas2)

    def test_extract_profit(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root
        )

        stdout1 = "Attack successful! profit: 100 ETH"
        stdout2 = "Gained: 50.5 USDC"
        stdout3 = "Balance: 1000"
        stdout4 = "No profit info"

        profit1 = executor._extract_profit(stdout1)
        profit2 = executor._extract_profit(stdout2)
        profit3 = executor._extract_profit(stdout3)
        profit4 = executor._extract_profit(stdout4)

        self.assertEqual(profit1, "100 ETH")
        self.assertEqual(profit2, "50.5 USDC")
        self.assertEqual(profit3, "1000")
        self.assertIsNone(profit4)

    def test_extract_impact_tags(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root
        )

        stdout = """
        Test running...
        IMPACT:FUNDS_DRAIN
        Some other output
        IMPACT:AUTHZ_BYPASS
        IMPACT:FUNDS_DRAIN
        End of test
        """

        tags = executor._extract_impact_tags(stdout)

        self.assertEqual(len(tags), 2)  # deduped
        self.assertIn("FUNDS_DRAIN", tags)
        self.assertIn("AUTHZ_BYPASS", tags)

    def test_extract_determinism(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root
        )

        stdout = """
        ENV:BLOCK_NUMBER 12345
        ENV:TIMESTAMP 1234567890
        ENV:CALLER 0x1234567890123456789012345678901234567890
        Some other output
        """

        meta = executor._extract_determinism(stdout)

        self.assertEqual(meta["BLOCK_NUMBER"], 12345)
        self.assertEqual(meta["TIMESTAMP"], 1234567890)
        self.assertEqual(meta["CALLER"], "0x1234567890123456789012345678901234567890")

    def test_extract_error(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root
        )

        stderr1 = "Error: Compilation failed with type mismatch"
        stderr2 = ""
        stdout1 = "Test running..."
        stdout2 = "FAILED: Assertion failed at line 10"

        error1 = executor._extract_error(stderr1, stdout1)
        error2 = executor._extract_error(stderr2, stdout2)
        error3 = executor._extract_error("", "")

        self.assertIn("Compilation failed", error1)
        self.assertIn("Assertion failed", error2)
        self.assertIsNone(error3)

    def test_run_command_success(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root
        )

        with patch('subprocess.run') as mock_run:
            mock_process = MagicMock()
            mock_process.returncode = 0
            mock_process.stdout = "Success output"
            mock_process.stderr = ""
            mock_run.return_value = mock_process

            result = executor._run_command(
                ["forge", "test"],
                cwd=self.project_root
            )

            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["stdout"], "Success output")
            self.assertIsInstance(result["execution_time"], float)

    def test_run_command_timeout(self):
        import subprocess

        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root,
            timeout=1
        )

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(
                cmd=["forge", "test"],
                timeout=1
            )

            result = executor._run_command(
                ["forge", "test"],
                cwd=self.project_root
            )

            self.assertEqual(result["exit_code"], -1)
            self.assertIn("Timeout", result["stderr"])
            self.mock_logger.error.assert_called()

    def test_run_command_exception(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root
        )

        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Command failed")

            result = executor._run_command(
                ["forge", "test"],
                cwd=self.project_root
            )

            self.assertEqual(result["exit_code"], -1)
            self.assertIn("Command failed", result["stderr"])
            self.mock_logger.error.assert_called()

    def test_execute_with_learning_manager(self):
        with patch('kb.learning_manager.KBLearningManager') as mock_learning_class:
            mock_learning_mgr = MagicMock()
            mock_learning_class.return_value = mock_learning_mgr

            executor = PoCExecutor(
                logger=self.mock_logger,
                project_root=self.project_root,
                kb=self.mock_kb,
                mode="dry-run"
            )

            poc = GeneratedPoC(
                hypothesis_id="test_1",
                contract_code="contract Test {}",
                test_code="contract Test {}",
                file_path=Path("/tmp/test.sol"),
                generation_method="template",
                cost=0.0
            )

            hypothesis = AttackHypothesis(
                hypothesis_id="test_1",
                attack_type="flash_loan",
                description="Test attack",
                target_function="test()",
                preconditions=[],
                steps=[],
                expected_impact="funds_drain",
                confidence=0.8,
                requires_research=[],
                evidence=[]
            )

            # patch _dry_run to return success
            with patch.object(executor, '_dry_run') as mock_dry_run:
                mock_dry_run.return_value = ExecutionResult(
                    poc_path=poc.file_path,
                    success=True,
                    exit_code=0,
                    stdout="Success",
                    stderr="",
                    gas_used=123456,
                    profit="100 ETH",
                    execution_time=1.5,
                    error_message=None
                )

                result = executor.execute(
                    poc=poc,
                    hypothesis=hypothesis,
                    contract_name="TestContract",
                    pattern_id="pattern_1"
                )
                mock_learning_mgr.learn_from_poc_result.assert_called_once()
                call_args = mock_learning_mgr.learn_from_poc_result.call_args[1]
                self.assertEqual(call_args["hypothesis"], hypothesis)
                self.assertEqual(call_args["contract_name"], "TestContract")
                self.assertEqual(call_args["pattern_id"], "pattern_1")

    def test_build_rich_error_context(self):
        current_error = "Error: Type mismatch at line 10"
        iteration_history = [
            {
                "type": "auto_fixer",
                "applied": ["fix_imports", "fix_visibility"],
                "error_summary": "Previous error summary",
                "fingerprint": "abc123"
            }
        ]
        contract_info = {
            "external_functions": ["transfer", "approve", "balanceOf"]
        }

        context = _build_rich_error_context(
            current_error,
            iteration_history,
            contract_info
        )

        self.assertIn("COMPILATION ERROR", context)
        self.assertIn("Type mismatch", context)
        self.assertIn("PREVIOUS ATTEMPTS", context)
        self.assertIn("auto_fixer", context)
        self.assertIn("FIX SUGGESTIONS", context)
        self.assertIn("REQUIREMENTS", context)
        self.assertIn("markImpact()", context)

    def test_forge_not_available_error(self):
        executor = PoCExecutor(
            logger=self.mock_logger,
            project_root=self.project_root,
            mode="local"
        )
        executor._forge_available = False

        poc = GeneratedPoC(
            hypothesis_id="test_1",
            contract_code="contract Test {}",
            test_code="contract Test {}",
            file_path=Path("/tmp/test.sol"),
            generation_method="template",
            cost=0.0
        )

        result = executor.execute(poc)

        self.assertFalse(result.success)
        self.assertEqual(result.exit_code, -1)
        self.assertIn("forge not found", result.error_message)

class TestBuildRichErrorContext(unittest.TestCase):
    """Test rich error context builder"""

    def test_basic_error_context(self):
        current_error = "Error: Function not found"
        context = _build_rich_error_context(current_error, [], None)

        self.assertIn("COMPILATION ERROR", context)
        self.assertIn("Function not found", context)
        self.assertIn("FIX SUGGESTIONS", context)

    def test_error_context_with_history(self):
        current_error = "Error: Still failing"
        history = [
            {"type": "attempt_1", "applied": ["fix_a"], "error_summary": "Error A"},
            {"type": "attempt_2", "applied": ["fix_b"], "error_summary": "Error B"},
        ]

        context = _build_rich_error_context(current_error, history, None)

        self.assertIn("PREVIOUS ATTEMPTS", context)
        self.assertIn("attempt_1", context)
        self.assertIn("attempt_2", context)

    def test_error_context_type_specific_suggestions(self):
        context1 = _build_rich_error_context(
            "Error: Function not found",
            [],
            None
        )
        self.assertIn("function name spelling", context1)
        context2 = _build_rich_error_context(
            "Error: Type incompatible",
            [],
            None
        )
        self.assertIn("param types", context2)
        context3 = _build_rich_error_context(
            "Error: memory location required",
            [],
            None
        )
        self.assertIn("memory", context3)

if __name__ == '__main__':
    unittest.main()
