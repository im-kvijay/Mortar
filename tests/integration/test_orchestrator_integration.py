"""integration tests for main orchestrator - full audit pipeline"""

import unittest
from unittest.mock import MagicMock, patch, AsyncMock, call
import tempfile
import shutil
import json
from pathlib import Path
from datetime import datetime, UTC
import sys

# setup path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from src.agent.orchestrator import AttackOrchestrator, AttackSession
from src.agent.base_attacker import AttackHypothesis, AttackRoundResult
from src.models.findings import AuditResult, Finding, Severity, VulnerabilityType
from src.utils.llm_backend.base import LLMBackend, LLMResponse
from src.utils.logging import ResearchLogger
from src.utils.cost_manager import CostManager
from src.kb.knowledge_graph import KnowledgeGraph
from src.config import config

SAMPLE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract VulnerableToken {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // VULNERABILITY: No balance check
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = address(this).balance;
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        require(address(this).balance >= balanceBefore, "Flash loan not repaid");
    }
}
"""

class MockLLMBackend(LLMBackend):
    """Mock LLM backend for deterministic testing."""

    def __init__(self, responses=None):
        super().__init__(model="mock-model")
        self.responses = responses or []
        self.call_count = 0
        self.calls = []
        self._response_index = 0

    def generate(self, prompt, **kwargs):
        self.calls.append({
            "prompt": prompt,
            "kwargs": kwargs,
            "timestamp": datetime.now(UTC).isoformat()
        })

        # return next response from queue, or empty response
        if self._response_index < len(self.responses):
            response_text = self.responses[self._response_index]
            self._response_index += 1
        else:
            response_text = json.dumps({
                "decision": "stop",
                "reasoning": "No more responses configured",
                "confidence": 0.5
            })

        self.call_count += 1

        return LLMResponse(
            text=response_text,
            thinking=None,
            prompt_tokens=100,
            output_tokens=200,
            thinking_tokens=0,
            cost=0.001,
            model="mock-model",
            metadata={},
            tool_calls=[]
        )

    def is_available(self) -> bool:
        return True

    def reset(self):
        self.call_count = 0
        self.calls = []
        self._response_index = 0

class TestOrchestratorIntegration(unittest.TestCase):
    """Integration tests for the main orchestrator."""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())

    
        (self.temp_dir / "src").mkdir()
        self.contract_path = self.temp_dir / "src" / "VulnerableToken.sol"
        self.contract_path.write_text(SAMPLE_CONTRACT)

    
        self.mock_backend = MockLLMBackend()
        self.logger = ResearchLogger()
        self.cost_manager = CostManager()
        self.knowledge_graph = KnowledgeGraph(contract_name="VulnerableToken")

    
        self.orchestrator = AttackOrchestrator(
            backend=self.mock_backend,
            logger=self.logger,
            cost_manager=self.cost_manager,
            knowledge_graph=self.knowledge_graph,
            knowledge_base=None,
            research_gateway=None,
            min_confidence=0.8,
            enable_arena_learning=False,
            enable_a2a=False,
            enable_econ_sim=False,
            audit_id="test-audit-001"
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_pipeline_with_mock_backend(self):
    
        self.mock_backend.responses = [
            # flashloanattacker response
            """
HYPOTHESIS: flash_loan
Description: Flash loan attack via flashLoan function
Target: flashLoan
Preconditions:
- Flash loan available
Steps:
- Borrow flash loan
- Manipulate state
- Repay loan
Impact: Price manipulation
Confidence: 0.85
Evidence:
- Function accepts flash loans
---

DECISION: stop
REASONING: Found flash loan vulnerability
CONFIDENCE: 0.85
""",
            # oracleattacker response
            """
DECISION: stop
REASONING: No oracle dependencies found
CONFIDENCE: 0.6
""",
            # reentrancyattacker response
            """
DECISION: stop
REASONING: No reentrancy vulnerabilities found
CONFIDENCE: 0.6
""",
            # logicattacker response
            """
HYPOTHESIS: logic
Description: Missing balance check in transfer
Target: transfer
Preconditions:
- No balance checks
Steps:
- Call transfer with amount > balance
- Exploit underflow
Impact: Unauthorized token creation
Confidence: 0.90
Evidence:
- Direct arithmetic without SafeMath
---

DECISION: stop
REASONING: Found critical logic error
CONFIDENCE: 0.90
"""
        ]

    
        contract_info = {
            "name": "VulnerableToken",
            "file_path": str(self.contract_path),
            "state_vars": ["balances"],
            "external_functions": ["transfer", "flashLoan"]
        }

        # run attack analysis
        session = self.orchestrator.analyze_contract(
            contract_source=SAMPLE_CONTRACT,
            contract_info=contract_info
        )

    
        self.assertIsInstance(session, AttackSession)
        self.assertEqual(session.contract_name, "VulnerableToken")
        self.assertGreater(len(session.all_hypotheses), 0)
        self.assertGreater(len(session.high_confidence_attacks), 0)

    
        high_conf = [h for h in session.all_hypotheses if h.confidence >= 0.8]
        self.assertGreater(len(high_conf), 0)

    
        self.assertGreaterEqual(self.mock_backend.call_count, 4)  # 4 attackers

    def test_phase_transitions(self):
        # track phase execution via mock spawning
        phases_executed = []

        original_spawn = self.orchestrator.spawn_attackers

        def tracked_spawn():
            phases_executed.append("spawn_attackers")
            return original_spawn()

        self.orchestrator.spawn_attackers = tracked_spawn

        original_execute = self.orchestrator._execute_attack_rounds

        def tracked_execute(*args, **kwargs):
            phases_executed.append("execute_rounds")
            return original_execute(*args, **kwargs)

        self.orchestrator._execute_attack_rounds = tracked_execute

    
        self.mock_backend.responses = [
            json.dumps({"hypotheses": [], "decision": "stop", "reasoning": "test", "confidence": 0.5})
            for _ in range(4)  # One for each attacker
        ]

        contract_info = {"name": "VulnerableToken"}

        # run analysis
        session = self.orchestrator.analyze_contract(
            contract_source=SAMPLE_CONTRACT,
            contract_info=contract_info
        )

    
        self.assertIn("spawn_attackers", phases_executed)
        self.assertIn("execute_rounds", phases_executed)

    
        spawn_idx = phases_executed.index("spawn_attackers")
        execute_idx = phases_executed.index("execute_rounds")
        self.assertLess(spawn_idx, execute_idx)

    def test_cal_phase_error_handling(self):
    
        invalid_contract = "not valid solidity code @#$%"

        contract_info = {"name": "InvalidContract"}

    
        self.mock_backend.responses = [
            json.dumps({"hypotheses": [], "decision": "stop", "reasoning": "invalid", "confidence": 0.5})
            for _ in range(4)
        ]

    
        try:
            session = self.orchestrator.analyze_contract(
                contract_source=invalid_contract,
                contract_info=contract_info
            )
        
            self.assertIsInstance(session, AttackSession)
        except Exception as e:
            # if it does error, should be a clean error
            self.fail(f"Orchestrator should handle invalid contract gracefully: {e}")

    def test_research_phase_timeout(self):
        # simulate slow responses by tracking time
        import time

        original_generate = self.mock_backend.generate

        def slow_generate(*args, **kwargs):
            time.sleep(0.1)  # Simulate slow LLM
            return original_generate(*args, **kwargs)

        self.mock_backend.generate = slow_generate

    
        self.mock_backend.responses = [
            json.dumps({"hypotheses": [], "decision": "stop", "reasoning": "timeout", "confidence": 0.5})
            for _ in range(4)
        ]

        contract_info = {"name": "VulnerableToken"}

        # run with timeout (should complete before crashing)
        start_time = time.time()
        session = self.orchestrator.analyze_contract(
            contract_source=SAMPLE_CONTRACT,
            contract_info=contract_info
        )
        elapsed = time.time() - start_time

    
        self.assertIsInstance(session, AttackSession)

    
        self.assertLess(elapsed, 60)  # Max 60 seconds for this test

    def test_attack_phase_budget_limit(self):
    
        cost_manager_with_budget = CostManager(max_cost_per_contract=0.01)

        orchestrator_with_budget = AttackOrchestrator(
            backend=self.mock_backend,
            logger=self.logger,
            cost_manager=cost_manager_with_budget,
            knowledge_graph=self.knowledge_graph
        )

    
        self.mock_backend.responses = [
            json.dumps({"hypotheses": [], "decision": "continue", "reasoning": "keep going", "confidence": 0.5})
            for _ in range(100)  # Way more than budget allows
        ]

        contract_info = {"name": "VulnerableToken"}

        # run analysis - should stop due to budget
        try:
            session = orchestrator_with_budget.analyze_contract(
                contract_source=SAMPLE_CONTRACT,
                contract_info=contract_info
            )

        
            self.assertIsInstance(session, AttackSession)

        
            self.assertLess(self.mock_backend.call_count, 100)
        except Exception as e:
            # budget exception is acceptable
            if "budget" not in str(e).lower() and "cost" not in str(e).lower():
                raise

    def test_verification_phase_failure(self):
    
        self.mock_backend.responses = [
            """
HYPOTHESIS: logic
Description: Test vulnerability
Target: transfer
Preconditions:
- Test precondition
Steps:
- step1
- step2
Impact: test impact
Confidence: 0.95
Evidence:
- Test evidence
---

DECISION: stop
REASONING: found vuln
CONFIDENCE: 0.95
"""
        ] + [
            """
DECISION: stop
REASONING: test
CONFIDENCE: 0.5
"""
            for _ in range(3)
        ]

        contract_info = {"name": "VulnerableToken"}

        # run analysis
        session = self.orchestrator.analyze_contract(
            contract_source=SAMPLE_CONTRACT,
            contract_info=contract_info
        )

    
        self.assertGreater(len(session.all_hypotheses), 0)

        # high confidence attacks should be detected
        self.assertGreater(len(session.high_confidence_attacks), 0)

    def test_empty_contract_handling(self):
        clean_contract = """
        // SPDX-License-Identifier: MIT
        pragma solidity 0.8.25;

        contract CleanContract {
            uint256 public value;

            function setValue(uint256 _value) external {
                value = _value;
            }
        }
        """

    
        self.mock_backend.responses = [
            json.dumps({
                "hypotheses": [],
                "decision": "stop",
                "reasoning": "No vulnerabilities found",
                "confidence": 0.8
            })
            for _ in range(4)  # All attackers find nothing
        ]

        contract_info = {"name": "CleanContract"}

        # run analysis
        session = self.orchestrator.analyze_contract(
            contract_source=clean_contract,
            contract_info=contract_info
        )

    
        self.assertIsInstance(session, AttackSession)

    
        self.assertEqual(len(session.high_confidence_attacks), 0)

        # all hypotheses should be empty or low confidence
        high_conf = [h for h in session.all_hypotheses if h.confidence >= 0.8]
        self.assertEqual(len(high_conf), 0)

    def test_multiple_findings_aggregation(self):
    
        self.mock_backend.responses = [
            # flashloanattacker
            """
HYPOTHESIS: flash_loan
Description: Flash loan vulnerability 1
Target: flashLoan
Confidence: 0.85
---

DECISION: stop
REASONING: found flash loan
CONFIDENCE: 0.85
""",
            # oracleattacker
            """
HYPOTHESIS: oracle
Description: Oracle manipulation vulnerability
Target: getPrice
Confidence: 0.80
---

DECISION: stop
REASONING: found oracle issue
CONFIDENCE: 0.80
""",
            # reentrancyattacker
            """
HYPOTHESIS: reentrancy
Description: Reentrancy vulnerability
Target: withdraw
Confidence: 0.90
---

DECISION: stop
REASONING: found reentrancy
CONFIDENCE: 0.90
""",
            # logicattacker
            """
HYPOTHESIS: logic
Description: Logic error in transfer
Target: transfer
Confidence: 0.95
---

DECISION: stop
REASONING: found logic error
CONFIDENCE: 0.95
"""
        ]

        contract_info = {"name": "VulnerableToken"}

        # run analysis
        session = self.orchestrator.analyze_contract(
            contract_source=SAMPLE_CONTRACT,
            contract_info=contract_info
        )

    
        self.assertGreaterEqual(len(session.all_hypotheses), 4)

    
        self.assertGreaterEqual(len(session.high_confidence_attacks), 3)

    
        attack_types = set(h.attack_type for h in session.all_hypotheses)
        self.assertGreaterEqual(len(attack_types), 3)

    def test_correlation_id_propagation(self):
    
        audit_id = "test-correlation-123"
        orchestrator = AttackOrchestrator(
            backend=self.mock_backend,
            logger=self.logger,
            cost_manager=self.cost_manager,
            knowledge_graph=self.knowledge_graph,
            audit_id=audit_id
        )

    
        self.assertEqual(orchestrator.audit_id, audit_id)

    
        self.mock_backend.responses = [
            json.dumps({"hypotheses": [], "decision": "stop", "reasoning": "test", "confidence": 0.5})
            for _ in range(4)
        ]

        contract_info = {"name": "VulnerableToken"}

        # run analysis
        session = orchestrator.analyze_contract(
            contract_source=SAMPLE_CONTRACT,
            contract_info=contract_info
        )

    
        self.assertIsInstance(session, AttackSession)

    def test_attacker_spawning_and_cleanup(self):
    
        self.mock_backend.responses = [
            json.dumps({"hypotheses": [], "decision": "stop", "reasoning": "test", "confidence": 0.5})
            for _ in range(4)
        ]

        contract_info = {"name": "VulnerableToken"}

        # track attackers before analysis
        initial_attackers = len(self.orchestrator.attackers) if hasattr(self.orchestrator, 'attackers') else 0

        # run analysis
        session = self.orchestrator.analyze_contract(
            contract_source=SAMPLE_CONTRACT,
            contract_info=contract_info
        )

    
        self.assertGreater(len(self.orchestrator.attackers), initial_attackers)

    
        # since a2a is disabled in setup, a2a_wrapped_attackers should be empty
        self.assertEqual(len(self.orchestrator.a2a_wrapped_attackers), 0)

    def test_circuit_breaker_on_api_failures(self):
    
        original_generate = self.mock_backend.generate

        def failing_generate(*args, **kwargs):
            raise Exception("RESOURCE_EXHAUSTED: quota exceeded")

        self.mock_backend.generate = failing_generate

        contract_info = {"name": "VulnerableToken"}

    
        try:
            session = self.orchestrator.analyze_contract(
                contract_source=SAMPLE_CONTRACT,
                contract_info=contract_info
            )
            # if circuit breaker works, should return empty session
            self.assertEqual(len(session.all_hypotheses), 0)
        except Exception as e:
            # circuit breaker exception is acceptable
            if "circuit breaker" not in str(e).lower() and "quota" not in str(e).lower():
                # other exceptions should not occur
                raise

    def test_hypothesis_pruning(self):
    
        # generate text-formatted hypotheses for each attacker
        def generate_many_hypotheses(count):
            hypotheses_text = ""
            for i in range(count):
                hypotheses_text += f"""
HYPOTHESIS: logic
Description: Hypothesis {i}
Target: transfer
Confidence: {0.5 + (i * 0.001)}
---
"""
            hypotheses_text += """
DECISION: stop
REASONING: many hypotheses
CONFIDENCE: 0.8
"""
            return hypotheses_text

        self.mock_backend.responses = [
            generate_many_hypotheses(40)  # 40 per attacker
            for _ in range(4)  # 4 attackers = 160 total hypotheses
        ]

        contract_info = {"name": "VulnerableToken"}

        # run analysis
        session = self.orchestrator.analyze_contract(
            contract_source=SAMPLE_CONTRACT,
            contract_info=contract_info
        )

    
        max_hypotheses = config.MAX_HYPOTHESES
        if len(session.all_hypotheses) > max_hypotheses:
            # pruning should have occurred
            self.assertLessEqual(len(session.all_hypotheses), max_hypotheses)

if __name__ == "__main__":
    unittest.main()
