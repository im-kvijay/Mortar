"""s for BaseAttacker"""

import unittest
from unittest.mock import MagicMock, patch
from collections import OrderedDict
from pathlib import Path
import sys

# add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from agent.base_attacker import (  # noqa: E402
    BaseAttacker,
    LRUCache,
    AttackHypothesis,
    JITResearchRequest,
    AttackRoundResult,
)
from utils.llm_backend import LLMResponse  # noqa: E402

class TestLRUCache(unittest.TestCase):
    """Test LRU cache implementation"""

    def test_lru_cache_initialization(self):
        cache = LRUCache(maxsize=100)
        self.assertEqual(cache.maxsize, 100)
        self.assertEqual(len(cache._cache), 0)

    def test_lru_cache_get_miss(self):
        cache = LRUCache(maxsize=10)
        result = cache.get("nonexistent")
        self.assertIsNone(result)

    def test_lru_cache_put_and_get(self):
        cache = LRUCache(maxsize=10)

        cache.put("key1", "value1")
        cache.put("key2", "value2")

        self.assertEqual(cache.get("key1"), "value1")
        self.assertEqual(cache.get("key2"), "value2")

    def test_lru_cache_update_existing(self):
        cache = LRUCache(maxsize=10)

        cache.put("key1", "value1")
        cache.put("key1", "value2")  # update

        self.assertEqual(cache.get("key1"), "value2")

    def test_lru_cache_eviction(self):
        cache = LRUCache(maxsize=3)

        cache.put("key1", "value1")
        cache.put("key2", "value2")
        cache.put("key3", "value3")

        # this should evict key1 (oldest)
        cache.put("key4", "value4")

        self.assertIsNone(cache.get("key1"))  # evicted
        self.assertEqual(cache.get("key2"), "value2")
        self.assertEqual(cache.get("key3"), "value3")
        self.assertEqual(cache.get("key4"), "value4")

    def test_lru_cache_access_order(self):
        cache = LRUCache(maxsize=3)

        cache.put("key1", "value1")
        cache.put("key2", "value2")
        cache.put("key3", "value3")

        # access key1 to make it most recently used
        cache.get("key1")

        # add key4 - should evict key2 (oldest), not key1
        cache.put("key4", "value4")

        self.assertEqual(cache.get("key1"), "value1")  # still present
        self.assertIsNone(cache.get("key2"))  # evicted
        self.assertEqual(cache.get("key3"), "value3")
        self.assertEqual(cache.get("key4"), "value4")

    def test_lru_cache_clear(self):
        cache = LRUCache(maxsize=10)

        cache.put("key1", "value1")
        cache.put("key2", "value2")

        cache.clear()

        self.assertIsNone(cache.get("key1"))
        self.assertIsNone(cache.get("key2"))
        self.assertEqual(len(cache._cache), 0)

    def test_lru_cache_thread_safety(self):
        cache = LRUCache(maxsize=10)
        self.assertIsNotNone(cache._lock)

        # basic operations should work (full thread safety test would need threading)
        cache.put("key1", "value1")
        self.assertEqual(cache.get("key1"), "value1")

class MockAttacker(BaseAttacker):
    """Mock attacker for testing abstract base class"""

    def get_system_prompt(self) -> str:
        return "Test system prompt"

    def get_attack_prompt(self, contract_source, contract_info, round_num, kb_knowledge) -> str:
        return f"Test attack prompt for round {round_num}"

    def extract_hypotheses(self, response, round_num):
        return self._default_extract_hypotheses(response, round_num)

    def should_continue(self, round_num, response, hypotheses):
        return self._default_should_continue(round_num, response, hypotheses, max_rounds=3)

class TestBaseAttacker(unittest.TestCase):
    """Test BaseAttacker functionality"""

    def setUp(self):
        self.mock_backend = MagicMock()
        self.mock_logger = MagicMock()
        self.mock_cost_manager = MagicMock()
        self.mock_knowledge_graph = MagicMock()

    def test_initialization_without_research_gateway(self):
        attacker = MockAttacker(
            name="TestAttacker",
            description="Test description",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph,
            research_gateway=None
        )

        self.assertEqual(attacker.name, "TestAttacker")
        self.assertIsNone(attacker.research_gateway)
        self.assertEqual(attacker.current_round, 0)
        self.assertEqual(len(attacker.all_hypotheses), 0)
        self.assertIsInstance(attacker.jit_cache, LRUCache)

    def test_initialization_with_research_gateway(self):
        mock_gateway = MagicMock()

        attacker = MockAttacker(
            name="TestAttacker",
            description="Test description",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph,
            research_gateway=mock_gateway
        )

        self.assertEqual(attacker.research_gateway, mock_gateway)

    def test_default_extract_hypotheses(self):
        attacker = MockAttacker(
            name="TestAttacker",
            description="Test",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph
        )

        response = """
        Some preamble text...

        HYPOTHESIS: flash_loan
        Description: Flash loan attack on pool
        Target: flashLoan()
        Preconditions:
        - Pool has liquidity
        - No fee check
        Steps:
        - Borrow max tokens
        - Manipulate price
        - Repay loan
        Impact: Drain pool funds
        Confidence: 0.9
        Evidence:
        - No fee validation
        Research Needed:
        - Check reentrancy guards
        ---

        HYPOTHESIS: reentrancy
        Description: Reentrancy in withdraw
        Target: withdraw()
        Preconditions:
        - External call before state update
        Steps:
        - Call withdraw
        - Reenter on callback
        Impact: Double withdrawal
        Confidence: 0.85
        ---
        """

        hypotheses = attacker._default_extract_hypotheses(response, round_num=1)

        self.assertEqual(len(hypotheses), 2)
        h1 = hypotheses[0]
        self.assertEqual(h1.attack_type, "flash_loan")
        self.assertIn("Flash loan attack", h1.description)
        self.assertEqual(h1.target_function, "flashLoan()")
        self.assertEqual(len(h1.preconditions), 2)
        self.assertEqual(len(h1.steps), 3)
        self.assertIn("Drain pool", h1.expected_impact)
        self.assertEqual(h1.confidence, 0.9)
        self.assertEqual(len(h1.evidence), 1)
        self.assertEqual(len(h1.requires_research), 1)
        h2 = hypotheses[1]
        self.assertEqual(h2.attack_type, "reentrancy")
        self.assertEqual(h2.confidence, 0.85)

    def test_default_extract_hypotheses_invalid(self):
        attacker = MockAttacker(
            name="TestAttacker",
            description="Test",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph
        )

        # invalid: missing description
        response = """
        HYPOTHESIS: flash_loan
        Target: flashLoan()
        ---
        """

        hypotheses = attacker._default_extract_hypotheses(response, round_num=1)
        self.assertEqual(len(hypotheses), 0)

    def test_default_should_continue_explicit_stop(self):
        attacker = MockAttacker(
            name="TestAttacker",
            description="Test",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph
        )

        response = """
        Analysis complete.
        DECISION: stop
        REASONING: Found 2 high-confidence attacks, no need to continue
        CONFIDENCE: 0.95
        """

        should_continue, reasoning, confidence = attacker._default_should_continue(
            round_num=1,
            response=response,
            hypotheses=[],
            max_rounds=5
        )

        self.assertFalse(should_continue)
        self.assertIn("Found 2 high-confidence", reasoning)
        self.assertEqual(confidence, 0.95)

    def test_default_should_continue_no_hypotheses(self):
        attacker = MockAttacker(
            name="TestAttacker",
            description="Test",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph
        )

        # round 1 - should continue
        should_continue_r1, _, _ = attacker._default_should_continue(
            round_num=1,
            response="",
            hypotheses=[],
            max_rounds=5
        )
        self.assertTrue(should_continue_r1)

        # round 2 - should stop
        should_continue_r2, reasoning, _ = attacker._default_should_continue(
            round_num=2,
            response="",
            hypotheses=[],
            max_rounds=5
        )
        self.assertFalse(should_continue_r2)
        self.assertIn("No", reasoning)

    def test_default_should_continue_high_confidence(self):
        attacker = MockAttacker(
            name="TestAttacker",
            description="Test",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph
        )

        high_conf_hypotheses = [
            AttackHypothesis(
                hypothesis_id="h1",
                attack_type="flash_loan",
                description="Attack 1",
                target_function="test()",
                preconditions=[],
                steps=[],
                expected_impact="funds_drain",
                confidence=0.95,
                requires_research=[],
                evidence=[]
            ),
            AttackHypothesis(
                hypothesis_id="h2",
                attack_type="reentrancy",
                description="Attack 2",
                target_function="test2()",
                preconditions=[],
                steps=[],
                expected_impact="double_spend",
                confidence=0.92,
                requires_research=[],
                evidence=[]
            )
        ]

        should_continue, reasoning, confidence = attacker._default_should_continue(
            round_num=1,
            response="",
            hypotheses=high_conf_hypotheses,
            max_rounds=5
        )

        self.assertFalse(should_continue)
        self.assertIn("Found 2 high-confidence", reasoning)

    def test_default_should_continue_max_rounds(self):
        attacker = MockAttacker(
            name="TestAttacker",
            description="Test",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph
        )

        should_continue, reasoning, _ = attacker._default_should_continue(
            round_num=5,
            response="",
            hypotheses=[],
            max_rounds=5
        )

        self.assertFalse(should_continue)
        # reasoning could be "maximum rounds" or "no hypotheses found" (both stop at round 5)
        self.assertTrue(
            "maximum rounds" in reasoning.lower() or "no" in reasoning.lower()
        )

    def test_default_should_continue_normal(self):
        attacker = MockAttacker(
            name="TestAttacker",
            description="Test",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph
        )

        # one low-confidence hypothesis
        hypotheses = [
            AttackHypothesis(
                hypothesis_id="h1",
                attack_type="logic",
                description="Potential issue",
                target_function="test()",
                preconditions=[],
                steps=[],
                expected_impact="minor",
                confidence=0.6,
                requires_research=[],
                evidence=[]
            )
        ]

        should_continue, reasoning, _ = attacker._default_should_continue(
            round_num=2,
            response="",
            hypotheses=hypotheses,
            max_rounds=5
        )

        self.assertTrue(should_continue)
        self.assertIn("Continuing", reasoning)

    def test_query_kb_loads_vulnerabilities(self):
        attacker = MockAttacker(
            name="TestAttacker",
            description="Test",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph
        )
        self.mock_knowledge_graph.get_nodes_by_type.return_value = []
        mock_vuln_node = MagicMock()
        mock_vuln_node.name = "Flash loan vulnerability"
        mock_vuln_node.confidence = 0.85
        mock_vuln_node.node_type.value = "vulnerability"
        mock_vuln_node.data = {
            "description": "Flash loan attack vector",
            "evidence": ["No fee check", "Unrestricted borrowing"]
        }

        self.mock_knowledge_graph.get_vulnerability_nodes.return_value = [mock_vuln_node]

        contract_info = {"name": "TestContract"}
        kb_knowledge = attacker._query_kb(contract_info)

        self.assertIn("vulnerabilities", kb_knowledge)
        self.assertEqual(len(kb_knowledge["vulnerabilities"]), 1)

        vuln = kb_knowledge["vulnerabilities"][0]
        self.assertEqual(vuln["name"], "Flash loan vulnerability")
        self.assertEqual(vuln["confidence"], 0.85)
        self.assertIn("Flash loan attack", vuln["data"]["description"])

    def test_infer_focus_area(self):
        attacker = MockAttacker(
            name="TestAttacker",
            description="Test",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph
        )
        self.assertEqual(
            attacker._infer_focus_area("What invariant holds for totalSupply?"),
            "invariant"
        )

        self.assertEqual(
            attacker._infer_focus_area("How does balance state change on transfer?"),
            "state_flow"
        )

        self.assertEqual(
            attacker._infer_focus_area("Is onlyOwner modifier correctly applied?"),
            "access_control"
        )

        self.assertEqual(
            attacker._infer_focus_area("What's the profit margin for this trade?"),
            "economic"
        )

        self.assertEqual(
            attacker._infer_focus_area("Does the oracle call use Chainlink?"),
            "dependency"
        )

        self.assertEqual(
            attacker._infer_focus_area("What happens when x > y?"),
            "business_logic"  # default
        )

    def test_format_contract_context(self):
        attacker = MockAttacker(
            name="TestAttacker",
            description="Test",
            backend=self.mock_backend,
            logger=self.mock_logger,
            cost_manager=self.mock_cost_manager,
            knowledge_graph=self.mock_knowledge_graph
        )

        contract_info = {
            "state_vars": ["balance", "owner", "totalSupply"],
            "taint_traces": ["owner -> balance", "totalSupply -> balance"],
            "invariants": ["totalSupply >= sum(balances)", "owner != address(0)"],
            "semantic_snippets": [
                {
                    "metadata": {"signature": "transfer(address,uint256)"},
                    "content": "function transfer(address to, uint256 amount) public returns (bool)"
                }
            ]
        }

        context = attacker._format_contract_context(contract_info)

        self.assertIn("STATE VARS:", context)
        self.assertIn("balance", context)
        self.assertIn("TAINT PATHS:", context)
        self.assertIn("owner -> balance", context)
        self.assertIn("INVARIANTS:", context)
        self.assertIn("totalSupply >= sum", context)
        self.assertIn("SEMANTIC HIGHLIGHTS:", context)
        self.assertIn("transfer", context)

if __name__ == '__main__':
    unittest.main()
