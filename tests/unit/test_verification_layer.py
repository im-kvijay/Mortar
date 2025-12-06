import json
import os
import unittest
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from utils.logging import ResearchLogger  # noqa: E402
from utils.cost_manager import CostManager  # noqa: E402
from utils.llm_backend.base import LLMBackend, LLMResponse  # noqa: E402
from agent.verification_layer import VerificationLayer  # noqa: E402
from kb.knowledge_graph import KnowledgeGraph  # noqa: E402
from agent.base_attacker import AttackHypothesis  # noqa: E402

class DummyBackend(LLMBackend):
    """Minimal backend stub that returns a deterministic verification response."""

    def __init__(self):
        super().__init__("dummy-model")

    def generate(self, prompt: str, system_prompt=None, max_tokens=4000, temperature=0.7, **kwargs) -> LLMResponse:
        payload = {
            "verified": True,
            "confidence": 0.9,
            "reasoning": "Stubbed verification approved.",
            "issues_found": [],
            "priority": 0.8,
        }
        return LLMResponse(text=json.dumps(payload))

    def is_available(self) -> bool:
        return True

class TestVerificationLayerParallel(unittest.TestCase):
    def setUp(self):
        self._orig_workers = os.environ.get("VERIFICATION_WORKERS")
        os.environ["VERIFICATION_WORKERS"] = "2"
        self.backend = DummyBackend()
        self.logger = ResearchLogger(project_root=str(PROJECT_ROOT))
        self.cost_manager = CostManager()
        self.layer = VerificationLayer(
            backend=self.backend,
            logger=self.logger,
            cost_manager=self.cost_manager,
            kb=None,
            enable_neurosymbolic=False,
        )
        self.graph = KnowledgeGraph("TestContract", project_root=str(PROJECT_ROOT))
        self.contract_info = {"name": "TestContract", "external_functions": ["foo()", "bar()"]}

    def tearDown(self):
        if self._orig_workers is None:
            os.environ.pop("VERIFICATION_WORKERS", None)
        else:
            os.environ["VERIFICATION_WORKERS"] = self._orig_workers

    def _hypothesis(self, idx: int) -> AttackHypothesis:
        return AttackHypothesis(
            hypothesis_id=f"hyp_{idx}",
            attack_type="logic",
            description=f"Hypothesis {idx}",
            target_function=f"func_{idx}",
            preconditions=["attacker_balance > 0"],
            steps=["Step 1: do something"],
            expected_impact="impact",
            confidence=0.8,
            requires_research=[],
            evidence=[],
        )

    def test_parallel_verification_produces_results(self):
        hypotheses = [self._hypothesis(1), self._hypothesis(2)]
        results = self.layer.verify_hypotheses(
            hypotheses=hypotheses,
            contract_source="contract source",
            contract_info=self.contract_info,
            knowledge_graph=self.graph,
        )
        self.assertEqual(len(results), 2)
        self.assertTrue(all(result.verified for result in results))

if __name__ == "__main__":
    unittest.main()
