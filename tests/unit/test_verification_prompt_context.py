import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from agent.verification_layer import VerificationLayer  # noqa: E402
from kb.knowledge_graph import KnowledgeGraph  # noqa: E402
from agent.base_attacker import AttackHypothesis  # noqa: E402
from utils.logging import ResearchLogger  # noqa: E402
from utils.cost_manager import CostManager  # noqa: E402
from utils.llm_backend.base import LLMBackend  # noqa: E402

class DummyBackend(LLMBackend):
    def __init__(self):
        super().__init__(model="dummy")

    def complete(self, *args, **kwargs):
        class Resp:
            def __init__(self):
                self.completion = '{"verified": false, "confidence": 0.1, "reasoning": "dummy", "issues_found": [], "priority": 0.1}'
                self.prompt_tokens = 0
                self.output_tokens = 0
        return Resp()

    def generate(self, *args, **kwargs):
        return self.complete(*args, **kwargs)

    def is_available(self) -> bool:
        return True

def test_verification_prompt_includes_taints_and_system_context():
    vl = VerificationLayer(
        backend=DummyBackend(),
        logger=ResearchLogger(),
        cost_manager=CostManager()
    )
    kg = KnowledgeGraph("Test")
    hyp = AttackHypothesis(
        hypothesis_id="h1",
        attack_type="logic",
        description="desc",
        target_function="fn",
        preconditions=[],
        steps=[],
        expected_impact="",
        confidence=0.5,
        requires_research=[],
        evidence=[],
    )
    contract_info = {
        "name": "Test",
        "system_context": "Project: Demo",
        "taint_traces": ["foo -> bar"],
        "external_functions": ["fn()"],
        "flash_loan_capable": False,
        "has_oracle": False,
    }
    # we don't call llm; just build prompt through the private helper
    prompt = vl._build_verification_prompt(
        hypothesis=hyp,
        contract_source="",
        contract_info=contract_info,
        graph_context="",
        similar_hypotheses=[]
    )
    assert "TAINT PATHS" in prompt
    assert "Project: Demo" in prompt
