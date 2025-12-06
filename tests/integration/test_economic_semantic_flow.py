"""
Integration-style check ensuring semantic slices and economic simulator findings
flow into verification prompts (Rewarder/Selfie-style economics).
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from agent.base_attacker import AttackHypothesis  # noqa: E402
from agent.economic_simulator import EconomicSimulator  # noqa: E402
from agent.verification_layer import VerificationLayer  # noqa: E402
from kb.knowledge_base import KnowledgeBase  # noqa: E402
from kb.knowledge_graph import KnowledgeGraph, NodeType  # noqa: E402
from context.project_context import ProjectContext  # noqa: E402
from utils.cost_manager import CostManager  # noqa: E402
from utils.logging import ResearchLogger  # noqa: E402
from utils.llm_backend.base import LLMBackend  # noqa: E402

SAMPLE_REWARDER = """
pragma solidity ^0.8.20;
contract RewarderPool {
    uint256 public rewardRate;
    uint256 public totalSupply;
    function deposit(uint256 amount) external {}
    function claimRewards() external {}
}
"""

SAMPLE_SELFIE = """
pragma solidity ^0.8.20;
contract SelfiePool {
    uint256 public flashFee;
    function flashLoan(uint256 amount) external {}
}
"""

class DummyBackend(LLMBackend):
    def __init__(self):
        super().__init__(model="dummy")

    def complete(self, *args, **kwargs):
        class Resp:
            def __init__(self):
                self.completion = (
                    '{"verified": false, "confidence": 0.1, "reasoning": "dummy", '
                    '"issues_found": [], "priority": 0.1}'
                )
                self.prompt_tokens = 0
                self.output_tokens = 0

        return Resp()

    def generate(self, *args, **kwargs):
        return self.complete(*args, **kwargs)

    def is_available(self) -> bool:
        return True

def test_rewarder_semantic_and_economic_context(tmp_path):
    rewarder_path = tmp_path / "RewarderPool.sol"
    rewarder_path.write_text(SAMPLE_REWARDER)
    selfie_path = tmp_path / "SelfiePool.sol"
    selfie_path.write_text(SAMPLE_SELFIE)

    project_context = ProjectContext(str(tmp_path))
    project_context.index_workspace()
    semantic_slices = project_context.get_semantic_slices("RewarderPool")

    kg = KnowledgeGraph("RewarderPool")
    kb = KnowledgeBase(disable_storage=True)
    simulator = EconomicSimulator(
        knowledge_graph=kg,
        knowledge_base=kb,
        logger=ResearchLogger(),
        max_steps=3,
        min_margin=0.0,
    )
    contract_info = {
        "name": "RewarderPool",
        "state_vars": ["rewardRate", "totalSupply"],
        "token_flows": [
            {
                "function": "deposit",
                "token": "RWD",
                "flow_type": "deposit",
                "amount_expression": "amount",
                "has_balance_check": False,
                "has_allowance_check": False,
                "updates_before_transfer": False,
            },
            {
                "function": "claimRewards",
                "token": "RWD",
                "flow_type": "withdrawal",
                "amount_expression": "rewardRate",
                "has_balance_check": False,
                "has_allowance_check": True,
                "updates_before_transfer": True,
            },
        ],
        "flash_loan_capable": True,
        "has_oracle": True,
        "semantic_snippets": semantic_slices,
        "system_context": project_context.get_system_view(),
        "invariants": ["Rewards should never exceed deposits"],
        "external_functions": ["deposit(uint256)", "claimRewards()"],
    }

    sim_result = simulator.simulate(contract_info, SAMPLE_REWARDER)
    contract_info["economic_findings"] = sim_result["summaries"]
    hypothesis = sim_result["hypotheses"][0] if sim_result["hypotheses"] else AttackHypothesis(
        hypothesis_id="econ_fallback",
        attack_type="economic",
        description="rewarder anomaly",
        target_function="claimRewards",
        preconditions=[],
        steps=[],
        expected_impact="",
        confidence=0.5,
        requires_research=[],
        evidence=[],
    )

    vl = VerificationLayer(
        backend=DummyBackend(),
        logger=ResearchLogger(),
        cost_manager=CostManager(),
        enable_neurosymbolic=False,
    )
    graph_context = vl._extract_graph_context(kg, hypothesis)
    prompt = vl._build_verification_prompt(
        hypothesis=hypothesis,
        contract_source=SAMPLE_REWARDER,
        contract_info=contract_info,
        graph_context=graph_context,
        similar_hypotheses=[],
    )

    assert "SEMANTIC HIGHLIGHTS" in prompt
    assert "ECONOMIC SIGNALS" in prompt
    assert "RewarderPool" in prompt

    econ_nodes = [
        n for n in kg.get_nodes_by_type(NodeType.BUSINESS_LOGIC) if n.metadata.get("actor")
    ]
    assert econ_nodes

    if os.getenv("RUN_HEAVY_ECON", "0") == "1":
        vl.verify_hypotheses(
            hypotheses=[hypothesis],
            contract_source=SAMPLE_REWARDER,
            contract_info=contract_info,
            knowledge_graph=kg,
            max_hypotheses=1,
        )
