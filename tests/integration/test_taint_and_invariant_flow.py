"""
Integration-style check: taint and invariants propagate through supervisor into verification prompt.
Uses dummy backends and minimal artifacts to keep runtime fast.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from research.state_modeler import StateModeler  # noqa: E402
from research.taint_tracer import trace_taint_paths  # noqa: E402
from research.invariant_expander import InvariantExpander  # noqa: E402
from agent.verification_layer import VerificationLayer  # noqa: E402
from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType  # noqa: E402
from utils.logging import ResearchLogger  # noqa: E402
from utils.cost_manager import CostManager  # noqa: E402
from utils.llm_backend.base import LLMBackend  # noqa: E402
from agent.base_attacker import AttackHypothesis  # noqa: E402
import os

SAMPLE_CONTRACT = """
pragma solidity ^0.8.17;
contract Sample {
    bool public paused;
    uint256 public totalAssets;
    function pause() external { paused = true; }
    function execute(address target, bytes calldata data) external {
        (bool ok,) = target.call(data);
        require(ok);
    }
}
"""

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

def test_taint_and_invariant_flow():
    # build graph and contract_info manually to avoid live llm calls
    kg = KnowledgeGraph("Sample")
    ci = {"name": "Sample"}
    # state modeling
    state_modeler = StateModeler()
    state_modeler.analyze("Sample", SAMPLE_CONTRACT, kg)
    ci["state_vars"] = ["paused", "totalAssets"]
    # taint tracing
    taints = trace_taint_paths(SAMPLE_CONTRACT, contract_name="Sample")
    ci["taint_traces"] = [f"{t['source']} -> {t['sink']} (line {t['line']})" for t in taints]
    ci["taint_traces_struct"] = taints
    for t in taints:
        fn_node = f"fn::{t['source']}"
        sink_node = f"Sample::call::{t['sink']}"
        kg.add_node(fn_node, NodeType.FUNCTION, t["source"])
        kg.add_node(sink_node, NodeType.DEPENDENCY, t["sink"])
        kg.add_edge(fn_node, sink_node, EdgeType.CALLS)
    # invariants
    invariants = InvariantExpander().add_invariants(ci, kg)
    ci["invariants"] = invariants

    vl = VerificationLayer(
        backend=DummyBackend(),
        logger=ResearchLogger(),
        cost_manager=CostManager(),
        enable_neurosymbolic=False,
    )
    hyp = AttackHypothesis(
        hypothesis_id="h1",
        attack_type="logic",
        description="desc",
        target_function="execute",
        preconditions=[],
        steps=[],
        expected_impact="",
        confidence=0.5,
        requires_research=[],
        evidence=[],
    )
    prompt = vl._build_verification_prompt(
        hypothesis=hyp,
        contract_source=SAMPLE_CONTRACT,
        contract_info=ci,
        graph_context="",
        similar_hypotheses=[],
    )
    assert "TAINT PATHS" in prompt
    assert "paused" in prompt or "totalAssets" in prompt
