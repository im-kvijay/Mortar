import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from agent.economic_simulator import EconomicSimulator  # noqa: E402
from kb.knowledge_graph import KnowledgeGraph, NodeType  # noqa: E402
from kb.knowledge_base import KnowledgeBase  # noqa: E402
from utils.logging import ResearchLogger  # noqa: E402

SAMPLE_SOURCE = """
pragma solidity ^0.8.20;
contract EconUnit {
    uint256 public totalAssets;
    uint256 public rewardRate;
    function deposit(uint256 amount) external {}
    function claim() external {}
}
"""

def test_economic_simulator_updates_kb_and_graph():
    kg = KnowledgeGraph("EconUnit")
    kb = KnowledgeBase(disable_storage=True)
    simulator = EconomicSimulator(
        knowledge_graph=kg,
        knowledge_base=kb,
        logger=ResearchLogger(),
        max_steps=3,
        min_margin=0.0,
    )
    contract_info = {
        "name": "EconUnit",
        "state_vars": ["totalAssets", "rewardRate"],
        "token_flows": [
            {
                "function": "deposit",
                "token": "TOK",
                "flow_type": "deposit",
                "amount_expression": "amount",
                "has_balance_check": False,
                "has_allowance_check": False,
                "updates_before_transfer": False,
            },
            {
                "function": "claim",
                "token": "TOK",
                "flow_type": "withdrawal",
                "amount_expression": "rewardPerToken",
                "has_balance_check": False,
                "has_allowance_check": True,
                "updates_before_transfer": True,
            },
        ],
        "flash_loan_capable": True,
        "has_oracle": True,
    }

    result = simulator.simulate(contract_info, SAMPLE_SOURCE)

    assert result["hypotheses"], "economic simulator should emit hypotheses"
    econ_nodes = [
        n for n in kg.get_nodes_by_type(NodeType.BUSINESS_LOGIC) if n.metadata.get("actor")
    ]
    assert econ_nodes, "knowledge graph should contain economic discovery nodes"

    kb_entry = kb.contract_knowledge.get("EconUnit", {})
    assert kb_entry.get("economic_simulator"), "KB should persist economic signals"
