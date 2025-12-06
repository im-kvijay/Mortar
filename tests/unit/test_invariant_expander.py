import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType  # noqa: E402
from research.invariant_expander import InvariantExpander  # noqa: E402

def test_invariant_expander_adds_nodes_and_edges():
    kg = KnowledgeGraph(contract_name="Vault")
    expander = InvariantExpander()
    contract_info = {"state_vars": ["paused", "totalAssets", "totalDebt"]}
    invariants = expander.add_invariants(contract_info, kg)
    assert "paused == false" in invariants
    nodes = kg.get_nodes_by_type(NodeType.INVARIANT)
    assert nodes, "Invariant nodes should be added"
    edges = kg.get_edges_from(nodes[0].node_id)
    assert edges, "Invariant nodes should have dependency edges to state vars"
