import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SRC = ROOT / "src"
for path in (ROOT, SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType  # noqa: E402
from research.state_modeler import StateModeler  # noqa: E402
from research.project_context import ProjectContext  # noqa: E402
from models.findings import ProjectStructure, ContractInfo  # noqa: E402

SAMPLE_CONTRACT = """
pragma solidity ^0.8.17;

contract Sample {
    bool public paused;
    uint256 totalAssets;

    function pause() external {
        paused = true;
    }

    function deposit(uint256 amount) external {
        totalAssets = totalAssets + amount;
    }
}
"""

def test_state_modeler_adds_state_nodes_and_edges():
    graph = KnowledgeGraph(contract_name="Sample")
    modeler = StateModeler()
    result = modeler.analyze("Sample", SAMPLE_CONTRACT, graph)

    # two state vars discovered
    assert set(result["state_vars"]) == {"paused", "totalAssets"}
    state_nodes = graph.get_nodes_by_type(NodeType.STATE_VAR)
    assert len(state_nodes) == 2

    # function edges captured - check edges directly instead of using removed function_view
    pause_edges = graph.get_edges_from("fn::pause")
    assert pause_edges, "pause() should have outgoing edges"
    assert any(edge.edge_type == EdgeType.MODIFIES for edge in pause_edges)

def test_project_context_zoom_views():
    # minimal project structure with one contract
    contract = ContractInfo(
        name="Sample",
        file_path=Path("Sample.sol"),
        solidity_version="0.8.17",
    )
    project = ProjectStructure(
        project_root=ROOT,
        project_name="TestProject",
        contracts=[contract],
        test_contracts=[],
        solidity_versions=["0.8.17"],
        total_contracts=1,
        total_lines_of_code=42,
    )
    graph = KnowledgeGraph(contract_name="Sample")
    graph.add_node("fn::pause", NodeType.FUNCTION, "pause")
    context = ProjectContext(project, {"Sample": graph})

    system = context.system_view()
    assert "Sample" in system["contracts"]

    # Test that we can get the graph and check nodes directly
    sample_graph = context.knowledge_graphs.get("Sample")
    assert sample_graph is not None
    pause_node = sample_graph.get_node("fn::pause")
    assert pause_node is not None
    assert pause_node.name == "pause"

def test_semantic_search_toggle():
    graph = KnowledgeGraph(contract_name="Sample")
    graph._semantic_enabled = True  # enable without env churn for test
    graph.index_semantic_snippets({"handler": "deposit withdraw flashLoan"}, metadata={"component": "finance"})
    results = graph.semantic_search("flash loan")
    assert results and results[0]["id"] == "handler"
