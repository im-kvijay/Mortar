import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from research.taint_tracer import trace_taint_paths  # noqa: E402
from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType  # noqa: E402

SAMPLE = """
pragma solidity ^0.8.17;

contract Caller {
    address target;

    function execute(bytes calldata data) external {
        (bool ok,) = target.call(data);
        require(ok, "fail");
    }
}
"""

def test_trace_taint_paths():
    traces = trace_taint_paths(SAMPLE, abi_map={"deadbeef": "Target.handle"}, contract_name="Caller")
    assert traces and traces[0]["source"] == "execute"
    assert "call" in traces[0]["sink"]
    assert traces[0]["contract"] == "Caller"

def test_traces_enrich_graph():
    graph = KnowledgeGraph(contract_name="Caller")
    traces = trace_taint_paths(SAMPLE)
    for t in traces:
        fn_node = f"fn::{t['source']}"
        sink_node = f"call::{t['sink']}"
        graph.add_node(fn_node, NodeType.FUNCTION, t["source"])
        graph.add_node(sink_node, NodeType.DEPENDENCY, t["sink"])
        graph.add_edge(fn_node, sink_node, EdgeType.CALLS)
    assert graph.get_node("fn::execute")
    assert graph.get_edges_from("fn::execute")
