import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from cal.code_graph import CodeGraph

SIMPLE_SRC = """
pragma solidity ^0.8.25;

contract Vault {
    uint256 public totalAssets;
    uint256 public totalDebt;

    function deposit(uint256 amount) public {
        totalAssets += amount;
        _updateDebt();
    }

    function _updateDebt() internal {
        totalDebt = totalAssets / 2;
    }

    function withdraw(uint256 amount) external {
        require(amount <= totalAssets, "too much");
        totalAssets -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

def test_code_graph_builds_nodes_and_edges():
    cg = CodeGraph("Vault")
    cg.build(SIMPLE_SRC)
    data = cg.to_dict()
    node_ids = {n["id"] for n in data["nodes"]}
    assert any(n.startswith("invariant::") for n in node_ids)
    assert "fn::deposit" in node_ids
    assert "fn::_updateDebt" in node_ids
    assert "state::totalAssets" in node_ids
    assert "state::totalDebt" in node_ids
    # reads/writes and calls captured
    edge_types = {(e["source"], e["target"], e.get("type")) for e in data["edges"]}
    assert ("fn::deposit", "fn::_updateDebt", "calls_internal") in edge_types
    assert ("fn::deposit", "state::totalAssets", "writes") in edge_types
    assert ("fn::withdraw", "dep::transfer", "calls_external") in edge_types

def test_code_graph_slice_limits_nodes():
    cg = CodeGraph("Vault")
    cg.build(SIMPLE_SRC)
    slice_obj = cg.slice("fn::deposit", hops=2, max_nodes=5)
    assert slice_obj.nodes, "slice should not be empty"
    assert len(slice_obj.nodes) <= 5

def test_code_graph_ingests_slither_calls_reads_writes():
    slither = {
        "contracts": [
            {
                "name": "Vault",
                "functions": [
                    {
                        "name": "deposit",
                        "calls": [{"name": "_updateDebt"}],
                        "stateVariablesRead": [{"name": "totalAssets"}],
                        "stateVariablesWritten": [{"name": "totalAssets"}],
                    },
                    {
                        "name": "_updateDebt",
                        "stateVariablesWritten": [{"name": "totalDebt"}],
                    },
                ],
            }
        ]
    }
    cg = CodeGraph("Vault")
    cg.build(SIMPLE_SRC, slither=slither)
    data = cg.to_dict()
    edge_types = {(e["source"], e["target"], e.get("type")) for e in data["edges"]}
    assert ("fn::deposit", "fn::_updateDebt", "calls_internal") in edge_types
    assert ("fn::deposit", "state::totalAssets", "writes") in edge_types
    assert ("fn::_updateDebt", "state::totalDebt", "writes") in edge_types
