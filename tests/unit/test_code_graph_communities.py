import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from cal.code_graph import CodeGraph  # noqa: E402

SRC = """
pragma solidity ^0.8.25;
contract A {
    uint256 public x;
    function a() external { x += 1; b(); }
    function b() internal { x += 2; }
    function c() external { x += 3; }
}
"""

def test_code_graph_communities_build():
    cg = CodeGraph("A")
    cg.build(SRC)
    comms = cg.graph_communities(max_communities=2, max_nodes=10)
    assert comms, "communities should be produced"
    assert comms[0].nodes, "community slice has nodes"
