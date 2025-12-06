import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from verification.iris_lite import IrisLite  # noqa: E402
from kb.knowledge_graph import KnowledgeGraph, NodeType  # noqa: E402

def test_iris_lite_taints_and_invariants():
    iris = IrisLite()
    kg = KnowledgeGraph("Demo")
    ci = {
        "name": "Demo",
        "taint_traces_struct": [{"source": "execute", "sink": "call(data)", "line": 12}],
        "invariants": ["!paused"],
    }
    findings = iris.assess(ci, kg)
    assert findings, "iris-lite should return findings"
    vuln_nodes = [n for n, data in kg.graph.nodes(data=True) if data.get("node_type") == NodeType.VULNERABILITY.value]
    assert vuln_nodes, "vulnerability nodes added"
    assert ci.get("structural_coverage"), "coverage metrics should be attached"
    assert any("risk_score" in f for f in findings), "risk scores should be present on findings"
