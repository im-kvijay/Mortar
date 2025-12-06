import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from research.dependency_refiner import DependencyRefiner  # noqa: E402

def test_dependency_refiner_merges_sources():
    refiner = DependencyRefiner()
    contract_info = {
        "name": "Demo",
        "taint_traces_struct": [{"source": "run", "sink": "Target.call(data)", "resolved_target": "Target.execute"}],
        "code_graph": {
            "edges": [
                {"source": "fn::run", "target": "dep::transfer", "type": "calls_external"},
            ]
        },
    }
    refined = refiner.refine(contract_info)
    sinks = {r["sink"] for r in refined}
    assert "Target.execute" in sinks or "Target.call(data)" in sinks
    assert any(r["via"] == "code_graph" for r in refined)
