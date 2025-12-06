import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from research.supervisor import Supervisor  # noqa: E402
from kb.knowledge_graph import KnowledgeGraph  # noqa: E402

def test_research_quality_handles_zero_denominators():
    sup = Supervisor(enable_v3=False, enable_moa=False, enable_ace=False, enable_a2a=False)
    kg = KnowledgeGraph("Demo")
    contract_info = {"name": "Demo", "total_functions": 0, "total_state_vars": 0}
    score = sup.calculate_research_quality(kg, specialist_results={}, contract_info=contract_info)
    assert 0.0 <= score <= 1.0
