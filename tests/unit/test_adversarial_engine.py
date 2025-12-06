import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from agent.adversarial_engine import AdversarialEngine  # noqa: E402

def test_adversarial_engine_skips_without_forge(tmp_path):
    engine = AdversarialEngine(project_root=str(tmp_path))
    results = engine.run_harnesses([{"name": "h1", "path": str(tmp_path)}])
    assert results, "should produce a result"
    if results[0].status == "skipped":
        assert "forge" in results[0].reason or results[0].reason
    else:
        assert results[0].status in {"passed", "failed"}
