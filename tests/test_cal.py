#!/usr/bin/env python3
"""
Pytest-friendly CAL smoke test.

We keep the legacy CLI runner for manual debugging but expose a lightweight
pytest entrypoint that can be skipped when the heavy DVD fixture or Slither
dependency is unavailable.
"""
import os
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
for path in (ROOT, SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from config import config  # noqa: E402
from cal import analyze_project  # noqa: E402

def _run_cal() -> int:
    dvd_path = config.DVD_DIR
    if not dvd_path.exists():
        print(f"ERROR: DVD not found at {dvd_path}")
        return 1

    
    print(f"Path: {dvd_path}\n")

    results = analyze_project(str(dvd_path))

    # extract results
    project = results["project"]
    static_findings = results["static_findings"]
    attack_surfaces = results["attack_surfaces"]

    # print brief summary (kept short for test logs)
    print(f"Project: {project.project_name} | Contracts: {project.total_contracts} | LOC: {project.total_lines_of_code:,}")
    print(f"Static findings: {len(static_findings)}")
    print(f"Attack surfaces: {len(attack_surfaces)}")
    return 0

@pytest.mark.skipif(
    os.getenv("CAL_RUN_DVD", "0") != "1",
    reason="Set CAL_RUN_DVD=1 to run full CAL DVD smoke (slow, requires Slither).",
)
def test_cal_dvd_smoke():
    exit_code = _run_cal()
    assert exit_code == 0

if __name__ == "__main__":
    sys.exit(_run_cal())
