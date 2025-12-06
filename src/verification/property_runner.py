"""property runner helpers (foundry invariants)"""

from __future__ import annotations

import subprocess
from typing import Tuple, Dict, Any


def run_foundry_invariants(sbx_root: str) -> Tuple[bool, Dict[str, Any]]:
    """attempt to run foundry invariant suites in sandbox"""
    try:
        p = subprocess.run(
            ["forge", "test", "-vvv", "--match-contract", "Invariant"],
            cwd=sbx_root,
            capture_output=True,
            text=True,
            timeout=240,
        )
        out = (p.stdout or "") + (p.stderr or "")
        # treat 'no contracts to fuzz' as neutral (not corroboration)
        if "No contracts to fuzz" in out:
            return False, {
                "neutral": True,
                "stdout": (p.stdout or "")[-1600:],
                "stderr": (p.stderr or "")[-800:],
                "exit_code": p.returncode,
            }
        # foundry prints failed when an invariant test fails
        failed = ("Test result: FAILED" in out) or ("Failing tests" in out)
        return bool(failed), {
            "stdout": (p.stdout or "")[-1600:],
            "stderr": (p.stderr or "")[-800:],
            "exit_code": p.returncode,
        }
    except Exception as e:
        return False, {"error": str(e)}
