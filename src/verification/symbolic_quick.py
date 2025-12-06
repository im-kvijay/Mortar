"""symbolic quick-check via mythril"""

from __future__ import annotations

import subprocess
import re
from typing import Tuple, Dict, Any


def run_mythril_quick(contract_path: str, timeout: int = 120) -> Tuple[bool, Dict[str, Any]]:
    try:
        p = subprocess.run(
            ["myth", "analyze", contract_path, "-q", "--execution-timeout", "60"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = p.stdout or ""
        stderr = p.stderr or ""
        found = ("Analysis results:" in stdout) and bool(re.search(r"Issue:\s", stdout))
        return bool(found), {
            "stdout": stdout[-2000:],
            "stderr": stderr[-800:],
            "exit_code": p.returncode,
        }
    except Exception as e:
        return False, {"error": str(e)}
