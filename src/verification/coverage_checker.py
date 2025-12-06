"""coverage checker for exploit classes"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Dict, Any

import json


def _load_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception:
        # minimal yaml substitute: accept json superset
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {"classes": []}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {"classes": []}
    except Exception:
        return {"classes": []}


def check_coverage(project_root: Path, classes: Iterable[str]) -> List[str]:
    cfg = _load_yaml(project_root / "coverage.yaml")
    entries = {str(c.get("name", "")).lower(): c for c in (cfg.get("classes") or [])}
    warnings: List[str] = []
    for cls in set(c.lower() for c in classes if c):
        entry = entries.get(cls)
        if not entry:
            warnings.append(f"[coverage] no coverage entry for class '{cls}'")
            continue
        if not entry.get("tags"):
            warnings.append(f"[coverage] class '{cls}' missing impact tags")
        if not entry.get("slither_detectors"):
            warnings.append(f"[coverage] class '{cls}' missing slither detectors mapping")
        if not entry.get("invariants"):
            warnings.append(f"[coverage] class '{cls}' missing invariants")
    return warnings
