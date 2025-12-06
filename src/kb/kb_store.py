# SPDX-License-Identifier: MIT
"""lightweight kb store with append-only jsonl event log"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, Any


class KBStore:
    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.events_dir = self.root / "events"
        self.events_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / "index.json"
        if not self.index_path.exists():
            self.index_path.write_text(json.dumps({"models": {}}, indent=2), encoding="utf-8")

    def _today_path(self) -> Path:
        ts = time.strftime("%Y%m%d")
        return self.events_dir / f"{ts}.ndjson"

    def add_event(self, record: Dict[str, Any]) -> None:
        path = self._today_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")

    def update_model(self, key: str, delta: Dict[str, float]) -> None:
        key = key or "unknown"
        idx = json.loads(self.index_path.read_text(encoding="utf-8"))
        model = idx["models"].get(key, {"counts": {}, "priors": {}})
        counts = model.get("counts", {})
        for feature, inc in delta.items():
            counts[feature] = counts.get(feature, 0.0) + inc
        # Laplace smoothing to keep probabilities bounded
        total = sum(v for v in counts.values()) + 1e-9
        priors = {feat: (value + 1.0) / (total + len(counts)) for feat, value in counts.items()}
        model["counts"] = counts
        model["priors"] = priors
        idx["models"][key] = model
        self.index_path.write_text(json.dumps(idx, indent=2), encoding="utf-8")

    def priors_for(self, key: str) -> Dict[str, float]:
        idx = json.loads(self.index_path.read_text(encoding="utf-8"))
        return idx["models"].get(key or "unknown", {}).get("priors", {})
