"""runprofile: lightweight per-run instrumentation for mortar-c. tracks per-phase timings and cost d..."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, Optional, Any, List


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class PhaseMetrics:
    """stores timing and cost deltas for a single pipeline phase."""

    name: str
    status: str = "pending"  # pending | in_progress | completed | error
    started_at: Optional[str] = None
    duration_sec: float = 0.0
    cost_delta: float = 0.0
    token_usage: Dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    _start_ts: Optional[float] = field(default=None, init=False, repr=False, compare=False)
    _cost_baseline: float = field(default=0.0, init=False, repr=False, compare=False)

    def mark_start(self, current_cost: float = 0.0) -> None:
        self.started_at = _now_iso()
        self._start_ts = time.time()
        self._cost_baseline = current_cost
        self.status = "in_progress"

    def mark_end(self, current_cost: float = 0.0, status: str = "completed", error: Optional[str] = None) -> None:
        if self._start_ts is not None:
            self.duration_sec = max(0.0, time.time() - self._start_ts)
        self.cost_delta = max(0.0, current_cost - self._cost_baseline)
        self.status = status
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "started_at": self.started_at,
            "duration_sec": self.duration_sec,
            "cost_delta": self.cost_delta,
            "token_usage": self.token_usage,
            "error": self.error,
            "notes": self.notes,
            "extra": self.extra,
        }


@dataclass
class RunProfile:
    """per-contract run profile capturing phase metrics."""

    contract_name: str
    profile_id: str = field(default_factory=lambda: f"run-{int(time.time())}")
    started_at: str = field(default_factory=_now_iso)
    phases: Dict[str, PhaseMetrics] = field(default_factory=dict)
    total_duration_sec: float = 0.0
    total_cost: float = 0.0
    notes: List[str] = field(default_factory=list)

    _start_ts: float = field(default_factory=time.time, init=False, repr=False, compare=False)

    def phase_start(self, name: str, current_cost: float = 0.0) -> None:
        phase = self.phases.get(name) or PhaseMetrics(name=name)
        phase.mark_start(current_cost=current_cost)
        self.phases[name] = phase

    def phase_end(self, name: str, current_cost: float = 0.0, status: str = "completed", error: Optional[str] = None) -> None:
        phase = self.phases.get(name)
        if not phase:
#            # if end called without start, initialize minimally
            phase = PhaseMetrics(name=name, status="in_progress")
        phase.mark_end(current_cost=current_cost, status=status, error=error)
        self.phases[name] = phase

    def finalize(self, total_cost: float = 0.0) -> None:
        self.total_cost = total_cost
        self.total_duration_sec = max(0.0, time.time() - self._start_ts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_name": self.contract_name,
            "profile_id": self.profile_id,
            "started_at": self.started_at,
            "total_duration_sec": self.total_duration_sec,
            "total_cost": self.total_cost,
            "phases": {name: phase.to_dict() for name, phase in self.phases.items()},
            "notes": self.notes,
        }

    def save_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)

