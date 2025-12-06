"""metrics logger for feature instrumentation"""

from __future__ import annotations

import json
import threading
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, Any

from config import config

_METRICS_PATH = config.DATA_DIR / "logs" / "feature_metrics.ndjson"
_METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
_LOCK = threading.Lock()


def log_metric(component: str, event: str, payload: Dict[str, Any]) -> None:
    """append structured metrics record to disk"""
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "component": component,
        "event": event,
    }
    record.update(payload)

    try:
        serialized = json.dumps(record)
    except Exception as exc:
        serialized = json.dumps(
            {
                "timestamp": record["timestamp"],
                "component": component,
                "event": event,
                "error": f"failed to serialize payload: {exc}",
            }
        )

    with _LOCK:
        with _METRICS_PATH.open("a", encoding="utf-8") as f:
            f.write(serialized + "\n")
