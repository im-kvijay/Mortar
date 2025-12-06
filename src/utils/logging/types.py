"""logging types and enums this module defines the core types used by the logging system: - logcateg..."""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional


class LogCategory(Enum):
    """log categories for organizing raw json files. each category corresponds to a different aspect of ..."""
    RESEARCH = "research"
    ATTACK = "attacks"
    KB_UPDATE = "kb_updates"
    DECISION = "decisions"
    GRAPH_UPDATE = "graph_updates"
    SYSTEM_METRIC = "metrics"
    ERROR = "errors"


@dataclass
class LogEntry:
    """structured log entry for database storage. this dataclass represents a single log event that gets..."""
    timestamp: str
    category: str
    event_type: str
    agent_name: Optional[str]
    contract_name: Optional[str]
    round_num: Optional[int]
    data: Dict[str, Any]
    metadata: Dict[str, Any]
