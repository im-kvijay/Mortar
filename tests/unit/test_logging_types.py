"""tests for logging.types module"""

import pytest
from src.utils.logging.types import LogCategory, LogEntry

class TestLogCategory:
    def test_all_categories_exist(self):
        expected = ["RESEARCH", "ATTACK", "KB_UPDATE", "DECISION",
                   "GRAPH_UPDATE", "SYSTEM_METRIC", "ERROR"]
        actual = [cat.name for cat in LogCategory]
        assert set(expected) == set(actual)

    def test_category_values(self):
        assert LogCategory.RESEARCH.value == "research"
        assert LogCategory.ATTACK.value == "attacks"
        assert LogCategory.KB_UPDATE.value == "kb_updates"
        assert LogCategory.DECISION.value == "decisions"
        assert LogCategory.GRAPH_UPDATE.value == "graph_updates"
        assert LogCategory.SYSTEM_METRIC.value == "metrics"
        assert LogCategory.ERROR.value == "errors"

    def test_category_from_value(self):
        assert LogCategory("research") == LogCategory.RESEARCH
        assert LogCategory("attacks") == LogCategory.ATTACK
        assert LogCategory("errors") == LogCategory.ERROR

    def test_category_invalid_value_raises_error(self):
        with pytest.raises(ValueError):
            LogCategory("invalid_category")

    def test_category_is_enum(self):
        from enum import Enum
        assert issubclass(LogCategory, Enum)

    def test_category_equality(self):
        cat1 = LogCategory.RESEARCH
        cat2 = LogCategory.RESEARCH
        cat3 = LogCategory.ATTACK

        assert cat1 == cat2
        assert cat1 != cat3
        assert cat1 is cat2  # enums are singletons

    def test_category_in_collection(self):
        categories = {LogCategory.RESEARCH, LogCategory.ATTACK}
        assert LogCategory.RESEARCH in categories
        assert LogCategory.ERROR not in categories

    def test_category_iteration(self):
        categories = list(LogCategory)
        assert len(categories) == 7
        assert all(isinstance(cat, LogCategory) for cat in categories)

class TestLogEntry:
    """ """

    def test_log_entry_creation_minimal(self):
        entry = LogEntry(
            timestamp="2025-10-21T10:00:00Z",
            category="research",
            event_type="discovery",
            agent_name=None,
            contract_name=None,
            round_num=None,
            data={},
            metadata={}
        )

        assert entry.timestamp == "2025-10-21T10:00:00Z"
        assert entry.category == "research"
        assert entry.event_type == "discovery"
        assert entry.agent_name is None
        assert entry.contract_name is None
        assert entry.round_num is None
        assert entry.data == {}
        assert entry.metadata == {}

    def test_log_entry_creation_full(self):
        entry = LogEntry(
            timestamp="2025-10-21T10:30:00Z",
            category="research",
            event_type="discovery",
            agent_name="BusinessLogic",
            contract_name="UnstoppableVault",
            round_num=1,
            data={"vulnerability": "reentrancy", "confidence": 0.85},
            metadata={"cost": 0.05, "tokens": 1500}
        )

        assert entry.timestamp == "2025-10-21T10:30:00Z"
        assert entry.category == "research"
        assert entry.event_type == "discovery"
        assert entry.agent_name == "BusinessLogic"
        assert entry.contract_name == "UnstoppableVault"
        assert entry.round_num == 1
        assert entry.data["vulnerability"] == "reentrancy"
        assert entry.data["confidence"] == 0.85
        assert entry.metadata["cost"] == 0.05
        assert entry.metadata["tokens"] == 1500

    def test_log_entry_is_dataclass(self):
        from dataclasses import is_dataclass
        assert is_dataclass(LogEntry)

    def test_log_entry_field_types(self):
        from dataclasses import fields

        field_dict = {f.name: f.type for f in fields(LogEntry)}

        assert field_dict["timestamp"] == str
        assert field_dict["category"] == str
        assert field_dict["event_type"] == str

    def test_log_entry_optional_fields(self):
        entry = LogEntry(
            timestamp="2025-10-21T10:00:00Z",
            category="error",
            event_type="exception",
            agent_name=None,
            contract_name=None,
            round_num=None,
            data={"error": "timeout"},
            metadata={}
        )

        assert entry.agent_name is None
        assert entry.contract_name is None
        assert entry.round_num is None

    def test_log_entry_with_complex_data(self):
        complex_data = {
            "vulnerability": {
                "type": "reentrancy",
                "severity": "CRITICAL",
                "affected_functions": ["withdraw", "claim"],
                "confidence": 0.95
            },
            "evidence": [
                {"line": 42, "code": "call.value(amount)()"},
                {"line": 45, "code": "balances[msg.sender] = 0"}
            ]
        }

        entry = LogEntry(
            timestamp="2025-10-21T10:00:00Z",
            category="research",
            event_type="discovery",
            agent_name="StateFlow",
            contract_name="VulnerableContract",
            round_num=2,
            data=complex_data,
            metadata={"thinking_tokens": 500}
        )

        assert entry.data["vulnerability"]["type"] == "reentrancy"
        assert len(entry.data["evidence"]) == 2
        assert entry.data["evidence"][0]["line"] == 42

    def test_log_entry_with_various_event_types(self):
        event_types = [
            "ai_call", "discovery", "attack_hypothesis", "poc_execution",
            "pattern_update", "graph_update", "decision", "error"
        ]

        for event_type in event_types:
            entry = LogEntry(
                timestamp="2025-10-21T10:00:00Z",
                category="research",
                event_type=event_type,
                agent_name="TestAgent",
                contract_name="TestContract",
                round_num=1,
                data={},
                metadata={}
            )
            assert entry.event_type == event_type

    def test_log_entry_equality(self):
        entry1 = LogEntry(
            timestamp="2025-10-21T10:00:00Z",
            category="research",
            event_type="discovery",
            agent_name="Agent1",
            contract_name="Contract1",
            round_num=1,
            data={"test": "data"},
            metadata={"meta": "data"}
        )

        entry2 = LogEntry(
            timestamp="2025-10-21T10:00:00Z",
            category="research",
            event_type="discovery",
            agent_name="Agent1",
            contract_name="Contract1",
            round_num=1,
            data={"test": "data"},
            metadata={"meta": "data"}
        )

        entry3 = LogEntry(
            timestamp="2025-10-21T10:01:00Z",
            category="research",
            event_type="discovery",
            agent_name="Agent1",
            contract_name="Contract1",
            round_num=1,
            data={"test": "data"},
            metadata={"meta": "data"}
        )

        assert entry1 == entry2
        assert entry1 != entry3

    def test_log_entry_with_empty_strings(self):
        entry = LogEntry(
            timestamp="",
            category="",
            event_type="",
            agent_name="",
            contract_name="",
            round_num=0,
            data={},
            metadata={}
        )

        assert entry.timestamp == ""
        assert entry.category == ""
        assert entry.event_type == ""
        assert entry.agent_name == ""

    def test_log_entry_round_num_types(self):
        # positive round
        entry1 = LogEntry(
            timestamp="2025-10-21T10:00:00Z",
            category="research",
            event_type="test",
            agent_name="Agent",
            contract_name="Contract",
            round_num=5,
            data={},
            metadata={}
        )
        assert entry1.round_num == 5

        # zero round
        entry2 = LogEntry(
            timestamp="2025-10-21T10:00:00Z",
            category="research",
            event_type="test",
            agent_name="Agent",
            contract_name="Contract",
            round_num=0,
            data={},
            metadata={}
        )
        assert entry2.round_num == 0

        # none round
        entry3 = LogEntry(
            timestamp="2025-10-21T10:00:00Z",
            category="research",
            event_type="test",
            agent_name="Agent",
            contract_name="Contract",
            round_num=None,
            data={},
            metadata={}
        )
        assert entry3.round_num is None

    def test_log_entry_mutation(self):
        entry = LogEntry(
            timestamp="2025-10-21T10:00:00Z",
            category="research",
            event_type="discovery",
            agent_name="Agent1",
            contract_name="Contract1",
            round_num=1,
            data={},
            metadata={}
        )

        # dataclasses are mutable by default
        entry.agent_name = "Agent2"
        assert entry.agent_name == "Agent2"

        entry.data["new_key"] = "new_value"
        assert entry.data["new_key"] == "new_value"

    def test_log_entry_repr(self):
        entry = LogEntry(
            timestamp="2025-10-21T10:00:00Z",
            category="research",
            event_type="discovery",
            agent_name="Agent1",
            contract_name="Contract1",
            round_num=1,
            data={},
            metadata={}
        )

        repr_str = repr(entry)
        assert "LogEntry" in repr_str
        assert "research" in repr_str
        assert "discovery" in repr_str
