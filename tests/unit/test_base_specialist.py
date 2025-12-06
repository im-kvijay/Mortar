"""s for EnhancedAgenticSpecialist agent loop."""

import os
import tempfile
import unittest
from pathlib import Path

# silence backend warnings during tests by providing dummy credentials.
os.environ.setdefault("OPENROUTER_API_KEY", "test-key")

from src.research.base_specialist import EnhancedAgenticSpecialist
from src.kb.knowledge_graph import KnowledgeGraph
from src.utils.llm_backend.base import LLMBackend, LLMResponse

class FakeBackend(LLMBackend):
    """Deterministic backend for testing the agent loop."""

    def __init__(self):
        super().__init__(model="fake-model")
        self._call_count = 0

    def is_available(self) -> bool:
        return True

    def generate(self, *_, **__):  # pragma: no cover
        raise NotImplementedError("FakeBackend.generate is not implemented for this test")

    def generate_with_tools_multi_turn(self, *_, **__):
        if self._call_count == 0:
            self._call_count += 1
            return LLMResponse(
                text="",
                thinking=None,
                prompt_tokens=12,
                output_tokens=0,
                thinking_tokens=0,
                cost=0.0,
                model=self.model,
                tool_calls=[
                    {
                        "id": "tool-call-1",
                        "name": "record_discovery",
                        "input": {
                            "discovery_type": "business_logic",
                            "content": "A deterministic discovery for testing.",
                            "confidence": 0.9,
                            "evidence": ["Dummy evidence"]
                        }
                    },
                    {
                        "id": "tool-call-2",
                        "name": "update_knowledge_graph",
                        "input": {
                            "action": "add_node",
                            "node_id": "function:foo",
                            "node_type": "function",
                            "name": "foo",
                            "data": {"visibility": "public"}
                        }
                    }
                ],
                metadata={}
            )

        if self._call_count == 1:
            self._call_count += 1
            return LLMResponse(
                text="",
                thinking=None,
                prompt_tokens=6,
                output_tokens=0,
                thinking_tokens=0,
                cost=0.0,
                model=self.model,
                tool_calls=[
                    {
                        "id": "tool-call-3",
                        "name": "analysis_complete",
                        "input": {
                            "summary": "done",
                            "confidence": 0.95,
                            "areas_covered": ["business_logic"]
                        }
                    }
                ],
                metadata={}
            )
        self._call_count += 1
        return LLMResponse(
            text="",
            thinking=None,
            prompt_tokens=0,
            output_tokens=0,
            thinking_tokens=0,
            cost=0.0,
            model=self.model,
            tool_calls=[],
            metadata={}
        )

class DummySpecialist(EnhancedAgenticSpecialist):
    """Minimal specialist implementation for exercising the base loop."""

    def __init__(self, **kwargs):
        super().__init__(
            name="DummySpecialist",
            description="Test specialist for deterministic scenarios",
            **kwargs
        )

    def get_system_prompt(self) -> str:
        return "You are a deterministic specialist used for unit testing."

    def get_analysis_prompt(self, contract_source: str, contract_info: dict) -> str:
        return (
            f"Analyze contract {contract_info.get('name', 'Unknown')} "
            "and call analysis_complete when satisfied."
        )

class TestEnhancedAgenticSpecialist(unittest.TestCase):
    """ """

    def test_agent_loop_records_tool_calls_and_completes(self):
        backend = FakeBackend()
        with tempfile.TemporaryDirectory() as tmpdir:
            specialist = DummySpecialist(
                project_root=Path(tmpdir),
                backend=backend,
                backend_type="fake",
                model="fake-model",
                thinking_budget=None,
                enable_interleaved_thinking=False
            )

            graph = KnowledgeGraph(contract_name="DummyContract")

            results = specialist.analyze_contract(
                contract_source="pragma solidity ^0.8.0; contract Dummy { function foo() external {} }",
                contract_info={"name": "DummyContract", "total_functions": 1},
                knowledge_graph=graph
            )

        self.assertEqual(len(results), 1)
        result = results[0]

        self.assertTrue(result.analysis_complete, "Specialist should mark completion when analysis_complete tool is used.")
        self.assertEqual(result.summary, "done")
        self.assertAlmostEqual(result.confidence, 0.95)
        self.assertIn("business_logic", result.areas_covered)
        self.assertGreaterEqual(result.total_discoveries, 1)
        self.assertGreaterEqual(len(result.tool_calls), 3)
        self.assertEqual(result.tool_calls[0]["tool"], "record_discovery")
        self.assertEqual(result.tool_calls[-1]["tool"], "analysis_complete")
        self.assertEqual(result.tool_calls[-1]["status"], "complete")

        graph_summary = graph.get_summary()
        self.assertEqual(graph_summary["total_nodes"], 1)
        self.assertIn("function", graph_summary["node_types"])

if __name__ == "__main__":  # pragma: no cover
    unittest.main()
