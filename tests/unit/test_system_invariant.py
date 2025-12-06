"""s for SystemInvariantAnalyst - refactored for new API."""

import unittest
from unittest.mock import MagicMock, patch
from src.research.system_invariant import SystemInvariantAnalyst
from src.research.base_specialist import EnhancedAnalysisResult
from src.research.memory import Discovery
from src.kb.project_graph import ProjectKnowledgeGraph

class TestSystemInvariantAnalyst(unittest.TestCase):
    def setUp(self):
        self.pkg = MagicMock(spec=ProjectKnowledgeGraph)
        self.pkg.contracts = {"A": MagicMock(), "B": MagicMock()}
        self.backend = MagicMock()
        self.mock_response = MagicMock()
        self.mock_response.text = "[]"
        self.mock_response.cost = 0.001

        self.analyst = SystemInvariantAnalyst(self.pkg, backend=self.backend)

    def test_analyze_system_detects_cycles(self):
        self.pkg.find_cycles.return_value = [["A:func1", "B:func2", "A:func1"]]
        self.pkg.find_central_nodes.return_value = [("A:func1", 0.5)]
        self.pkg.to_dict.return_value = {"nodes": [], "edges": []}
        self.backend.generate.return_value = self.mock_response

        results = self.analyst.analyze_system()
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(type(result).__name__, "EnhancedAnalysisResult")
        self.assertEqual(len(result.discoveries), 1)

        discovery = result.discoveries[0]
        self.assertEqual(type(discovery).__name__, "Discovery")
        self.assertEqual(discovery.discovery_type, "vulnerability")
        self.assertIn("Circular Dependency Detected", discovery.content)
        self.assertEqual(discovery.confidence, 0.8)
        self.assertTrue(any("A:func1" in e for e in discovery.evidence))

    def test_analyze_system_llm_findings(self):
        self.pkg.find_cycles.return_value = []
        self.pkg.find_central_nodes.return_value = []
        self.pkg.to_dict.return_value = {"nodes": [], "edges": []}
        self.mock_response.text = """
        [
            {
                "title": "Trust Boundary Violation",
                "description": "Contract A trusts B but B is upgradeable.",
                "severity": "High",
                "affected_contracts": ["A", "B"]
            }
        ]
        """
        self.backend.generate.return_value = self.mock_response

        results = self.analyst.analyze_system()

        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(len(result.discoveries), 1)

        discovery = result.discoveries[0]
        self.assertIn("Trust Boundary Violation", discovery.content)
        self.assertEqual(discovery.discovery_type, "vulnerability")
        self.assertEqual(discovery.confidence, 0.9)  # high severity maps to 0.9
        self.assertTrue(any("A" in e for e in discovery.evidence))

    def test_analyze_system_handles_llm_error(self):
        self.pkg.find_cycles.return_value = []
        self.pkg.find_central_nodes.return_value = []
        self.pkg.to_dict.return_value = {"nodes": [], "edges": []}
        self.backend.generate.side_effect = Exception("LLM API error")

        results = self.analyst.analyze_system()
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(len(result.discoveries), 0)
        self.assertTrue(result.analysis_complete)

    def test_analyze_system_filters_self_loops(self):
        self.pkg.find_cycles.return_value = [["A"]]  # self-loop
        self.pkg.find_central_nodes.return_value = []
        self.pkg.to_dict.return_value = {"nodes": [], "edges": []}

        self.backend.generate.return_value = self.mock_response

        results = self.analyst.analyze_system()

        # self-loop should be filtered out
        self.assertEqual(len(results[0].discoveries), 0)

    def test_result_metadata(self):
        self.pkg.find_cycles.return_value = []
        self.pkg.find_central_nodes.return_value = []
        self.pkg.to_dict.return_value = {"nodes": [], "edges": []}

        self.backend.generate.return_value = self.mock_response

        results = self.analyst.analyze_system()
        result = results[0]

        self.assertIn("cross_contract_calls", result.areas_covered)
        self.assertIn("circular_dependencies", result.areas_covered)
        self.assertTrue(result.analysis_complete)
        self.assertGreater(result.confidence, 0)

if __name__ == '__main__':
    unittest.main()
