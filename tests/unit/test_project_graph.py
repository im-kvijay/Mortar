
import unittest
from unittest.mock import MagicMock
from src.kb.project_graph import ProjectKnowledgeGraph
from src.models.findings import ContractInterfaceSummary

class TestProjectKnowledgeGraph(unittest.TestCase):
    def setUp(self):
        self.pkg = ProjectKnowledgeGraph("TestProject")

    def test_add_contract_node(self):
        summary = ContractInterfaceSummary(
            name="Vault",
            file_path="src/Vault.sol",
            purpose="Holds funds",
            external_api=["deposit()", "withdraw()"],
            state_variables=["balances"],
            dependencies=["Token"],
            trust_assumptions=[]
        )
        
        self.pkg.add_contract_node("Vault", summary)
        # node id format: "vault:contract_def"
        self.assertTrue(self.pkg.graph.has_node("Vault:contract_def"))
        data = self.pkg.graph.nodes["Vault:contract_def"]
        self.assertEqual(data["type"], "contract_def")
        self.assertEqual(data["file_path"], "src/Vault.sol")

    def test_add_cross_contract_edge(self):
        self.pkg.graph.add_node("Vault:Contract")
        self.pkg.graph.add_node("Token:Contract")
        
        self.pkg.add_cross_contract_edge("Vault", "Contract", "Token", "Contract", "calls")
        
        self.assertTrue(self.pkg.graph.has_edge("Vault:Contract", "Token:Contract"))
        
        # multidigraph edge access
        edges = self.pkg.graph.get_edge_data("Vault:Contract", "Token:Contract")
        self.assertIsNotNone(edges)
        
        found = False
        for key, data in edges.items():
            if data["type"] == "cross_contract" and data["relation"] == "calls":
                found = True
                break
        self.assertTrue(found)

    def test_graph_analysis(self):
        # create a cycle: a -> b -> a
        summary_a = MagicMock()
        summary_a.name = "A"
        summary_b = MagicMock()
        summary_b.name = "B"
        
        self.pkg.add_contract_node("A", summary_a)
        self.pkg.add_contract_node("B", summary_b)
        
        self.pkg.add_cross_contract_edge("A", "contract_def", "B", "contract_def", "calls")
        self.pkg.add_cross_contract_edge("B", "contract_def", "A", "contract_def", "calls")
        
        cycles = self.pkg.find_cycles()
        # cycle should be detected (e.g. [['A:contract_def', 'B:contract_def']])
        self.assertTrue(len(cycles) > 0)
        
        central = self.pkg.find_central_nodes()
        self.assertTrue(len(central) > 0)
        self.assertTrue(len(central) > 0)
        self.assertEqual(central[0][0], "A:contract_def") # or b, depending on pagerank stability

    def test_advanced_queries(self):
        # setup graph for trace_flow
        summary_a = MagicMock()
        summary_a.name = "A"
        summary_b = MagicMock()
        summary_b.name = "B"
        summary_c = MagicMock()
        summary_c.name = "C"
        
        self.pkg.add_contract_node("A", summary_a)
        self.pkg.add_contract_node("B", summary_b)
        self.pkg.add_contract_node("C", summary_c)
        
        self.pkg.add_cross_contract_edge("A", "contract_def", "B", "contract_def", "calls")
        self.pkg.add_cross_contract_edge("B", "contract_def", "C", "contract_def", "calls")
        paths = self.pkg.query_system("trace_flow", start_node="A:contract_def", end_node="C:contract_def")
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0], ["A:contract_def", "B:contract_def", "C:contract_def"])
        # add edge to specific function node manually since add_cross_contract_edge assumes contract nodes mostly
        # but add_cross_contract_edge allows specifying nodes.
        self.pkg.graph.add_node("B:deposit", type="function", contract="B")
        self.pkg.add_cross_contract_edge("A", "contract_def", "B", "deposit", "calls")
        
        usages = self.pkg.query_system("find_usage", signature="deposit")
        self.assertEqual(len(usages), 1)
        self.assertEqual(usages[0]["target"], "B:deposit")

if __name__ == '__main__':
    unittest.main()
