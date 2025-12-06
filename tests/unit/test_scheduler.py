
import unittest
import networkx as nx
from src.cal.scheduler import TaskScheduler

class TestTaskScheduler(unittest.TestCase):
    def setUp(self):
        self.graph = nx.DiGraph()

    def test_simple_linear_dependency(self):
        # a -> b -> c
        # b depends on a. C depends on B.
        # edges in dependency graph: (a, b), (b, c) ?
        # wait, if b depends on a, does the edge go a->b or b->a?
        # in projectscanner: self.graph.add_edge(dep, contract.name)
        # so if b imports a, edge is a -> b.
        # topological sort: a comes first.
        # scheduler (kahn's): nodes with in-degree 0 first.
        # a has in-degree 0. B has 1 (from A).
        
        self.graph.add_edge("A", "B")
        self.graph.add_edge("B", "C")
        
        scheduler = TaskScheduler(self.graph)
        batches = scheduler.get_execution_batches()
        
        self.assertEqual(len(batches), 3)
        self.assertEqual(batches[0], ["A"])
        self.assertEqual(batches[1], ["B"])
        self.assertEqual(batches[2], ["C"])

    def test_branching_dependency(self):
        # a -> b, a -> c
        # b and c depend on a.
        self.graph.add_edge("A", "B")
        self.graph.add_edge("A", "C")
        
        scheduler = TaskScheduler(self.graph)
        batches = scheduler.get_execution_batches()
        
        self.assertEqual(len(batches), 2)
        self.assertEqual(batches[0], ["A"])
        self.assertCountEqual(batches[1], ["B", "C"]) # order doesn't matter in batch

    def test_independent_components(self):
        # a -> b
        # c -> d
        self.graph.add_edge("A", "B")
        self.graph.add_edge("C", "D")
        
        scheduler = TaskScheduler(self.graph)
        batches = scheduler.get_execution_batches()
        
        self.assertEqual(len(batches), 2)
        self.assertCountEqual(batches[0], ["A", "C"])
        self.assertCountEqual(batches[1], ["B", "D"])

    def test_cycle_handling(self):
        # a -> b -> a (cycle)
        self.graph.add_edge("A", "B")
        self.graph.add_edge("B", "A")
        
        scheduler = TaskScheduler(self.graph)
        batches = scheduler.get_execution_batches()
        # if a broken: batch 1: [a], batch 2: [b]
        # if b broken: batch 1: [b], batch 2: [a]
        self.assertEqual(len(batches), 2)
        
        flat = [item for sublist in batches for item in sublist]
        self.assertCountEqual(flat, ["A", "B"])

if __name__ == '__main__':
    unittest.main()
