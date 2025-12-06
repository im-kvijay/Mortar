"""task scheduler for parallel auditing"""

import networkx as nx
from typing import List, Set, Dict, Any

class TaskScheduler:
    """schedules audits based on dependencies"""

    def __init__(self, dependency_graph: nx.DiGraph):
        self.graph = dependency_graph

    def get_execution_batches(self) -> List[List[str]]:
        """returns batches for parallel execution"""
        graph = self.graph.copy()
        batches = []

        while graph.number_of_nodes() > 0:
            current_batch = [n for n in graph.nodes if graph.in_degree(n) == 0]

            if not current_batch:
                node_to_break = min(graph.nodes, key=lambda n: graph.in_degree(n))
                current_batch = [node_to_break]
                print(f"[scheduler] cycle detected, breaking at {node_to_break}")

            batches.append(current_batch)
            graph.remove_nodes_from(current_batch)

        return batches

    def estimate_parallelism(self) -> float:
        batches = self.get_execution_batches()
        if not batches:
            return 0.0
        return sum(len(b) for b in batches) / len(batches)
