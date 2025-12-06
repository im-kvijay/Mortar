"""
InvariantExpander: derive invariants from state model and taint/dependency info.
"""
from __future__ import annotations

from typing import Dict, List
from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType


class InvariantExpander:
    def __init__(self, discovered_by: str = "invariant_expander"):
        self.discovered_by = discovered_by

    def add_invariants(
        self,
        contract_info: Dict[str, any],
        knowledge_graph: KnowledgeGraph,
    ) -> List[str]:
        invariants: List[str] = []
        # Pausable guard
        state_vars = contract_info.get("state_vars", [])
        if any("paused" == sv or "pause" in sv.lower() for sv in state_vars):
            invariants.append("paused == false")
        # Supply caps
        if any("maxSupply" in sv or "cap" in sv.lower() for sv in state_vars):
            invariants.append("totalSupply <= cap")
        # Debt/asset balance consistency
        if any("totalDebt" in sv or "totalAssets" in sv for sv in state_vars):
            invariants.append("totalAssets >= totalDebt")

        for inv in invariants:
            node_id = f"invariant::{inv}"
            knowledge_graph.add_node(
                node_id=node_id,
                node_type=NodeType.INVARIANT,
                name=inv,
                data={"source": "expander"},
                discovered_by=self.discovered_by,
                metadata={"component": "invariant"},
            )
            # Link invariants to state vars they reference
            for sv in state_vars:
                if sv in inv:
                    sv_node = f"state::{sv}"
                    if not knowledge_graph.get_node(sv_node):
                        knowledge_graph.add_node(
                            node_id=sv_node,
                            node_type=NodeType.STATE_VAR,
                            name=sv,
                            data={},
                            discovered_by=self.discovered_by,
                            metadata={"component": "invariant"},
                        )
                    knowledge_graph.add_edge(
                        source=node_id,
                        target=sv_node,
                        edge_type=EdgeType.DEPENDS_ON,
                        data={"source": "expander"},
                        discovered_by=self.discovered_by,
                        metadata={"component": "invariant"},
                    )
        contract_info["invariants"] = invariants
        return invariants
