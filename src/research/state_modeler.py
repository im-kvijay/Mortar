"""state modeler - extracts state variables and transitions using regex."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Any

from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType


@dataclass
class StateVariable:
    name: str
    var_type: str
    visibility: str


class StateModeler:
    def __init__(self, discovered_by: str = "state_modeler"):
        self.discovered_by = discovered_by

    def analyze(self, contract_name: str, contract_source: str, knowledge_graph: KnowledgeGraph) -> Dict[str, Any]:
        """extract state variables and function -> state transitions."""
        state_vars = self._extract_state_vars(contract_source)
        transitions = self._extract_transitions(contract_source, state_vars)

        for var in state_vars:
            node_id = f"state::{var.name}"
            knowledge_graph.add_node(
                node_id=node_id,
                node_type=NodeType.STATE_VAR,
                name=var.name,
                data={"type": var.var_type, "visibility": var.visibility},
                discovered_by=self.discovered_by,
                metadata={"component": "state_model"},
            )

        for fn_name, writes in transitions.items():
            fn_node_id = f"fn::{fn_name}"
            if not knowledge_graph.get_node(fn_node_id):
                knowledge_graph.add_node(
                    node_id=fn_node_id,
                    node_type=NodeType.FUNCTION,
                    name=fn_name,
                    data={},
                    discovered_by=self.discovered_by,
                    metadata={"component": "state_model"},
                )
            for var_name in writes:
                var_node_id = f"state::{var_name}"
                if knowledge_graph.get_node(var_node_id):
                    knowledge_graph.add_edge(
                        source=fn_node_id,
                        target=var_node_id,
                        edge_type=EdgeType.MODIFIES,
                        data={"reason": "assignment"},
                        discovered_by=self.discovered_by,
                        metadata={"component": "state_model"},
                    )

        return {"state_vars": [v.name for v in state_vars], "transitions": transitions}

    def _extract_state_vars(self, source: str) -> List[StateVariable]:
        """parse state variables using regex, skip function params/local vars."""
        vars_found: List[StateVariable] = []
        pattern = re.compile(r"(?P<visibility>public|private|internal|external)?\s*(?P<type>bytes\d*|uint\d*|int\d*|bool|address|string|mapping\s*\([^)]+\)|[A-Za-z_][A-Za-z0-9_]*)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;", re.MULTILINE)
        for line in source.splitlines():
            if "function" in line:
                continue
            match = pattern.search(line)
            if not match:
                continue
            visibility = match.group("visibility") or "internal"
            var_type = match.group("type")
            name = match.group("name")
            vars_found.append(StateVariable(name=name, var_type=var_type, visibility=visibility))
        return vars_found

    def _extract_transitions(self, source: str, state_vars: List[StateVariable]) -> Dict[str, List[str]]:
        """map functions to state variables they assign to (pattern: var =)."""
        transitions: Dict[str, List[str]] = {}
        fn_pattern = re.compile(r"function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
        current_fn = None
        var_names = [v.name for v in state_vars]

        for line in source.splitlines():
            fn_match = fn_pattern.search(line)
            if fn_match:
                current_fn = fn_match.group("name")
                continue
            if not current_fn:
                continue
            for var in var_names:
                if re.search(rf"\b{re.escape(var)}\s*=", line):
                    transitions.setdefault(current_fn, []).append(var)
        return transitions
