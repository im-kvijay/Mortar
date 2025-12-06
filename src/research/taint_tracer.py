"""taint tracer - maps entrypoints to external sinks across contracts."""
from __future__ import annotations

import re
from typing import List, Dict, Optional, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from kb.project_graph import ProjectKnowledgeGraph

SINK_PATTERNS = [
    r"\.call\s*\(",
    r"\.call\{",  # new-style
    r"\.delegatecall\s*\(",
    r"\.staticcall\s*\(",
    r"\.transfer\s*\(",
    r"\.send\s*\(",
]


def trace_taint_paths(contract_source: str, abi_map: Optional[Dict[str, str]] = None, contract_name: str = "") -> List[Dict[str, str]]:
    traces: List[Dict[str, str]] = []
    lines = contract_source.splitlines()
    current_fn = None
    current_visibility = None
    # Precompute simple contract.function call matches to improve target resolution
    qualified_call = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for idx, line in enumerate(lines, start=1):
        fn_match = re.search(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*(public|external)", line)
        if fn_match:
            current_fn = fn_match.group(1)
            current_visibility = fn_match.group(2)
            continue
        if not current_fn:
            continue
        if "function " in line:
            current_fn = None
            current_visibility = None
            continue
        resolved_target = None
        qual = qualified_call.search(line)
        if qual:
            resolved_target = f"{qual.group(1)}.{qual.group(2)}"
        for pattern in SINK_PATTERNS:
            if re.search(pattern, line):
                sink = line.strip()
                selector_match = re.search(r"([a-fA-F0-9]{8})", sink)
                if not resolved_target and abi_map and selector_match:
                    selector = selector_match.group(1)
                    resolved_target = abi_map.get(selector)
                traces.append({
                    "source": current_fn,
                    "visibility": current_visibility or "unknown",
                    "sink": sink,
                    "resolved_target": resolved_target,
                    "line": idx,
                    "contract": contract_name or "unknown"
                })
    return traces


def trace_cross_contract_taint(
    contract_name: str,
    source_function: str,
    project_graph: "ProjectKnowledgeGraph",
    visited: Optional[set] = None
) -> List[Dict[str, Any]]:
    """trace taint flow across contract boundaries using project knowledge graph."""
    if visited is None:
        visited = set()

    current_node = (contract_name, source_function)
    if current_node in visited:
        return []
    visited.add(current_node)

    cross_contract_paths = []
    source_node_id = f"{contract_name}:{source_function}"

    for u, v, data in project_graph.graph.edges(data=True):
        if u.startswith(f"{contract_name}:") and data.get("relation") == "external_call":
            target_contract = data.get("metadata", {}).get("target_contract")
            target_function = data.get("metadata", {}).get("target_function")

            if not target_contract or not target_function:
                if ":" in v:
                    target_contract = v.split(":")[0]
                    target_function = v.split(":")[-1]

            if target_contract and target_function:
                path_entry = {
                    "source_contract": contract_name,
                    "source_function": source_function,
                    "target_contract": target_contract,
                    "target_function": target_function,
                    "call_type": data.get("metadata", {}).get("call_type", "unknown"),
                    "edge_data": data
                }
                cross_contract_paths.append(path_entry)

                downstream_paths = trace_cross_contract_taint(
                    contract_name=target_contract,
                    source_function=target_function,
                    project_graph=project_graph,
                    visited=visited
                )

                for downstream in downstream_paths:
                    chained_path = {
                        **path_entry,
                        "downstream": downstream
                    }
                    cross_contract_paths.append(chained_path)

    return cross_contract_paths
