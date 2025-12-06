"""mortar code graph (mcg): builds multi-relational graphs from solidity with k-hop slicing and community detection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, Any

import networkx as nx
from networkx.algorithms import community

@dataclass
class CodeGraphSlice:
    nodes: List[str]
    edges: List[Tuple[str, str, str]]
    metadata: Dict[str, str]
    invariants: List[str] = None

class CodeGraph:
    def __init__(self, contract_name: str):
        self.contract_name = contract_name
        self.graph = nx.MultiDiGraph()
        self._state_vars: Set[str] = set()
        self._functions: Set[str] = set()
        self._taint_edges: List[Tuple[str, str, str]] = []
        self._slither_calls: List[Tuple[str, str]] = []
        self._slither_reads: List[Tuple[str, str]] = []
        self._slither_writes: List[Tuple[str, str]] = []
        self._communities: List[List[str]] = []

    def build(self, source: str, slither: Optional[Dict[str, Any]] = None) -> None:
        self._taint_edges = []
        self._state_vars = self._extract_state_vars(source)
        self._functions = self._extract_functions(source)
        if slither:
            self._ingest_slither(slither)
        self._add_state_nodes()
        self._add_function_nodes()
        self._add_read_write_edges(source)
        self._add_call_edges(source)

    def slice(self, center: str, hops: int = 2, max_nodes: int = 40) -> CodeGraphSlice:
        """return a k-hop ego graph slice around `center`."""
        if center not in self.graph:
            return CodeGraphSlice(nodes=[], edges=[], metadata={"center": center, "hops": str(hops)})

        ego = nx.ego_graph(self.graph, center, radius=hops, undirected=False)
        if len(ego) > max_nodes:
            # prune by degree
            nodes_by_deg = sorted(ego.degree, key=lambda x: x[1], reverse=True)[:max_nodes]
            keep = {n for n, _ in nodes_by_deg}
            ego = ego.subgraph(keep).copy()

        edges = [(u, v, d.get("type", "")) for u, v, d in ego.edges(data=True)]
        invariants = [
            n
            for n in ego.nodes
            if self.graph.nodes[n].get("type") == "invariant"
        ]
        return CodeGraphSlice(
            nodes=list(ego.nodes),
            edges=edges,
            metadata={"center": center, "hops": str(hops), "max_nodes": str(max_nodes)},
            invariants=invariants,
        )

    def graph_communities(self, max_communities: int = 4, max_nodes: int = 40) -> List[CodeGraphSlice]:
        """derive communities over the code graph using greedy modularity."""
        if self.graph.number_of_nodes() == 0:
            return []
        try:
            comms_iter = community.greedy_modularity_communities(self.graph.to_undirected())
            comms = [list(sorted(c)) for c in comms_iter]
        except Exception:
            comms = [list(c) for c in nx.weakly_connected_components(self.graph)]

        slices: List[CodeGraphSlice] = []
        for idx, nodes in enumerate(comms[:max_communities]):
            sub = self.graph.subgraph(nodes).copy()
            if len(sub) > max_nodes:
                nodes_by_deg = sorted(sub.degree, key=lambda x: x[1], reverse=True)[:max_nodes]
                keep = {n for n, _ in nodes_by_deg}
                sub = sub.subgraph(keep).copy()
            edges = [(u, v, d.get("type", "")) for u, v, d in sub.edges(data=True)]
            invariants = [n for n in sub.nodes if sub.nodes[n].get("type") == "invariant"]
            slices.append(
                CodeGraphSlice(
                    nodes=list(sub.nodes),
                    edges=edges,
                    metadata={"community": str(idx), "size": str(len(sub.nodes))},
                    invariants=invariants,
                )
            )
        self._communities = [s.nodes for s in slices]
        return slices

    def add_taint_traces(self, traces: List[Dict[str, Any]]) -> None:
        """add taint edges (source function -> external sink) into the graph."""
        for trace in traces:
            src = trace.get("source")
            sink_label = trace.get("resolved_target") or trace.get("sink")
            if not src or not sink_label:
                continue
            target_contract = self.contract_name
            target_fn = sink_label
            if "." in sink_label:
                parts = sink_label.split(".", 1)
                if len(parts) == 2 and parts[0]:
                    target_contract = parts[0]
                    target_fn = parts[1]
            fn_node = f"fn::{src}"
            sink_node = f"{target_contract}::call::{target_fn}"
            self.graph.add_node(fn_node, type="function", label=src)
            self.graph.add_node(sink_node, type="dependency", label=sink_label)
            self.graph.add_edge(
                fn_node,
                sink_node,
                type="taint_flow",
                line=trace.get("line"),
                taint=True,
                target_contract=target_contract if target_contract != self.contract_name else None,
            )
            self._taint_edges.append((fn_node, sink_node, sink_label))

    def to_dict(self) -> Dict:
        return {
            "contract": self.contract_name,
            "nodes": [{**self.graph.nodes[n], "id": n} for n in self.graph.nodes],
            "edges": [
                {"source": u, "target": v, **data} for u, v, data in self.graph.edges(data=True)
            ],
            "metadata": {
                "state_vars": list(self._state_vars),
                "functions": list(self._functions),
                "taint_edges": len(self._taint_edges),
                "communities": len(self._communities),
            },
        }

    def to_dot(self) -> str:
        try:
            from networkx.drawing.nx_pydot import to_pydot

            return to_pydot(self.graph).to_string()
        except Exception:
            return ""

    def _ingest_slither(self, slither: Dict[str, Any]) -> None:
        """ingest slither json to improve call/read/write fidelity."""
        try:
            for contract in slither.get("contracts", []):
                if contract.get("name") != self.contract_name:
                    continue
                for fn_obj in contract.get("functions", []):
                    fn_name = fn_obj.get("name")
                    if not fn_name:
                        continue
                    # calls
                    for call in fn_obj.get("calls", []):
                        callee = call.get("name") or call if isinstance(call, str) else None
                        if callee:
                            self._slither_calls.append((fn_name, callee))
                    # reads
                    for sv in fn_obj.get("stateVariablesRead", []):
                        sv_name = sv.get("name") or sv if isinstance(sv, str) else None
                        if sv_name:
                            self._slither_reads.append((fn_name, sv_name))
                            self._state_vars.add(sv_name)
                    # writes
                    for sv in fn_obj.get("stateVariablesWritten", []):
                        sv_name = sv.get("name") or sv if isinstance(sv, str) else None
                        if sv_name:
                            self._slither_writes.append((fn_name, sv_name))
                            self._state_vars.add(sv_name)
        except Exception:
            # best-effort; fall back to regex heuristics
            self._slither_calls = []
            self._slither_reads = []
            self._slither_writes = []

    def _add_state_nodes(self) -> None:
        for sv in self._state_vars:
            self.graph.add_node(f"state::{sv}", type="state_var", label=sv)
        # add basic invariants based on common patterns
        for inv in self._derive_invariants():
            node_id = f"invariant::{inv}"
            self.graph.add_node(node_id, type="invariant", label=inv)
            # link invariants to referenced state variables
            for sv in self._state_vars:
                if sv in inv:
                    self.graph.add_edge(node_id, f"state::{sv}", type="depends_on")

    def _add_function_nodes(self) -> None:
        for fn in self._functions:
            self.graph.add_node(f"fn::{fn}", type="function", label=fn)

    def _extract_state_vars(self, source: str) -> Set[str]:
        vars_found: Set[str] = set()
        pattern = re.compile(
            r"(?P<type>bytes\d*|uint\d*|int\d*|bool|address|string|mapping\s*\([^)]+\)|[A-Za-z_][A-Za-z0-9_]*)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;",
            re.MULTILINE,
        )
        for match in pattern.finditer(source):
            name = match.group("name")
            if name not in {"contract", "interface", "library"}:
                vars_found.add(name)
        return vars_found

    def _extract_functions(self, source: str) -> Set[str]:
        fns: Set[str] = set()
        pattern = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\b")
        for match in pattern.finditer(source):
            fns.add(match.group(1))
        return fns

    def _find_enclosing_fn(self, source: str, pos: int) -> Optional[str]:
        pre = source[:pos]
        matches = list(re.finditer(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\b", pre))
        if matches:
            return matches[-1].group(1)
        return None

    def _derive_invariants(self) -> List[str]:
        """derive simple invariants from known state variable patterns."""
        invariants: List[str] = []
        lowers = {sv.lower(): sv for sv in self._state_vars}
        # paused flags
        for name in self._state_vars:
            if "pause" in name.lower():
                invariants.append(f"!{name}")
        # supply/asset caps
        if any("cap" in n for n in lowers):
            cap_var = next(v for k, v in lowers.items() if "cap" in k)
            if "total" in lowers:
                invariants.append(f"total <= {cap_var}")
            for name in self._state_vars:
                if "supply" in name.lower():
                    invariants.append(f"{name} <= {cap_var}")
        # assets vs debt/balance
        assets = [v for k, v in lowers.items() if "assets" in k or "balance" in k]
        debt = [v for k, v in lowers.items() if "debt" in k or "liability" in k]
        for a in assets:
            for d in debt:
                invariants.append(f"{a} >= {d}")
        return list(dict.fromkeys(invariants))  # de-dupe preserving order

    def _add_read_write_edges(self, source: str) -> None:
        if not self._state_vars:
            return
        if self._slither_reads or self._slither_writes:
            for fn, sv in self._slither_reads:
                if fn and sv:
                    self.graph.add_edge(f"fn::{fn}", f"state::{sv}", type="reads")
            for fn, sv in self._slither_writes:
                if fn and sv:
                    self.graph.add_edge(f"fn::{fn}", f"state::{sv}", type="writes")
            return
        for sv in self._state_vars:
            # writes
            write_patterns = [
                rf"\b{sv}\b\s*=",
                rf"\b{sv}\b\s*\+=",
                rf"\b{sv}\b\s*-=",
                rf"\b{sv}\b\s*\*\=",
                rf"\b{sv}\b\s*/=",
                rf"\b{sv}\b\+\+",
                rf"\b{sv}\b--",
            ]
            for pat in write_patterns:
                for m in re.finditer(pat, source):
                    fn = self._find_enclosing_fn(source, m.start())
                    if fn:
                        fn_node = f"fn::{fn}"
                        sv_node = f"state::{sv}"
                        self.graph.add_edge(fn_node, sv_node, type="writes")
            # reads (exclude writes)
            for m in re.finditer(rf"\b{sv}\b", source):
                # skip writes by checking surrounding text
                window = source[max(0, m.start() - 4) : m.start() + 4]
                if re.search(r"(=|\+=|-=|\*=|/=|\+\+|--)", window):
                    continue
                fn = self._find_enclosing_fn(source, m.start())
                if fn:
                    fn_node = f"fn::{fn}"
                    sv_node = f"state::{sv}"
                    self.graph.add_edge(fn_node, sv_node, type="reads")

    def _add_call_edges(self, source: str) -> None:
        if self._slither_calls:
            for caller, callee in self._slither_calls:
                caller_node = f"fn::{caller}"
                if callee in self._functions:
                    callee_node = f"fn::{callee}"
                    self.graph.add_edge(caller_node, callee_node, type="calls_internal")
                else:
                    sink_node = f"dep::{callee}"
                    if sink_node not in self.graph:
                        self.graph.add_node(sink_node, type="dependency", label=callee)
                    self.graph.add_edge(caller_node, sink_node, type="calls_external")
            return

        call_pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
        for match in call_pattern.finditer(source):
            callee = match.group(1)
            fn = self._find_enclosing_fn(source, match.start())
            if not fn:
                continue
            caller_node = f"fn::{fn}"
            if callee in self._functions:
                callee_node = f"fn::{callee}"
                self.graph.add_edge(caller_node, callee_node, type="calls_internal")
            else:
                sink_node = f"dep::{callee}"
                if sink_node not in self.graph:
                    self.graph.add_node(sink_node, type="dependency", label=callee)
                self.graph.add_edge(caller_node, sink_node, type="calls_external")
