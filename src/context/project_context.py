import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
import networkx as nx
from config import config

@dataclass
class FunctionNode:
    name: str
    signature: str
    code: str
    start_line: int
    end_line: int
    modifiers: List[str]
    visibility: str
    mutability: str
    docstring: str = ""

@dataclass
class StateVarNode:
    name: str
    type: str
    visibility: str
    is_immutable: bool
    is_constant: bool
    line: int

@dataclass
class ContractNode:
    name: str
    file_path: str
    code: str
    kind: str  # contract, interface, library, abstract
    inheritance: List[str]
    imports: List[str]
    functions: Dict[str, FunctionNode] = field(default_factory=dict)
    state_vars: Dict[str, StateVarNode] = field(default_factory=dict)
    dependencies: Set[str] = field(default_factory=set)  # Resolved contract names
    docstring: str = ""

class ProjectContext:
    def __init__(self, project_root: str, semantic_backend: Optional[str] = None):
        self.project_root = Path(project_root)
        self.contracts: Dict[str, ContractNode] = {}
        self.files_map: Dict[str, str] = {}  # path -> contract_name
        self.graphs: Dict[str, nx.MultiDiGraph] = {}
        self.system_graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self.taint_paths: List[Dict[str, Any]] = []

        # Initialize Semantic Search
        from src.context.semantic_search import SemanticSearch

        self.semantic_backend = (semantic_backend or config.SEMANTIC_BACKEND).lower()
        self.semantic_search = SemanticSearch(
            backend_preference=self.semantic_backend,
            persist_dir=config.SEMANTIC_CACHE_DIR,
        )

        self.is_indexed = False

    def index_workspace(self):
        print(f"[ProjectContext] Indexing workspace: {self.project_root}")
        sol_files = []
        skip_dirs = {"lib", "node_modules", "test", "tests", "script"}
        for root, _, files in os.walk(self.project_root):
            root_parts = set(Path(root).parts)
            if root_parts & skip_dirs:
                continue
            for file in files:
                if file.endswith(".sol"):
                    sol_files.append(os.path.join(root, file))
        for file_path in sol_files:
            self._parse_file(file_path)
        self._resolve_dependencies()
        self._index_semantic_search()
        self.is_indexed = True
        print(f"[ProjectContext] Indexed {len(self.contracts)} contracts")

    def _index_semantic_search(self):
        docs: List[str] = []
        metadatas: List[Dict[str, Any]] = []
        existing_keys = {
            (m.get("type"), m.get("contract"), m.get("name"))
            for m in self.semantic_search.metadatas
        }

        for contract_name, node in self.contracts.items():
            for func_name, func in node.functions.items():
                doc = f"Function {func_name} in {contract_name}. Signature: {func.signature}. {func.code}"
                meta = {
                    "type": "function",
                    "contract": contract_name,
                    "name": func_name,
                    "signature": func.signature
                }
                key = (meta["type"], meta["contract"], meta["name"])
                if key in existing_keys:
                    continue
                docs.append(doc)
                metadatas.append(meta)
                existing_keys.add(key)
            for var_name, var in node.state_vars.items():
                doc = f"State Variable {var_name} in {contract_name}. Type: {var.type}. Visibility: {var.visibility}."
                meta = {
                    "type": "state_var",
                    "contract": contract_name,
                    "name": var_name
                }
                key = (meta["type"], meta["contract"], meta["name"])
                if key in existing_keys:
                    continue
                docs.append(doc)
                metadatas.append(meta)
                existing_keys.add(key)
        if docs:
            self.semantic_search.add_documents(docs, metadatas)
            print(f"[ProjectContext] Added {len(docs)} items to semantic search")
        summaries = self._collect_community_summaries()
        if summaries:
            summary_docs = [s["text"] for s in summaries]
            summary_meta = [s["meta"] for s in summaries]
            self.semantic_search.add_documents(summary_docs, summary_meta)
            print(f"[ProjectContext] Added {len(summary_docs)} community summaries to semantic search")

    def get_relevant_code(self, query: str, budget: int = 2000, structured: bool = False):
        if not self.is_indexed:
            self.index_workspace()

        results = self.semantic_search.search(query, top_k=config.SEMANTIC_TOP_K)

        response = [f"// Relevant code for query: '{query}'\n"]
        structured_payload: List[Dict[str, Any]] = []
        current_tokens = 0

        for res in results:
            content_len = len(res.content)
            tokens = max(1, content_len // 4)
            if current_tokens + tokens > budget:
                break

            snippet = {
                "score": res.score,
                "metadata": res.metadata,
                "content": res.content,
            }

            if structured:
                structured_payload.append(snippet)
            else:
                response.append(f"// Score: {res.score:.2f}")
                if res.metadata.get("type") == "function":
                    contract = self.contracts.get(res.metadata.get("contract", ""))
                    func = contract.functions.get(res.metadata.get("name", "")) if contract else None
                    response.append(f"// Contract: {res.metadata.get('contract', 'unknown')}")
                    if func:
                        response.append(f"{func.signature} {{ ... }}")
                    else:
                        response.append(res.content)
                else:
                    response.append(res.content)
                response.append("")
            current_tokens += tokens

        if structured:
            return {"query": query, "payload": structured_payload, "used_tokens": current_tokens}
        return {"query": query, "text": "\n".join(response), "used_tokens": current_tokens}

    def _parse_file(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"[ProjectContext] Error reading {file_path}: {e}")
            return
        contract_pattern = r'(contract|interface|library|abstract\s+contract)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{'
        matches = list(re.finditer(contract_pattern, content))
        for i, match in enumerate(matches):
            kind_full = match.group(1)
            kind = kind_full.split()[-1]
            name = match.group(2)
            inheritance_str = match.group(3)
            
            inheritance = []
            if inheritance_str:
                inheritance = [x.strip() for x in inheritance_str.split(',')]
            start_idx = match.start()
            end_idx = self._find_closing_brace(content, match.end() - 1)
            contract_code = content[start_idx:end_idx+1]

            imports = [imp.strip() for imp in re.findall(r'import\s+["\']([^"\']+)["\']\s*;', content)]
            node = ContractNode(
                name=name,
                file_path=file_path,
                code=contract_code,
                kind=kind,
                inheritance=inheritance,
                imports=imports
            )
            start_line = content[:start_idx].count("\n")
            self._parse_members(node, line_offset=start_line)
            self.contracts[name] = node
            self.files_map[file_path] = name

    def _parse_members(self, node: ContractNode, line_offset: int = 0):
        var_pattern = r'^\s*([a-zA-Z0-9_\[\]\.]+)\s+(public|private|internal)(?:\s+(constant|immutable))?\s+([a-zA-Z0-9_]+)\s*(?:=.*?)?;'
        for match in re.finditer(var_pattern, node.code, re.MULTILINE):
            type_name = match.group(1)
            visibility = match.group(2)
            modifier = match.group(3)
            name = match.group(4)
            line = node.code[: match.start()].count("\n") + 1 + line_offset
            
            node.state_vars[name] = StateVarNode(
                name=name,
                type=type_name,
                visibility=visibility,
                is_immutable=(modifier == 'immutable'),
                is_constant=(modifier == 'constant'),
                line=line
            )
        func_pattern = r'function\s+(\w+)\s*\((.*?)\)\s*(public|external|internal|private)?\s*(pure|view|payable)?'
        for match in re.finditer(func_pattern, node.code):
            name = match.group(1)
            args = match.group(2)
            visibility = match.group(3) or "public"
            mutability = match.group(4) or "nonpayable"
            fn_start = match.start()
            brace_start = node.code.find("{", match.end())
            fn_end = brace_start if brace_start != -1 else match.end()
            if brace_start != -1:
                try:
                    fn_end = self._find_closing_brace(node.code, brace_start)
                except Exception:
                    fn_end = brace_start
            fn_code = node.code[fn_start:fn_end + 1]
            start_line = node.code[:fn_start].count("\n") + 1 + line_offset
            end_line = node.code[:fn_end].count("\n") + 1 + line_offset
            signature = f"function {name}({args})"
            node.functions[name] = FunctionNode(
                name=name,
                signature=signature,
                code=fn_code,
                start_line=start_line,
                end_line=end_line,
                modifiers=[],
                visibility=visibility,
                mutability=mutability
            )

    def _find_closing_brace(self, content: str, start_idx: int) -> int:
        open_count = 0
        for i in range(start_idx, len(content)):
            if content[i] == '{':
                open_count += 1
            elif content[i] == '}':
                open_count -= 1
                if open_count == 0:
                    return i
        return len(content) - 1

    def _resolve_dependencies(self):
        for name, node in self.contracts.items():
            for parent in node.inheritance:
                if parent in self.contracts:
                    node.dependencies.add(parent)

    def get_system_view(self) -> Dict[str, Any]:
        return {
            "contracts": list(self.contracts.keys()),
            "dependencies": {name: sorted(node.dependencies) for name, node in self.contracts.items()},
            "state_vars": {name: list(node.state_vars.keys()) for name, node in self.contracts.items()},
            "taint_paths": self.taint_paths,
            "graphs": list(self.graphs.keys()),
            "system_metrics": self.analyze_system(),
        }

    def merge_contract_graph(self, contract_name: str, graph: nx.MultiDiGraph) -> None:
        try:
            prefixed = nx.relabel_nodes(graph, lambda n: f"{contract_name}:{n}")
            self.graphs[contract_name] = prefixed
            self.system_graph = nx.compose(self.system_graph, prefixed)
        except Exception:
            self.graphs[contract_name] = graph

    def add_taint_paths(self, contract_name: str, traces: List[Dict[str, Any]]) -> None:
        for trace in traces:
            src_fn = trace.get("source")
            sink_label = trace.get("resolved_target") or trace.get("sink")
            if not src_fn or not sink_label:
                continue
            target_contract = contract_name
            target_fn = sink_label
            if "." in sink_label:
                parts = sink_label.split(".", 1)
                if len(parts) == 2 and parts[0]:
                    target_contract = parts[0]
                    target_fn = parts[1]
            src_node = f"{contract_name}:fn::{src_fn}"
            sink_node = f"{target_contract}:call::{target_fn}"
            self.system_graph.add_node(src_node, type="function", contract=contract_name, label=src_fn)
            self.system_graph.add_node(sink_node, type="dependency", contract=target_contract, label=sink_label)
            self.system_graph.add_edge(
                src_node,
                sink_node,
                type="taint_flow",
                line=trace.get("line"),
                taint=True,
                target_contract=target_contract if target_contract != contract_name else None,
            )
            self.taint_paths.append(
                {
                    "source_contract": contract_name,
                    "source": src_fn,
                    "sink": sink_label,
                    "target_contract": target_contract,
                }
            )

    def analyze_system(self, top_k: int = 5) -> Dict[str, Any]:
        graph = self.system_graph
        if graph.number_of_nodes() == 0:
            return {"cycles": [], "centrality": [], "node_count": 0, "edge_count": 0, "taint_edges": 0}

        try:
            cycles = list(nx.simple_cycles(graph))[:top_k]
        except Exception:
            cycles = []
        try:
            pr = nx.pagerank(graph)
            centrality = sorted(pr.items(), key=lambda x: x[1], reverse=True)[:top_k]
        except Exception:
            centrality = []

        taint_edges = sum(1 for _, _, data in graph.edges(data=True) if data.get("taint"))
        return {
            "cycles": cycles,
            "centrality": centrality,
            "node_count": graph.number_of_nodes(),
            "edge_count": graph.number_of_edges(),
            "taint_edges": taint_edges,
        }

    def system_communities(self, max_communities: int = 4, max_nodes: int = 120) -> List[Dict[str, Any]]:
        graph = self.system_graph
        if graph.number_of_nodes() == 0:
            return []
        try:
            comms_iter = nx.algorithms.community.greedy_modularity_communities(graph.to_undirected())
            comms = [list(sorted(c)) for c in comms_iter]
        except Exception:
            comms = [list(c) for c in nx.weakly_connected_components(graph)]

        slices: List[Dict[str, Any]] = []
        for idx, nodes in enumerate(comms[:max_communities]):
            sub = graph.subgraph(nodes).copy()
            if len(sub) > max_nodes:
                nodes_by_deg = sorted(sub.degree, key=lambda x: x[1], reverse=True)[:max_nodes]
                keep = {n for n, _ in nodes_by_deg}
                sub = sub.subgraph(keep).copy()
            edges = [(u, v, d.get("type", "")) for u, v, d in sub.edges(data=True)]
            slices.append({"community": idx, "nodes": list(sub.nodes), "edges": edges})
        return slices

    def get_semantic_slices(self, contract_name: str, budget: int = 1200) -> List[Dict[str, Any]]:
        if not self.is_indexed:
            self.index_workspace()
        results = self.semantic_search.search(contract_name, top_k=config.SEMANTIC_TOP_K)
        slices: List[Dict[str, Any]] = []
        tokens = 0
        for res in results:
            target = res.metadata.get("contract")
            if target and target != contract_name:
                continue
            token_cost = max(1, len(res.content) // 4)
            if tokens + token_cost > budget:
                break
            slices.append({"score": res.score, "metadata": res.metadata, "content": res.content})
            tokens += token_cost
        return slices

    def _collect_community_summaries(self) -> List[Dict[str, Any]]:
        summaries: List[Dict[str, Any]] = []
        for name, node in self.contracts.items():
            labels: List[str] = []
            labels.extend(node.functions.keys())
            labels.extend(node.state_vars.keys())
            text = f"Contract {name}: " + ", ".join(sorted(labels)[:40])
            summaries.append({"text": text, "meta": {"type": "community", "contract": name, "name": name}})
        return summaries
