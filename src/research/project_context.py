"""project context - hierarchical views for navigating large codebases."""
from __future__ import annotations

from typing import Dict, Optional, Any, List

from src.models.findings import ProjectStructure, ContractInfo
from kb.knowledge_graph import KnowledgeGraph


class ProjectContext:
    """hierarchical context helper for system -> component -> function navigation."""

    def __init__(
        self,
        project: ProjectStructure,
        knowledge_graphs: Optional[Dict[str, KnowledgeGraph]] = None,
    ):
        self.project = project
        self.knowledge_graphs = knowledge_graphs or {}
        self._contracts: Dict[str, ContractInfo] = {c.name: c for c in project.contracts}

    def register_graph(self, contract_name: str, graph: KnowledgeGraph) -> None:
        self.knowledge_graphs[contract_name] = graph

    def system_view(self) -> Dict[str, Any]:
        """high-level overview across contracts."""
        return {
            "project": self.project.project_name,
            "contracts": list(self._contracts.keys()),
            "solidity_versions": self.project.solidity_versions,
            "loc": self.project.total_lines_of_code,
            "graphs": list(self.knowledge_graphs.keys()),
        }

    def get_system_view(self) -> Dict[str, Any]:
        return self.system_view()

    def component_view(self, component_name: str) -> Dict[str, Any]:
        """mid-level view filtered by component tags."""
        nodes: List[str] = []
        edges: List[Any] = []
        for graph in self.knowledge_graphs.values():
            comp_view = graph.component_view(component_name)
            if comp_view["nodes"]:
                nodes.extend(comp_view["nodes"])
                edges.extend(comp_view["edges"])
        return {"component": component_name, "nodes": nodes, "edges": edges}

    def function_view(self, contract_name: str, function_name: str) -> Dict[str, Any]:
        """low-level view of specific function."""
        graph = self.knowledge_graphs.get(contract_name)
        if not graph:
            return {"function": function_name, "node_id": None, "edges": []}
        return graph.function_view(function_name)

    def get_contract(self, name: str) -> Optional[ContractInfo]:
        return self._contracts.get(name)

    def list_contracts(self) -> List[str]:
        return list(self._contracts.keys())

    def get_relevant_code(self, query: str, budget: int = 2000) -> Dict[str, Any]:
        """retrieve relevant code snippets using semantic index or graph search."""
        try:
            from src.context.project_context import ProjectContext as NewProjectContext  # type: ignore

            ctx = NewProjectContext(str(self.project.project_root))
            ctx.index_workspace()
            results = ctx.get_relevant_code(query=query, budget=budget, structured=True)
            if isinstance(results, dict):
                payload = results.get("payload") or results.get("results") or []
            else:
                payload = results or []
            snippets = [
                {
                    "contract": item.get("metadata", {}).get("contract"),
                    "id": item.get("metadata", {}).get("name"),
                    "score": item.get("score"),
                    "text": (item.get("content") or "")[:budget],
                }
                for item in payload
            ]
            if snippets:
                return {"query": query, "snippets": snippets[:5]}
        except Exception:
            pass

        snippets: List[Dict[str, Any]] = []
        for name, graph in self.knowledge_graphs.items():
            results = graph.semantic_search(query, limit=3)
            for res in results:
                snippets.append(
                    {
                        "contract": name,
                        "id": res.get("id"),
                        "score": res.get("score"),
                        "text": res.get("text")[:budget],
                    }
                )
        snippets.sort(key=lambda x: x["score"], reverse=True)
        return {"query": query, "snippets": snippets[:5]}
