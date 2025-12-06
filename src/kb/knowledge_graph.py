"""knowledge graph for contract analysis"""

import json
import logging
import os
import re
import sys
import threading
import networkx as nx
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple, TypedDict, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import config


class NodeDict(TypedDict, total=False):
    """serialized node data"""
    node_id: str
    node_type: str
    name: str
    data: Dict[str, Any]
    discovered_by: Optional[str]
    confidence: float
    timestamp: str
    metadata: Dict[str, Any]


class EdgeDict(TypedDict, total=False):
    """serialized edge data"""
    source: str
    target: str
    edge_type: str
    data: Dict[str, Any]
    discovered_by: Optional[str]
    confidence: float
    timestamp: str
    metadata: Dict[str, Any]


class GraphDict(TypedDict, total=False):
    """complete graph serialization"""
    contract_name: str
    metadata: Dict[str, Any]
    nodes: List[NodeDict]
    edges: List[EdgeDict]


class SemanticSearchResult(TypedDict):
    """semantic search result"""
    id: str
    text: str
    score: float
    metadata: Dict[str, Any]


class SeedHypothesisDict(TypedDict, total=False):
    """kb-sourced attack hypothesis"""
    hypothesis_id: str
    attack_type: str
    description: str
    target_function: str
    preconditions: List[str]
    steps: List[str]
    expected_impact: str
    confidence: float
    requires_research: List[str]
    evidence: List[str]
    from_kb: bool
    requires_verification: bool


class NodeType(Enum):
    """node types"""
    FUNCTION = "function"
    STATE_VAR = "state_variable"
    INVARIANT = "invariant"
    ASSUMPTION = "assumption"
    DEPENDENCY = "dependency"
    VALUE_FLOW = "value_flow"
    ACCESS_CONTROL = "access_control"
    BUSINESS_LOGIC = "business_logic"
    VULNERABILITY = "vulnerability"
    ATTACK_VECTOR = "attack_vector"


class EdgeType(Enum):
    """edge types"""
    CALLS = "calls"
    MODIFIES = "modifies"
    READS = "reads"
    DEPENDS_ON = "depends_on"
    VALIDATES = "validates"
    VIOLATES = "violates"
    PROTECTS = "protects"
    ENABLES = "enables"
    TRANSFERS = "transfers"
    REQUIRES = "requires"
    IMPLEMENTS = "implements"
    INHERITS = "inherits"
    USES = "uses"


@dataclass
class GraphNode:
    """graph node"""
    node_id: str
    node_type: NodeType
    name: str
    data: Dict[str, Any] = field(default_factory=dict)
    discovered_by: Optional[str] = None
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """graph edge"""
    source: str
    target: str
    edge_type: EdgeType
    data: Dict[str, Any] = field(default_factory=dict)
    discovered_by: Optional[str] = None
    confidence: float = 1.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


class KnowledgeGraph:
    """knowledge graph for a single contract"""
    MAX_NODES = 10000
    MAX_EDGES = 50000

    def __init__(self, contract_name: str, project_root: Optional[str] = None):
        self.contract_name = contract_name
        self.project_root = Path(project_root or str(config.PROJECT_ROOT))
        self.graphs_dir = config.KNOWLEDGE_GRAPHS_DIR
        self.graphs_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self.graph = nx.MultiDiGraph()

        self.metadata = {
            "contract_name": contract_name,
            "created_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "total_nodes": 0,
            "total_edges": 0,
            "analyzed_functions": set(),
            "total_functions": 0,
            "traced_state_vars": set(),
            "total_state_vars": 0,
        }

        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []

        # o(1) lookup indexes
        self._edge_signatures: Set[Tuple[str, str, str]] = set()
        self._nodes_by_type: Dict[NodeType, Set[str]] = {}

        # centrality cache
        self._centrality_cache: Optional[Dict[str, float]] = None
        self._centrality_cache_valid: bool = False

        # semantic index
        self._semantic_index: List[Tuple[str, str, Dict[str, Any]]] = []
        self._semantic_enabled = bool(os.getenv("ENABLE_SEMANTIC_INDEX", "1") != "0")

    def _edge_signature(self, edge: GraphEdge) -> Tuple[str, str, str]:
        return (edge.source, edge.target, edge.edge_type.value if hasattr(edge.edge_type, "value") else str(edge.edge_type))

    def _invalidate_centrality_cache(self):
        self._centrality_cache_valid = False
        self._centrality_cache = None

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        name: str,
        data: Optional[Dict[str, Any]] = None,
        discovered_by: Optional[str] = None,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> GraphNode:
        """add node to graph"""
        with self._lock:
            if len(self.nodes) >= self.MAX_NODES:
                raise ValueError(f"Graph node limit reached ({self.MAX_NODES})")

            node = GraphNode(
                node_id=node_id,
                node_type=node_type,
                name=name,
                data=data or {},
                discovered_by=discovered_by,
                confidence=confidence,
                metadata=metadata or {}
            )

            self.graph.add_node(
                node_id,
                node_type=node_type.value if hasattr(node_type, 'value') else node_type,
                name=name,
                data=data or {},
                discovered_by=discovered_by,
                confidence=confidence
            )

            self.nodes[node_id] = node

            if node_type not in self._nodes_by_type:
                self._nodes_by_type[node_type] = set()
            self._nodes_by_type[node_type].add(node_id)

            self.metadata["total_nodes"] = len(self.nodes)
            self.metadata["last_updated"] = datetime.now().isoformat()

            if node_type == NodeType.FUNCTION:
                self.metadata["analyzed_functions"].add(node_id)
            elif node_type == NodeType.STATE_VAR:
                self.metadata["traced_state_vars"].add(node_id)

            self._invalidate_centrality_cache()
            return node

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: EdgeType,
        data: Optional[Dict[str, Any]] = None,
        discovered_by: Optional[str] = None,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> GraphEdge:
        """add edge to graph"""
        with self._lock:
            if len(self.edges) >= self.MAX_EDGES:
                raise ValueError(f"Graph edge limit reached ({self.MAX_EDGES})")

            edge = GraphEdge(
                source=source,
                target=target,
                edge_type=edge_type,
                data=data or {},
                discovered_by=discovered_by,
                confidence=confidence,
                metadata=metadata or {}
            )

            edge_sig = self._edge_signature(edge)
            if edge_sig in self._edge_signatures:
                for existing_edge in self.edges:
                    if self._edge_signature(existing_edge) == edge_sig:
                        return existing_edge

            self.graph.add_edge(
                source,
                target,
                edge_type=edge_type.value,
                data=data or {},
                discovered_by=discovered_by,
                confidence=confidence
            )

            self.edges.append(edge)
            self._edge_signatures.add(edge_sig)

            self.metadata["total_edges"] = len(self.edges)
            self.metadata["last_updated"] = datetime.now().isoformat()

            self._invalidate_centrality_cache()
            return edge

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """get node by id"""
        with self._lock:
            return self.nodes.get(node_id)

    def get_nodes_by_type(self, node_type: Union[NodeType, str]) -> List[GraphNode]:
        """get all nodes of type - o(k) not o(n)"""
        with self._lock:
            node_ids = self._nodes_by_type.get(node_type, set())
            return [self.nodes[node_id] for node_id in node_ids if node_id in self.nodes]

    def get_edges_from(self, node_id: str) -> List[GraphEdge]:
        """get edges from node"""
        with self._lock:
            return [e for e in self.edges if e.source == node_id]

    def get_edges_to(self, node_id: str) -> List[GraphEdge]:
        """get edges to node"""
        with self._lock:
            return [e for e in self.edges if e.target == node_id]

    def get_neighbors(self, node_id: str) -> List[str]:
        """get neighbor node ids"""
        with self._lock:
            if node_id not in self.graph:
                return []
            return list(self.graph.neighbors(node_id))

    def get_predecessors(self, node_id: str) -> List[str]:
        """get predecessor node ids"""
        with self._lock:
            if node_id not in self.graph:
                return []
            return list(self.graph.predecessors(node_id))

    def find_path(self, source: str, target: str) -> Optional[List[str]]:
        """find shortest path between nodes"""
        with self._lock:
            try:
                return nx.shortest_path(self.graph, source, target)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return None

    def find_all_paths(
        self,
        source: str,
        target: str,
        cutoff: int = 5,
        max_depth: int = 10,
        max_paths: int = 100
    ) -> List[List[str]]:
        """find all paths between nodes with limits"""
        with self._lock:
            try:
                depth_limit = max_depth if max_depth is not None else cutoff
                path_generator = nx.all_simple_paths(self.graph, source, target, cutoff=depth_limit)
                all_paths = list(path_generator)
                return all_paths[:max_paths]
            except (nx.NodeNotFound):
                return []

    def _tokenize(self, text: str) -> Set[str]:
        """tokenize text for semantic search"""
        base_tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)
        tokens: Set[str] = set()
        for tok in base_tokens:
            lower_tok = tok.lower()
            tokens.add(lower_tok)
            split_parts = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", tok)
            for part in split_parts:
                if part:
                    tokens.add(part.lower())
        return tokens

    def index_semantic_snippets(self, snippets: Dict[str, str], metadata: Optional[Dict[str, Any]] = None) -> None:
        """index snippets for semantic retrieval"""
        if not self._semantic_enabled:
            return
        meta = metadata or {}
        for key, text in snippets.items():
            if not text:
                continue
            token_set = self._tokenize(text)
            self._semantic_index.append((key, text, {"tokens": token_set, **meta}))

    def semantic_search(self, query: str, limit: int = 5) -> List[SemanticSearchResult]:
        """search snippets by token overlap"""
        if not self._semantic_enabled or not query.strip():
            return []
        query_tokens = self._tokenize(query)
        scored: List[Tuple[float, Tuple[str, str, Dict[str, Any]]]] = []
        for entry in self._semantic_index:
            tokens = entry[2].get("tokens", set())
            if not tokens:
                continue
            overlap = len(query_tokens & tokens)
            if overlap == 0:
                continue
            score = overlap / max(1, len(tokens))
            scored.append((score, entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        results: List[Dict[str, Any]] = []
        for score, (key, text, meta) in scored[:limit]:
            results.append({"id": key, "text": text, "score": score, "metadata": meta})
        return results

    def system_view(self) -> Dict[str, Any]:
        """high-level snapshot: counts, dependencies, critical nodes"""
        dependencies = [n for n in self.nodes.values() if n.node_type == NodeType.DEPENDENCY]
        critical = self.get_critical_nodes(threshold=0.05)
        return {
            "contract": self.contract_name,
            "totals": {"nodes": len(self.nodes), "edges": len(self.edges)},
            "dependencies": [d.name for d in dependencies],
            "critical_nodes": critical,
            "metadata": {
                "functions": len(self.metadata.get("analyzed_functions", [])),
                "state_vars": len(self.metadata.get("traced_state_vars", [])),
            },
        }

    def get_centrality(self) -> Dict[str, float]:
        """get betweenness centrality (cached)"""
        with self._lock:
            if len(self.graph.nodes) == 0:
                return {}

            if self._centrality_cache_valid and self._centrality_cache is not None:
                return self._centrality_cache

            self._centrality_cache = nx.betweenness_centrality(self.graph)
            self._centrality_cache_valid = True
            return self._centrality_cache

    def get_critical_nodes(self, threshold: float = 0.1) -> List[str]:
        """deprecated: use get_vulnerability_nodes() - topology not suitable for vuln detection"""
        centrality = self.get_centrality()
        return [node for node, score in centrality.items() if score >= threshold]

    def get_vulnerability_nodes(self, min_confidence: float = 0.5) -> List[GraphNode]:
        """get vulnerability nodes above confidence threshold"""
        with self._lock:
            return [
                node for node in self.nodes.values()
                if (node.node_type == NodeType.VULNERABILITY or
                    (hasattr(node.node_type, 'value') and node.node_type.value == 'vulnerability') or
                    node.node_type == 'vulnerability') and
                node.confidence >= min_confidence
            ]

    def get_seed_hypotheses_from_history(
        self,
        source_contract: str,
        seed_confidence: float = 0.6
    ) -> List[SeedHypothesisDict]:
        """extract historical vulns as seed hypotheses (additive, requires verification)"""
        source_path = self.graphs_dir / f"{source_contract}_final.json"
        if not source_path.exists():
            return []

        try:
            with open(source_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return []

        seeds: List[Dict[str, Any]] = []
        for node_data in data.get("nodes", []):
            node_type_value = node_data.get("node_type")
            if node_type_value != "vulnerability":
                continue

            historical_confidence = node_data.get("confidence", 0.85)
            node_metadata = node_data.get("data", {})

            seeds.append({
                "hypothesis_id": f"kb_seed_{source_contract}_{node_data.get('node_id', 'unknown')}",
                "attack_type": node_metadata.get("attack_type", "logic"),
                "description": node_data.get("name", "Historical vulnerability"),
                "target_function": node_metadata.get("target_function", "unknown"),
                "preconditions": node_metadata.get("preconditions", []),
                "steps": node_metadata.get("steps", []),
                "expected_impact": node_metadata.get("impact", "Unknown impact"),
                "confidence": seed_confidence,
                "requires_research": [],
                "evidence": [
                    f"[KB SEED] Historical confidence: {historical_confidence:.2f}",
                    f"[KB SEED] Source: {source_contract}",
                    f"[KB SEED] Discovered by: {node_data.get('discovered_by', 'unknown')}"
                ],
                "from_kb": True,
                "requires_verification": True,
            })

        return seeds

    def to_dict(self) -> GraphDict:
        """convert graph to dict for json serialization"""
        with self._lock:
            metadata = self.metadata.copy()
            metadata["analyzed_functions"] = list(metadata.get("analyzed_functions", set()))
            metadata["traced_state_vars"] = list(metadata.get("traced_state_vars", set()))

            return {
                "contract_name": self.contract_name,
                "metadata": metadata,
                "nodes": [
                    {
                        "node_id": n.node_id,
                        "node_type": n.node_type.value,
                        "name": n.name,
                        "data": n.data,
                        "discovered_by": n.discovered_by,
                        "confidence": n.confidence,
                        "timestamp": n.timestamp,
                        "metadata": n.metadata
                    }
                    for n in self.nodes.values()
                ],
                "edges": [
                    {
                        "source": e.source,
                        "target": e.target,
                        "edge_type": e.edge_type.value,
                        "data": e.data,
                        "discovered_by": e.discovered_by,
                        "confidence": e.confidence,
                        "timestamp": e.timestamp,
                        "metadata": e.metadata
                    }
                    for e in self.edges
                ]
            }

    def save(self, filename: Optional[str] = None) -> str:
        """save graph to json"""
        if filename is None:
            filename = f"{self.contract_name}_final.json"

        filepath = self.graphs_dir / filename
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

        return str(filepath)

    @classmethod
    def load(cls, filepath: str) -> "KnowledgeGraph":
        """load graph from json"""
        with open(filepath, 'r', encoding="utf-8") as f:
            data = json.load(f)

        graph = cls(contract_name=data["contract_name"])

        metadata = data["metadata"]
        metadata["analyzed_functions"] = set(metadata.get("analyzed_functions", []))
        metadata["traced_state_vars"] = set(metadata.get("traced_state_vars", []))
        graph.metadata = metadata

        for node_data in data["nodes"]:
            graph.add_node(
                node_id=node_data["node_id"],
                node_type=NodeType(node_data["node_type"]),
                name=node_data["name"],
                data=node_data["data"],
                discovered_by=node_data.get("discovered_by"),
                confidence=node_data.get("confidence", 1.0),
                metadata=node_data.get("metadata", {})
            )

        for edge_data in data["edges"]:
            graph.add_edge(
                source=edge_data["source"],
                target=edge_data["target"],
                edge_type=EdgeType(edge_data["edge_type"]),
                data=edge_data["data"],
                discovered_by=edge_data.get("discovered_by"),
                confidence=edge_data.get("confidence", 1.0),
                metadata=edge_data.get("metadata", {})
            )

        return graph

    def bootstrap_from_existing(
        self,
        source_contract: str,
        copy_edges: bool = True,
        quiet: bool = True
    ) -> bool:
        """preload graph with nodes/edges from previously analyzed contract"""
        source_path = self.graphs_dir / f"{source_contract}_final.json"
        if not source_path.exists():
            if not quiet:
                logger.debug("No cached graph found", extra={"contract": source_contract, "path": str(source_path)})
            return False

        try:
            with open(source_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            if not quiet:
                logger.warning("Failed to load cached graph", extra={"contract": source_contract, "error": str(exc)})
            return False

        nodes_added = 0
        for node_data in data.get("nodes", []):
            node_id = node_data.get("node_id")
            node_type_value = node_data.get("node_type")
            if not node_id or not node_type_value or node_id in self.nodes:
                continue
            try:
                node_type = NodeType(node_type_value)
            except ValueError:
                continue
            self.add_node(
                node_id=node_id,
                node_type=node_type,
                name=node_data.get("name", node_id),
                data=node_data.get("data") or {},
                discovered_by=node_data.get("discovered_by"),
                confidence=node_data.get("confidence", 1.0),
                metadata=node_data.get("metadata") or {}
            )
            nodes_added += 1

        if copy_edges and nodes_added:
            for edge_data in data.get("edges", []):
                source = edge_data.get("source")
                target = edge_data.get("target")
                edge_type_value = edge_data.get("edge_type")
                if (
                    not source
                    or not target
                    or source not in self.nodes
                    or target not in self.nodes
                    or not edge_type_value
                ):
                    continue
                sig = (source, target, edge_type_value)
                if sig in self._edge_signatures:
                    continue
                try:
                    edge_type = EdgeType(edge_type_value)
                except ValueError:
                    continue
                self.add_edge(
                    source=source,
                    target=target,
                    edge_type=edge_type,
                    data=edge_data.get("data") or {},
                    discovered_by=edge_data.get("discovered_by"),
                    confidence=edge_data.get("confidence", 1.0),
                    metadata=edge_data.get("metadata") or {}
                )

        src_meta = data.get("metadata", {})
        analyzed = set(src_meta.get("analyzed_functions", []))
        traced = set(src_meta.get("traced_state_vars", []))
        self.metadata["analyzed_functions"].update(analyzed)
        self.metadata["traced_state_vars"].update(traced)
        self.metadata["total_functions"] = max(
            self.metadata.get("total_functions", 0),
            src_meta.get("total_functions", 0)
        )
        self.metadata["total_state_vars"] = max(
            self.metadata.get("total_state_vars", 0),
            src_meta.get("total_state_vars", 0)
        )
        self.metadata["last_updated"] = datetime.now().isoformat()
        return nodes_added > 0

    def get_summary(self) -> Dict[str, Any]:
        """get summary statistics"""
        with self._lock:
            node_types = {}
            for node in self.nodes.values():
                t = node.node_type.value
                node_types[t] = node_types.get(t, 0) + 1

            edge_types = {}
            for edge in self.edges:
                t = edge.edge_type.value
                edge_types[t] = edge_types.get(t, 0) + 1

            return {
                "contract_name": self.contract_name,
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "node_types": node_types,
                "edge_types": edge_types,
                "analyzed_functions": len(self.metadata.get("analyzed_functions", set())),
                "total_functions": self.metadata.get("total_functions", 0),
                "traced_state_vars": len(self.metadata.get("traced_state_vars", set())),
                "total_state_vars": self.metadata.get("total_state_vars", 0),
                "critical_nodes": self.get_critical_nodes()
            }

    def print_summary(self):
        """print summary to console"""
        summary = self.get_summary()

        logger.info("Knowledge graph summary", extra={
            "contract": self.contract_name,
            "total_nodes": summary['total_nodes'],
            "total_edges": summary['total_edges'],
            "node_types": summary['node_types'],
            "edge_types": summary['edge_types'],
            "analyzed_functions": f"{summary['analyzed_functions']}/{summary['total_functions']}",
            "traced_state_vars": f"{summary['traced_state_vars']}/{summary['total_state_vars']}",
            "critical_nodes_count": len(summary['critical_nodes'])
        })

        print("\n" + "="*60)
        print(f"KNOWLEDGE GRAPH: {self.contract_name}")
        print("="*60)
        print(f"Total Nodes: {summary['total_nodes']}")
        print(f"Total Edges: {summary['total_edges']}")
        print("\nNode Types:")
        for node_type, count in summary['node_types'].items():
            print(f"  {node_type}: {count}")
        print("\nEdge Types:")
        for edge_type, count in summary['edge_types'].items():
            print(f"  {edge_type}: {count}")
        print("\nAnalysis Coverage:")
        print(f"  Functions: {summary['analyzed_functions']}/{summary['total_functions']}")
        print(f"  State Vars: {summary['traced_state_vars']}/{summary['total_state_vars']}")
        print(f"\nCritical Nodes: {len(summary['critical_nodes'])}")
        for node_id in summary['critical_nodes'][:5]:
            node = self.get_node(node_id)
            print(f"  - {node.name} ({node.node_type.value})")
        print("="*60 + "\n")


if __name__ == "__main__":
    graph = KnowledgeGraph("UnstoppableVault")

    graph.metadata["total_functions"] = 10
    graph.metadata["total_state_vars"] = 5

    graph.add_node(
        node_id="fn_flashLoan",
        node_type=NodeType.FUNCTION,
        name="flashLoan",
        data={"visibility": "external", "params": ["uint256 amount"]},
        discovered_by="StateFlow"
    )

    graph.add_node(
        node_id="fn_deposit",
        node_type=NodeType.FUNCTION,
        name="deposit",
        data={"visibility": "public", "params": ["uint256 assets", "address receiver"]},
        discovered_by="StateFlow"
    )

    graph.add_node(
        node_id="var_totalAssets",
        node_type=NodeType.STATE_VAR,
        name="totalAssets",
        data={"type": "uint256", "visibility": "public"},
        discovered_by="StateFlow"
    )

    graph.add_node(
        node_id="inv_balance_equals_totalAssets",
        node_type=NodeType.INVARIANT,
        name="Balance equals totalAssets",
        data={"formula": "token.balanceOf(vault) == totalAssets", "critical": True},
        discovered_by="Invariant"
    )

    graph.add_edge(
        "fn_flashLoan", "var_totalAssets",
        EdgeType.READS,
        discovered_by="StateFlow"
    )

    graph.add_edge(
        "fn_deposit", "var_totalAssets",
        EdgeType.MODIFIES,
        discovered_by="StateFlow"
    )

    graph.add_edge(
        "var_totalAssets", "inv_balance_equals_totalAssets",
        EdgeType.VALIDATES,
        discovered_by="Invariant"
    )

    graph.print_summary()

    filepath = graph.save()
    logger.info("Graph saved", extra={"path": filepath})

    loaded = KnowledgeGraph.load(filepath)
    logger.info("Graph loaded successfully")
    loaded.print_summary()
