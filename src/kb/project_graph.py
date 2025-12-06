"""unified knowledge graph for entire project"""

from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field
import networkx as nx
from kb.knowledge_graph import KnowledgeGraph, GraphNode, GraphEdge, NodeType, EdgeType
from typing import Optional

@dataclass
class SystemNode(GraphNode):
    """system-level entity node"""
    contract_name: str = ""

class ProjectKnowledgeGraph:
    """unified knowledge graph for entire project"""
    
    def __init__(self, project_name: str):
        self.project_name = project_name
        self.graph = nx.MultiDiGraph()
        self.contracts: Dict[str, KnowledgeGraph] = {}
        
    def merge_contract_graph(self, contract_name: str, kg: KnowledgeGraph):
        """
        Merge a single contract's knowledge graph into the project graph.
        Prefixes node IDs with contract name to avoid collisions.
        """
        self.contracts[contract_name] = kg
        
        for node_id, node_data in kg.graph.nodes(data=True):
            # Create unique ID: "ContractName:NodeID"
            unique_id = f"{contract_name}:{node_id}"
            
            # Add node with contract metadata
            self.graph.add_node(
                unique_id,
                **node_data,
                contract=contract_name,
                original_id=node_id
            )
            
        for u, v, key, edge_data in kg.graph.edges(keys=True, data=True):
            u_unique = f"{contract_name}:{u}"
            v_unique = f"{contract_name}:{v}"
            
            self.graph.add_edge(
                u_unique,
                v_unique,
                key=key,
                **edge_data
            )

    def add_contract_node(self, contract_name: str, contract_info: Any):
        """
        Add a high-level node representing the contract definition itself.
        """
        node_id = f"{contract_name}:contract_def"
        self.graph.add_node(
            node_id,
            type="contract_def",
            name=contract_name,
            contract=contract_name,
            file_path=str(contract_info.file_path)
        )
            
    def add_cross_contract_edge(self, 
                                source_contract: str, source_node: str,
                                target_contract: str, target_node: str,
                                relation: str,
                                metadata: Dict[str, Any] = None):
        """
        Add an edge between nodes in different contracts.
        Example: Token.transfer -> Vault.deposit
        """
        u = f"{source_contract}:{source_node}"
        v = f"{target_contract}:{target_node}"
        
        if u not in self.graph:
            # Create placeholder if missing (e.g. external call to unknown function)
            self.graph.add_node(u, type="placeholder", contract=source_contract)
        if v not in self.graph:
            self.graph.add_node(v, type="placeholder", contract=target_contract)
            
        self.graph.add_edge(u, v, relation=relation, type="cross_contract", **(metadata or {}))

    def add_taint_edge(self, source_contract: str, source_fn: str, target_contract: Optional[str], sink_label: str, metadata: Optional[Dict[str, Any]] = None):
        """
        Add a taint edge between contracts when we know the sink target.
        """
        target_contract = target_contract or source_contract
        self.add_cross_contract_edge(
            source_contract=source_contract,
            source_node=f"fn::{source_fn}",
            target_contract=target_contract,
            target_node=f"call::{sink_label}",
            relation="taint_flow",
            metadata=metadata or {}
        )

    def add_invariant_node(self, contract_name: str, invariant: str):
        node_id = f"{contract_name}:invariant::{invariant}"
        self.graph.add_node(
            node_id,
            type="invariant",
            contract=contract_name,
            label=invariant
        )

    def query_system(self, query_type: str, **kwargs) -> List[Any]:
        """
        Execute system-wide queries.
        
        Supported types:
        - "find_usage": Find all usages of a function signature across contracts
        - "trace_flow": Find paths between two system nodes
        """
        if query_type == "find_usage":
            signature = kwargs.get("signature")
            if not signature:
                return []
            
            usages = []
            # Look for edges pointing to a node that matches the signature
            for u, v, data in self.graph.edges(data=True):
                # Check if target node matches signature (e.g. "Vault:deposit" matches "deposit")
                if v.endswith(f":{signature}"):
                    usages.append({
                        "source": u,
                        "target": v,
                        "relation": data.get("relation", "unknown")
                    })
            return usages

        elif query_type == "trace_flow":
            start_node = kwargs.get("start_node")
            end_node = kwargs.get("end_node")
            if not start_node or not end_node:
                return []
            
            try:
                # Find all simple paths (limit to short paths for performance)
                paths = list(nx.all_simple_paths(self.graph, source=start_node, target=end_node, cutoff=5))
                return paths
            except nx.NetworkXNoPath:
                return []
            except Exception:
                return []

        return []

    def find_cycles(self) -> List[List[str]]:
        """
        Find circular dependencies between contracts.
        Returns a list of cycles, where each cycle is a list of node IDs.
        """
        try:
            # Filter for contract dependency edges only to avoid noise
            # But for now, simple_cycles on the whole graph is a good start
            return list(nx.simple_cycles(self.graph))
        except Exception:
            return []

    def find_central_nodes(self, top_k: int = 5) -> List[tuple[str, float]]:
        """
        Identify central/critical contracts using PageRank.
        Returns list of (node_id, score).
        """
        try:
            scores = nx.pagerank(self.graph)
            sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
            return sorted_scores[:top_k]
        except Exception:
            return []

    def get_cross_contract_calls(self, contract_name: str) -> List[Dict[str, Any]]:
        """
        Get all cross-contract calls originating from a contract.

        Args:
            contract_name: Contract name to search

        Returns:
            List of call edges with source/target/metadata
        """
        calls = []
        prefix = f"{contract_name}:"

        for u, v, data in self.graph.edges(data=True):
            # Find edges from this contract to another contract
            if u.startswith(prefix):
                target_contract = v.split(":", 1)[0] if ":" in v else ""
                if target_contract and target_contract != contract_name:
                    calls.append({
                        "source": u,
                        "target": v,
                        "source_contract": contract_name,
                        "target_contract": target_contract,
                        "relation": data.get("relation", "unknown"),
                        "metadata": data
                    })

        return calls

    def find_trust_boundaries(self) -> List[Dict[str, Any]]:
        """
        Find trust boundaries in the system (cross-contract edges with security implications).

        Trust boundaries are edges where:
        - Control/value flows between contracts
        - Access control checks may be required
        - Reentrancy or front-running risks exist

        Returns:
            List of trust boundary edges with risk indicators
        """
        boundaries = []

        # Look for cross-contract edges with security implications
        for u, v, data in self.graph.edges(data=True):
            u_contract = u.split(":", 1)[0] if ":" in u else ""
            v_contract = v.split(":", 1)[0] if ":" in v else ""

            # Skip intra-contract edges
            if not u_contract or not v_contract or u_contract == v_contract:
                continue

            relation = data.get("relation", "")
            edge_type = data.get("type", "")

            # Identify trust boundary indicators
            is_value_transfer = "transfer" in relation.lower() or "send" in relation.lower()
            is_call = "call" in relation.lower() or edge_type == "cross_contract"
            is_taint_flow = relation == "taint_flow"

            if is_value_transfer or is_call or is_taint_flow:
                boundaries.append({
                    "source": u,
                    "target": v,
                    "source_contract": u_contract,
                    "target_contract": v_contract,
                    "relation": relation,
                    "risk_level": "high" if is_value_transfer else "medium",
                    "indicators": {
                        "value_transfer": is_value_transfer,
                        "external_call": is_call,
                        "taint_flow": is_taint_flow
                    },
                    "metadata": data
                })

        return boundaries

    def trace_cross_contract_flow(
        self,
        source: str,
        sink: str,
        max_depth: int = 10,
        max_paths: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Trace data/control flow between two nodes across contract boundaries.

        Args:
            source: Source node ID (e.g., "TokenA:transfer")
            sink: Sink node ID (e.g., "VaultB:deposit")
            max_depth: Maximum path length
            max_paths: Maximum number of paths to return

        Returns:
            List of flow paths with contract boundary crossings highlighted
        """
        try:
            # Find all simple paths (limited for performance)
            path_generator = nx.all_simple_paths(self.graph, source, sink, cutoff=max_depth)
            paths = []

            for path in path_generator:
                if len(paths) >= max_paths:
                    break

                # Analyze path for contract boundaries
                boundary_crossings = []
                contracts_in_path = []
                prev_contract = None

                for node in path:
                    contract = node.split(":", 1)[0] if ":" in node else ""
                    if contract and contract != prev_contract:
                        if prev_contract:
                            boundary_crossings.append({
                                "from": prev_contract,
                                "to": contract
                            })
                        if contract not in contracts_in_path:
                            contracts_in_path.append(contract)
                        prev_contract = contract

                paths.append({
                    "path": path,
                    "length": len(path),
                    "contracts": contracts_in_path,
                    "boundary_crossings": len(boundary_crossings),
                    "crossings": boundary_crossings
                })

            return paths

        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
        except Exception:
            return []

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for storage"""
        return {
            "project_name": self.project_name,
            "nodes": [
                {"id": n, **self.graph.nodes[n]}
                for n in self.graph.nodes
            ],
            "edges": [
                {"source": u, "target": v, **data}
                for u, v, data in self.graph.edges(data=True)
            ]
        }
