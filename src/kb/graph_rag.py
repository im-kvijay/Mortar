"""graph-based rag for vulnerability patterns"""

import json
import networkx as nx
import igraph as ig
import leidenalg
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict
import numpy as np
from pathlib import Path

from kb.knowledge_base import VulnerabilityPattern, KnowledgeBase


@dataclass
class PatternNode:
    """vulnerability pattern node"""
    pattern_id: str
    pattern: VulnerabilityPattern
    community: Optional[int] = None  # leiden cluster id
    centrality: float = 0.0  # centrality score


@dataclass
class GraphRAGStats:
    """graphrag statistics"""
    num_nodes: int
    num_edges: int
    num_communities: int
    avg_degree: float
    density: float
    largest_component_size: int


class GraphRAG:
    """graph-based rag"""

    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base
        self.graph = nx.DiGraph()
        self.igraph = None
        self.nodes: Dict[str, PatternNode] = {}
        self.communities: Dict[int, List[str]] = {}
        self.built = False
        self._stats = None

    def build_graph(self, similarity_threshold: float = 0.3):
        """build graph from kb patterns with similarity edges"""
        print(f"[GraphRAG] Building graph from {len(self.kb.patterns)} patterns...")

        # create nodes
        for pattern_id, pattern in self.kb.patterns.items():
            node = PatternNode(
                pattern_id=pattern_id,
                pattern=pattern
            )
            self.nodes[pattern_id] = node
            self.graph.add_node(pattern_id, **{
                'name': pattern.name,
                'vuln_type': pattern.vuln_type,
                'confidence': pattern.confidence,
                'node_obj': node
            })

        print(f"[GraphRAG] Created {len(self.nodes)} nodes")

        # create edges based on similarity
        edge_count = 0

        for p1_id, p1_node in self.nodes.items():
            for p2_id, p2_node in self.nodes.items():
                if p1_id >= p2_id:
                    continue

                p1 = p1_node.pattern
                p2 = p2_node.pattern

                similarity = self._calculate_similarity(p1, p2)

                if similarity >= similarity_threshold:
                    self.graph.add_edge(p1_id, p2_id, weight=similarity, type='similarity')
                    self.graph.add_edge(p2_id, p1_id, weight=similarity, type='similarity')
                    edge_count += 2

        print(f"[GraphRAG] Created {edge_count} edges (similarity threshold: {similarity_threshold})")

        # calculate centrality
        self._calculate_centrality()

        self.built = True
        print(f"[GraphRAG] Graph built successfully!")

    def _calculate_similarity(self, p1: VulnerabilityPattern, p2: VulnerabilityPattern) -> float:
        """calculate similarity between two patterns (0.0-1.0)"""
        score = 0.0

        if p1.vuln_type == p2.vuln_type:
            score += 0.5

        desc1_words = set(p1.description.lower().split())
        desc2_words = set(p2.description.lower().split())
        if desc1_words and desc2_words:
            desc_overlap = len(desc1_words & desc2_words) / len(desc1_words | desc2_words)
            score += 0.2 * desc_overlap

        if p1.preconditions and p2.preconditions:
            precond1 = set(p.lower() for p in p1.preconditions)
            precond2 = set(p.lower() for p in p2.preconditions)
            precond_overlap = len(precond1 & precond2) / max(len(precond1 | precond2), 1)
            score += 0.15 * precond_overlap

        if p1.attack_steps and p2.attack_steps:
            steps1 = set(s.lower() for s in p1.attack_steps)
            steps2 = set(s.lower() for s in p2.attack_steps)
            steps_overlap = len(steps1 & steps2) / max(len(steps1 | steps2), 1)
            score += 0.15 * steps_overlap

        return min(score, 1.0)

    def _calculate_centrality(self):
        """calculate node centrality scores using pagerank"""
        if not self.graph.nodes:
            return

        centrality = nx.pagerank(self.graph, weight='weight')
        for node_id, score in centrality.items():
            if node_id in self.nodes:
                self.nodes[node_id].centrality = score

    def leiden_cluster(self, resolution: float = 1.0) -> Dict[int, List[str]]:
        """cluster patterns into communities using leiden algorithm"""
        if not self.built:
            raise RuntimeError("Must call build_graph() first")

        print(f"[GraphRAG] Running Leiden clustering (resolution={resolution})...")

        # convert networkx to igraph
        edge_list = [(u, v) for u, v, _ in self.graph.edges(data=True)]
        self.igraph = ig.Graph(directed=False)
        self.igraph.add_vertices(list(self.nodes.keys()))

        node_to_idx = {node_id: idx for idx, node_id in enumerate(self.nodes.keys())}
        idx_edges = [(node_to_idx[u], node_to_idx[v]) for u, v in edge_list]
        self.igraph.add_edges(idx_edges)

        # run leiden
        partition = leidenalg.find_partition(
            self.igraph,
            leidenalg.RBConfigurationVertexPartition,
            resolution_parameter=resolution
        )

        # extract communities
        self.communities = defaultdict(list)
        idx_to_node = {idx: node_id for node_id, idx in node_to_idx.items()}

        for comm_id, members in enumerate(partition):
            for member_idx in members:
                node_id = idx_to_node[member_idx]
                self.nodes[node_id].community = comm_id
                self.communities[comm_id].append(node_id)

        print(f"[GraphRAG] Found {len(self.communities)} communities")
        print(f"[GraphRAG] Community sizes: {[len(c) for c in self.communities.values()]}")
        self._update_stats()

        return dict(self.communities)

    def retrieve_context(
        self,
        query_pattern_id: str,
        k: int = 10,
        hops: int = 2,
        include_community: bool = True
    ) -> List[VulnerabilityPattern]:
        """multi-hop retrieval from query pattern, returns top-k related patterns"""
        if not self.built:
            raise RuntimeError("Must call build_graph() first")

        if query_pattern_id not in self.nodes:
            print(f"[GraphRAG] WARNING: Pattern {query_pattern_id} not in graph")
            return []

        # collect candidate patterns via graph traversal
        candidates: Set[str] = set()
        visited: Set[str] = set()
        frontier: Set[str] = {query_pattern_id}

        for hop in range(hops):
            next_frontier: Set[str] = set()
            for node_id in frontier:
                if node_id in visited:
                    continue
                visited.add(node_id)
                candidates.add(node_id)

                for neighbor in self.graph.neighbors(node_id):
                    if neighbor not in visited:
                        next_frontier.add(neighbor)

            frontier = next_frontier

        # include community members
        if include_community:
            query_node = self.nodes[query_pattern_id]
            if query_node.community is not None:
                community_members = self.communities.get(query_node.community, [])
                candidates.update(community_members)

        # score candidates by relevance
        query_pattern = self.nodes[query_pattern_id].pattern
        scored_patterns = []

        for candidate_id in candidates:
            if candidate_id == query_pattern_id:
                continue

            candidate_pattern = self.nodes[candidate_id].pattern
            score = self._calculate_retrieval_score(
                query_pattern,
                candidate_pattern,
                candidate_id,
                query_pattern_id
            )
            scored_patterns.append((score, candidate_pattern))

        # sort and return top-k
        scored_patterns.sort(reverse=True, key=lambda x: x[0])
        return [pattern for _, pattern in scored_patterns[:k]]

    def _calculate_retrieval_score(
        self,
        query: VulnerabilityPattern,
        candidate: VulnerabilityPattern,
        candidate_id: str,
        query_id: str
    ) -> float:
        """score how relevant a candidate is for retrieval"""
        score = 0.0

        similarity = self._calculate_similarity(query, candidate)
        score += 0.4 * similarity

        centrality = self.nodes[candidate_id].centrality
        score += 0.2 * centrality

        score += 0.2 * candidate.confidence

        try:
            distance = nx.shortest_path_length(self.graph, query_id, candidate_id)
            score += 0.2 * (1.0 / (distance + 1))
        except nx.NetworkXNoPath:
            score += 0.0

        return score

    def get_community_patterns(self, community_id: int) -> List[VulnerabilityPattern]:
        """get all patterns in a community"""
        if community_id not in self.communities:
            return []

        pattern_ids = self.communities[community_id]
        return [self.nodes[pid].pattern for pid in pattern_ids]

    def get_stats(self) -> GraphRAGStats:
        """get statistics about the graph"""
        if not self.built:
            return GraphRAGStats(0, 0, 0, 0.0, 0.0, 0)
        if self._stats:
            return self._stats

        num_nodes = self.graph.number_of_nodes()
        num_edges = self.graph.number_of_edges()
        num_communities = len(self.communities)

        avg_degree = sum(dict(self.graph.degree()).values()) / max(num_nodes, 1)
        density = nx.density(self.graph)

        if num_nodes > 0:
            largest_cc = max(nx.weakly_connected_components(self.graph), key=len)
            largest_component_size = len(largest_cc)
        else:
            largest_component_size = 0

        stats = GraphRAGStats(
            num_nodes=num_nodes,
            num_edges=num_edges,
            num_communities=num_communities,
            avg_degree=avg_degree,
            density=density,
            largest_component_size=largest_component_size
        )
        self._stats = stats
        return stats

    def _update_stats(self) -> None:
        """invalidate cached stats for recomputation"""
        self._stats = None
        if self.built:
            _ = self.get_stats()

    def to_payload(self) -> Dict[str, Any]:
        """serialize the graph for persistence"""
        return {
            "nodes": [
                {
                    "pattern_id": pattern_id,
                    "community": node.community,
                    "centrality": node.centrality,
                }
                for pattern_id, node in self.nodes.items()
            ],
            "edges": [
                (u, v, data.get("weight", 1.0))
                for u, v, data in self.graph.edges(data=True)
            ],
            "communities": self.communities,
            "stats": self._stats.__dict__ if self._stats else None,
            "built": self.built,
        }

    def save_to_disk(self, file_path: Path) -> None:
        """persist graph state to disk using json"""
        payload = self.to_payload()
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with file_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)

    @classmethod
    def load_from_disk(cls, knowledge_base: KnowledgeBase, file_path: Path) -> "GraphRAG":
        """load graph state from disk"""
        with file_path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        instance = cls(knowledge_base=knowledge_base)
        instance._restore_from_payload(payload)
        return instance

    def _restore_from_payload(self, payload: Dict[str, Any]) -> None:
        """restore internal structures from serialized payload"""
        self.graph = nx.DiGraph()
        self.nodes = {}
        self.communities = payload.get("communities", {})

        for node_data in payload.get("nodes", []):
            pattern_id = node_data.get("pattern_id")
            if not pattern_id:
                continue
            pattern = self.kb.patterns.get(pattern_id)
            if not pattern:
                continue
            node = PatternNode(
                pattern_id=pattern_id,
                pattern=pattern,
                community=node_data.get("community"),
                centrality=node_data.get("centrality", 0.0),
            )
            self.nodes[pattern_id] = node
            self.graph.add_node(
                pattern_id,
                name=pattern.name,
                vuln_type=pattern.vuln_type,
                confidence=pattern.confidence,
                node_obj=node,
            )

        for u, v, weight in payload.get("edges", []):
            if u in self.nodes and v in self.nodes:
                self.graph.add_edge(u, v, weight=weight, type="similarity")

        stats_payload = payload.get("stats")
        if stats_payload:
            self._stats = GraphRAGStats(**stats_payload)
        else:
            self._stats = None
        self.built = payload.get("built", bool(self.nodes))

    def visualize_graph(self, output_path: str = "graph_rag.png"):
        """save graph visualization (requires matplotlib)"""
        try:
            import matplotlib.pyplot as plt

            plt.figure(figsize=(20, 20))

            # color by community
            if self.communities:
                colors = [self.nodes[node].community or 0 for node in self.graph.nodes()]
            else:
                colors = ['blue'] * self.graph.number_of_nodes()

            # size by centrality
            sizes = [self.nodes[node].centrality * 3000 + 100 for node in self.graph.nodes()]

            pos = nx.spring_layout(self.graph, k=1, iterations=50)
            nx.draw_networkx(
                self.graph,
                pos,
                node_color=colors,
                node_size=sizes,
                with_labels=False,
                edge_color='gray',
                alpha=0.6,
                cmap=plt.cm.tab10
            )

            plt.title("GraphRAG Vulnerability Pattern Network")
            plt.axis('off')
            plt.tight_layout()
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            print(f"[GraphRAG] Saved visualization to {output_path}")
            plt.close()

        except ImportError:
            print("[GraphRAG] matplotlib not available, skipping visualization")

    def generate_community_summaries(self, backend) -> Dict[int, str]:
        """generate hierarchical summaries for each community using llm"""
        if not self.communities:
            print("[GraphRAG] No communities found, run build_graph() first")
            return {}

        community_summaries = {}

        for community_id in self.communities.keys():
            community_patterns = self.communities[community_id]

            if not community_patterns:
                continue

            pattern_descriptions = []
            for pid in community_patterns[:10]:
                node = self.nodes.get(pid)
                if node:
                    pattern = node.pattern
                    pattern_descriptions.append(
                        f"- {pattern.name} ({pattern.vuln_type}): {pattern.description[:150]}"
                    )

            if not pattern_descriptions:
                continue

            prompt = f"""Analyze this community of {len(community_patterns)} related vulnerability patterns and generate a concise summary.

Patterns in Community {community_id}:
{chr(10).join(pattern_descriptions)}

Generate a 2-3 sentence summary that captures:
1. The common theme or attack category
2. Key relationships between patterns
3. The overall risk level

Summary:"""

            try:
                response = backend.generate(
                    prompt=prompt,
                    max_tokens=200,
                    temperature=0.3
                )
                summary = response.content[0].text.strip()
                community_summaries[community_id] = summary

            except Exception as e:
                print(f"[GraphRAG] Failed to generate summary for community {community_id}: {e}")
                community_summaries[community_id] = f"Community of {len(community_patterns)} patterns"

        return community_summaries

    def get_hierarchical_context(
        self,
        pattern_ids: List[str],
        backend,
        include_community_summaries: bool = True
    ) -> Dict[str, Any]:
        """get hierarchical context: patterns + community summaries + related patterns"""
        # get initial patterns
        patterns = []
        community_ids = set()

        for pid in pattern_ids:
            node = self.nodes.get(pid)
            if node:
                patterns.append(node.pattern)
                if node.community is not None:
                    community_ids.add(node.community)

        # expand via multi-hop retrieval
        expanded = []
        for pid in pattern_ids:
            if pid in self.nodes:
                expanded_patterns = self.retrieve_context(query_pattern_id=pid, k=20, hops=2)
                expanded.extend([p.id for p in expanded_patterns])

        # get community summaries if requested
        summaries = {}
        if include_community_summaries and community_ids:
            all_summaries = self.generate_community_summaries(backend)
            for cid in community_ids:
                if cid in all_summaries:
                    summaries[cid] = all_summaries[cid]

        return {
            "query_patterns": patterns,
            "community_summaries": summaries,
            "expanded_patterns": [self.nodes[pid].pattern for pid in expanded if pid in self.nodes],
            "total_context_size": len(patterns) + len(expanded)
        }
