"""
DependencyRefiner: sharpens R/W and dependency sets using taint + MCG context.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class DependencyRefiner:
    def refine(self, contract_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Produce a refined dependency list from taint traces and code graph deps.
        """
        refined: List[Dict[str, Any]] = []
        # Taint-derived dependencies
        for t in contract_info.get("taint_traces_struct") or []:
            sink = t.get("resolved_target") or t.get("sink")
            if not sink:
                continue
            target_contract = sink.split(".")[0] if "." in sink else contract_info.get("name")
            refined.append(
                {
                    "source": t.get("source"),
                    "sink": sink,
                    "target_contract": target_contract,
                    "via": "taint",
                }
            )
        # Code graph dependency nodes
        code_graph = contract_info.get("code_graph") or {}
        for edge in code_graph.get("edges", []):
            if edge.get("type") == "calls_external":
                refined.append(
                    {
                        "source": edge.get("source"),
                        "sink": edge.get("target"),
                        "target_contract": self._target_from_dep(edge.get("target")),
                        "via": "code_graph",
                    }
                )

        # De-dup
        seen = set()
        unique: List[Dict[str, Any]] = []
        for item in refined:
            key = (item.get("source"), item.get("sink"), item.get("target_contract"), item.get("via"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique

    def rank_communities(
        self, summaries: List[Dict[str, Any]], queries: List[str], top_k: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Rank community summaries using simple token overlap scoring.
        """
        scored: List[Dict[str, Any]] = []
        query_tokens = self._tokenize(" ".join(queries))
        for summary in summaries:
            text = summary.get("summary", "")
            tokens = self._tokenize(text)
            score = len(query_tokens & tokens)
            # Raise weight if explicitly marked as taint/source community
            if summary.get("metadata", {}).get("taint_hit"):
                score += 2
            scored.append({**summary, "score": score})
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    def _tokenize(self, text: str) -> set[str]:
        return {t.lower() for t in text.replace(",", " ").split() if t}

    def _target_from_dep(self, dep_label: str | None) -> str:
        if not dep_label:
            return ""
        if "::" in dep_label:
            return dep_label.split("::", 1)[0]
        return dep_label.split(".")[0]
