"""
IRIS-lite: structural verification triage

Applies lightweight taint + invariant + dependency checks to highlight
high-risk flows without invoking heavy SMT. Designed to run before/alongside
verification to focus effort on the most dangerous paths.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType


class IrisLite:
    def __init__(self, max_findings: int = 5):
        self.max_findings = max_findings

    def assess(
        self,
        contract_info: Dict[str, Any],
        knowledge_graph: Optional[KnowledgeGraph] = None,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        taints = contract_info.get("taint_traces_struct") or []
        invariants = contract_info.get("invariants") or []

        coverage = self._compute_coverage_metrics(contract_info, knowledge_graph, taints, invariants)
        if coverage:
            # Attach coverage summary for downstream prompts
            contract_info["structural_coverage"] = coverage
            findings.append(
                {
                    "type": "coverage",
                    "description": (
                        f"Structural coverage score {coverage['coverage_score']:.2f} "
                        f"(functions {coverage['functions_covered']}/{coverage['functions_total']}, "
                        f"taints {coverage['taint_count']}, invariants {coverage['invariant_count']})"
                    ),
                    "coverage": coverage,
                    "risk_score": coverage["coverage_score"],
                }
            )
            if len(findings) >= self.max_findings:
                return findings

        # Taint paths that end in external calls are prioritized
        for taint in taints:
            src = taint.get("source")
            sink = taint.get("sink")
            desc = f"Taint flow {src} -> {sink}"
            risk = self._score_taint(taint, coverage)
            findings.append(
                {
                    "type": "taint_flow",
                    "description": desc,
                    "source": src,
                    "sink": sink,
                    "line": taint.get("line"),
                    "risk_score": risk,
                }
            )
            self._add_graph_vuln(
                knowledge_graph,
                node_id=f"taint::{src}->{sink}",
                label=desc,
                target=f"fn::{src}" if src else None,
            )
            if len(findings) >= self.max_findings:
                return findings

        # Invariants present but unverified (flag for attention)
        for inv in invariants:
            inv_label = inv if isinstance(inv, str) else inv.get("invariant") or str(inv)
            risk = self._score_invariant(inv_label, coverage)
            findings.append(
                {
                    "type": "invariant_check",
                    "description": f"Invariant requires validation: {inv_label}",
                    "risk_score": risk,
                }
            )
            self._add_graph_vuln(
                knowledge_graph,
                node_id=f"invariant::{inv_label}",
                label=f"invariant: {inv_label}",
                target=None,
            )
            if len(findings) >= self.max_findings:
                return findings

        return findings

    def _add_graph_vuln(
        self,
        knowledge_graph: Optional[KnowledgeGraph],
        node_id: str,
        label: str,
        target: Optional[str],
    ) -> None:
        if not knowledge_graph:
            return
        knowledge_graph.add_node(
            node_id=node_id,
            node_type=NodeType.VULNERABILITY,
            name=label,
            data={},
            discovered_by="iris_lite",
            metadata={"component": "iris_lite"},
        )
        if target:
            if not knowledge_graph.get_node(target):
                knowledge_graph.add_node(
                    node_id=target,
                    node_type=NodeType.FUNCTION,
                    name=target.replace("fn::", ""),
                    data={},
                    discovered_by="iris_lite",
                    metadata={"component": "iris_lite"},
                )
            knowledge_graph.add_edge(
                source=node_id,
                target=target,
                edge_type=EdgeType.VIOLATES,
                data={"description": label},
                discovered_by="iris_lite",
                metadata={"component": "iris_lite"},
            )

    def _compute_coverage_metrics(
        self,
        contract_info: Dict[str, Any],
        knowledge_graph: Optional[KnowledgeGraph],
        taints: List[Dict[str, Any]],
        invariants: List[Any],
    ) -> Dict[str, Any]:
        total_funcs = contract_info.get("total_functions") or 0
        total_funcs = max(total_funcs, knowledge_graph.metadata.get("total_functions", 0) if knowledge_graph else 0)
        analyzed_funcs = len(knowledge_graph.metadata.get("analyzed_functions", set())) if knowledge_graph else 0
        total_funcs = max(total_funcs, analyzed_funcs)
        func_cov = analyzed_funcs / total_funcs if total_funcs else 0.0

        taint_count = len(taints)
        inv_count = len(invariants)
        denom = max(total_funcs, 1)
        taint_cov = min(taint_count / denom, 1.0)
        inv_cov = min(inv_count / denom, 1.0)

        coverage_score = round(0.5 * func_cov + 0.25 * taint_cov + 0.25 * inv_cov, 3)
        return {
            "functions_total": total_funcs,
            "functions_covered": analyzed_funcs,
            "function_coverage": func_cov,
            "taint_count": taint_count,
            "taint_coverage": taint_cov,
            "invariant_count": inv_count,
            "invariant_coverage": inv_cov,
            "coverage_score": coverage_score,
        }

    def _score_taint(self, taint: Dict[str, Any], coverage: Dict[str, Any]) -> float:
        sink = (taint.get("sink") or "").lower()
        risk = 0.55
        if any(keyword in sink for keyword in ["delegatecall", ".call", "call(", "transfer", "send"]):
            risk += 0.2
        if taint.get("source") and taint.get("sink"):
            risk += 0.05
        cov_penalty = 1.0 - coverage.get("function_coverage", 0.0)
        risk += 0.15 * cov_penalty
        return min(1.0, max(0.0, risk))

    def _score_invariant(self, invariant_label: str, coverage: Dict[str, Any]) -> float:
        base = 0.45
        cov_penalty = 1.0 - coverage.get("coverage_score", 0.0)
        risk = base + 0.25 * cov_penalty
        if "pause" in invariant_label.lower() or "reentrancy" in invariant_label.lower():
            risk += 0.05
        return min(1.0, max(0.0, risk))
