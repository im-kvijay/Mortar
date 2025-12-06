"""module docstring"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from agent.base_attacker import AttackHypothesis
from kb.knowledge_graph import KnowledgeGraph, NodeType, EdgeType


class LogicVulnScanner:
    def __init__(self, max_findings: int = 5):
        self.max_findings = max_findings
        # context-aware patterns to reduce false positives
        self._library_pattern = re.compile(r'\blibrary\s+\w+\s*\{', re.IGNORECASE)
        self._interface_pattern = re.compile(r'\binterface\s+\w+\s*\{', re.IGNORECASE)
        self._abstract_pattern = re.compile(r'\babstract\s+contract\s+\w+\s*\{', re.IGNORECASE)

    def scan(
        self,
        contract_source: str,
        contract_info: Dict[str, Any],
        knowledge_graph: Optional[KnowledgeGraph] = None,
        code_graph: Optional[Any] = None,
    ) -> List[AttackHypothesis]:
        findings: List[AttackHypothesis] = []

        # skip scanning if this is a library, interface, or abstract contract
        if self._is_library_or_interface(contract_source):
            return findings
        # pattern 1: external/public function with arbitrary call/delegatecall and no auth guard
        call_pattern = re.compile(
            r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*(public|external)([^{]*)\{(?P<body>[^}]*)\}",
            re.DOTALL,
        )
        for match in call_pattern.finditer(contract_source):
            fn_name = match.group(1)
            visibility = match.group(2)
            fn_modifiers = match.group(3) or ""
            body = match.group("body") or ""

            # context-aware filtering
            if self._is_view_or_pure(fn_modifiers):
                continue  # View/pure functions can't modify state - lower risk
            if self._has_extensive_validation(body):
                continue  # Multiple require/assert checks suggest thorough validation
            if not self._looks_unprotected(body):
                continue

            if re.search(r"\.delegatecall\s*\(", body) or re.search(r"\.call\s*\(", body):
                desc = f"Unprotected low-level execution via {fn_name}({visibility}) may allow arbitrary calls"
                hyp = self._as_hypothesis(
                    contract_info,
                    fn_name,
                    attack_type="logic",
                    description=desc,
                    evidence=["low-level call without auth guard"],
                    confidence=0.64,
                )
                self._add_graph_vuln(knowledge_graph, fn_name, "low_level_exec", desc)
                findings.append(hyp)
                if len(findings) >= self.max_findings:
                    return findings

        # pattern 2: value transfer before external call → reentrancy hint
        transfer_then_call = re.compile(
            r"transfer\([^;]+;\s*[^;]*\b([A-Za-z_][A-Za-z0-9_]*)\.[A-Za-z_][A-Za-z0-9_]*\s*\(",
            re.DOTALL,
        )
        for m in transfer_then_call.finditer(contract_source):
            fn_enclosing = self._find_enclosing_function(contract_source, m.start())
            if not fn_enclosing:
                continue
            desc = f"Reentrancy surface: value transfer before external call in {fn_enclosing}"
            hyp = self._as_hypothesis(
                contract_info,
                fn_enclosing,
                attack_type="reentrancy",
                description=desc,
                evidence=["value transfer precedes external call"],
                confidence=0.55,
            )
            self._add_graph_vuln(knowledge_graph, fn_enclosing, "reentrancy_surface", desc)
            findings.append(hyp)
            if len(findings) >= self.max_findings:
                return findings

        # pattern 3: state mutation without guard in external/public func
        state_vars = contract_info.get("state_vars") or []
        mutation_pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(\+\+|--|[+\-*/]?=)")
        for match in call_pattern.finditer(contract_source):
            fn_name = match.group(1)
            visibility = match.group(2)
            body = match.group("body") or ""
            if visibility not in {"public", "external"}:
                continue
            if self._has_auth_guard(body):
                continue
            mut_vars = set()
            for mut in mutation_pattern.finditer(body):
                var_name = mut.group(1)
                if var_name in state_vars:
                    mut_vars.add(var_name)
            if mut_vars:
                desc = f"State mutation without checks in {fn_name}: {', '.join(sorted(mut_vars))}"
                hyp = self._as_hypothesis(
                    contract_info,
                    fn_name,
                    attack_type="logic",
                    description=desc,
                    evidence=[f"mutates {', '.join(sorted(mut_vars))} without guard"],
                    confidence=0.48,
                )
                self._add_graph_vuln(knowledge_graph, fn_name, "unguarded_state_mutation", desc)
                findings.append(hyp)
                if len(findings) >= self.max_findings:
                    return findings

        # pattern 4: upgradeability surfaces without auth
        for match in call_pattern.finditer(contract_source):
            fn_name = match.group(1)
            visibility = match.group(2)
            body = match.group("body") or ""
            if visibility not in {"public", "external"}:
                continue
            if not re.search(r"upgradeTo|upgradeToAndCall", fn_name, re.IGNORECASE):
                continue
            if self._has_auth_guard(body):
                continue
            desc = f"Upgrade entrypoint {fn_name} lacks access control"
            hyp = self._as_hypothesis(
                contract_info,
                fn_name,
                attack_type="upgradeability",
                description=desc,
                evidence=["upgrade function without guard"],
                confidence=0.52,
            )
            self._add_graph_vuln(knowledge_graph, fn_name, "unguarded_upgrade", desc)
            findings.append(hyp)
            if len(findings) >= self.max_findings:
                return findings

        # pattern 5: oracle reads without sanity/freshness checks
        oracle_call = re.compile(r"(latestAnswer|getPrice|getRate|consult)\s*\(")
        for match in call_pattern.finditer(contract_source):
            fn_name = match.group(1)
            visibility = match.group(2)
            body = match.group("body") or ""
            if visibility not in {"public", "external"}:
                continue
            if not oracle_call.search(body):
                continue
            if self._has_auth_guard(body):
                continue
            if re.search(r"timestamp|stale|fresh|old|delay", body, re.IGNORECASE):
                continue
            desc = f"Oracle price read in {fn_name} lacks freshness/sanity checks"
            hyp = self._as_hypothesis(
                contract_info,
                fn_name,
                attack_type="oracle",
                description=desc,
                evidence=["oracle read without freshness/bounds"],
                confidence=0.45,
            )
            self._add_graph_vuln(knowledge_graph, fn_name, "oracle_sanity", desc)
            findings.append(hyp)
            if len(findings) >= self.max_findings:
                return findings

        # pattern 6: public setter of critical external address without guard
        critical_tokens = ("oracle", "aggregator", "price", "impl", "implementation", "admin", "proxy")
        setter_pattern = re.compile(r"\bfunction\s+(set[A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(public|external)[^{]*\{(?P<body>[^}]*)\}", re.DOTALL)
        for match in setter_pattern.finditer(contract_source):
            fn_name = match.group(1)
            args = match.group(2) or ""
            visibility = match.group(3)
            body = match.group("body") or ""
            if self._has_auth_guard(body):
                continue
            if not any(tok in fn_name.lower() or tok in args.lower() or tok in body.lower() for tok in critical_tokens):
                continue
            desc = f"Critical setter {fn_name} lacks access control"
            hyp = self._as_hypothesis(
                contract_info,
                fn_name,
                attack_type="logic",
                description=desc,
                evidence=["setter for critical address without guard"],
                confidence=0.5,
            )
            self._add_graph_vuln(knowledge_graph, fn_name, "unguarded_setter", desc)
            findings.append(hyp)
            if len(findings) >= self.max_findings:
                return findings

        # pattern 7: delegatecall to storage impl without guard
        delegate_pattern = re.compile(r"delegatecall\s*\(\s*(?:abi\.encode|[^;]+)\)")
        impl_pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.delegatecall|\bdelegatecall\s*\(\s*(?:abi\.encodeCall|abi\.encodeWithSignature|abi\.encodeWithSelector)?", re.DOTALL)
        for match in call_pattern.finditer(contract_source):
            fn_name = match.group(1)
            visibility = match.group(2)
            body = match.group("body") or ""
            if visibility not in {"public", "external"}:
                continue
            if not delegate_pattern.search(body) and not impl_pattern.search(body):
                continue
            if self._has_auth_guard(body):
                continue
            desc = f"Delegatecall surface {fn_name} without guard"
            hyp = self._as_hypothesis(
                contract_info,
                fn_name,
                attack_type="upgradeability",
                description=desc,
                evidence=["delegatecall reachable without auth"],
                confidence=0.46,
            )
            self._add_graph_vuln(knowledge_graph, fn_name, "unguarded_delegatecall", desc)
            findings.append(hyp)
            if len(findings) >= self.max_findings:
                return findings

        # pattern 8: initializer-style function without guard
        init_pattern = re.compile(r"\bfunction\s+(initialize|init)\s*\([^)]*\)\s*(public|external)[^{]*\{(?P<body>[^}]*)\}", re.DOTALL | re.IGNORECASE)
        for match in init_pattern.finditer(contract_source):
            fn_name = match.group(1)
            body = match.group("body") or ""
            if self._has_auth_guard(body):
                continue
            if re.search(r"initializer|onlyInitializing", body, re.IGNORECASE):
                continue
            desc = f"Initializer {fn_name} lacks guard; re-initialization risk"
            hyp = self._as_hypothesis(
                contract_info,
                fn_name,
                attack_type="upgradeability",
                description=desc,
                evidence=["initializer exposed without guard"],
                confidence=0.44,
            )
            self._add_graph_vuln(knowledge_graph, fn_name, "unguarded_initializer", desc)
            findings.append(hyp)
            if len(findings) >= self.max_findings:
                return findings

        return findings
    def _looks_unprotected(self, body: str) -> bool:
        return not self._has_auth_guard(body)

    def _has_auth_guard(self, body: str) -> bool:
        return bool(
            re.search(r"onlyOwner|onlyRole|auth|authenticat|owner\s*==|msg\.sender\s*==\s*\w+", body)
        )

    def _is_library_or_interface(self, source: str) -> bool:
        """Check if source is a library, interface, or abstract contract"""
        return bool(
            self._library_pattern.search(source) or
            self._interface_pattern.search(source) or
            self._abstract_pattern.search(source)
        )

    def _is_view_or_pure(self, fn_declaration: str) -> bool:
        """Check if function is view or pure (lower risk)"""
        return bool(re.search(r'\b(view|pure)\b', fn_declaration, re.IGNORECASE))

    def _has_extensive_validation(self, body: str) -> bool:
        """Check if function body has extensive validation (multiple require/assert)"""
        require_count = len(re.findall(r'\brequire\s*\(', body))
        assert_count = len(re.findall(r'\bassert\s*\(', body))
        return (require_count + assert_count) >= 3  # 3+ checks suggests thorough validation

    def _find_enclosing_function(self, source: str, pos: int) -> Optional[str]:
        pre = source[:pos]
        matches = list(re.finditer(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\b", pre))
        if matches:
            return matches[-1].group(1)
        return None

    def _as_hypothesis(
        self,
        contract_info: Dict[str, Any],
        fn_name: str,
        attack_type: str,
        description: str,
        evidence: List[str],
        confidence: float,
    ) -> AttackHypothesis:
        return AttackHypothesis(
            hypothesis_id=f"logic_scan::{fn_name}::{attack_type}",
            attack_type=attack_type,
            description=description,
            target_function=fn_name,
            preconditions=[],
            steps=[],
            expected_impact="potential arbitrary call or state corruption",
            confidence=confidence,
            requires_research=[],
            evidence=evidence,
        )

    def _add_graph_vuln(
        self,
        knowledge_graph: Optional[KnowledgeGraph],
        fn_name: str,
        vuln_kind: str,
        description: str,
    ) -> None:
        if not knowledge_graph:
            return
        fn_node = f"fn::{fn_name}"
        if not knowledge_graph.get_node(fn_node):
            knowledge_graph.add_node(
                node_id=fn_node,
                node_type=NodeType.FUNCTION,
                name=fn_name,
                data={},
                discovered_by="logic_scanner",
                metadata={"component": "logic_scan"},
            )
        vuln_node = f"vuln::{vuln_kind}::{fn_name}"
        knowledge_graph.add_node(
            node_id=vuln_node,
            node_type=NodeType.VULNERABILITY,
            name=vuln_kind,
            data={"description": description},
            discovered_by="logic_scanner",
            metadata={"component": "logic_scan"},
        )
        knowledge_graph.add_edge(
            source=vuln_node,
            target=fn_node,
            edge_type=EdgeType.VIOLATES,
            data={"description": description},
            discovered_by="logic_scanner",
            metadata={"component": "logic_scan"},
        )
