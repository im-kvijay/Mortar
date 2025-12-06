"""
System Invariant Analyst

A specialized agent that hunts for cross-contract vulnerabilities by analyzing
the Project Knowledge Graph. It looks for broken invariants, trust issues, and
economic loops that span multiple contracts.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path
from kb.project_graph import ProjectKnowledgeGraph
from kb.knowledge_graph import KnowledgeGraph
from research.base_specialist import EnhancedAgenticSpecialist, EnhancedAnalysisResult
from research.memory import Discovery
from utils.llm_backend import LLMBackend


class SystemInvariantAnalyst(EnhancedAgenticSpecialist):
    """
    Analyzes system-wide invariants and cross-contract logic using ProjectKnowledgeGraph.

    This specialist looks for vulnerabilities that span multiple contracts:
    - Token balance conservation across contracts
    - Access control consistency
    - Re-entrancy guard coverage across call chains
    - Trust assumption violations
    """

    def __init__(
        self,
        project_graph: ProjectKnowledgeGraph,
        project_root: Optional[str] = None,
        backend: Optional[LLMBackend] = None,
        backend_type: Optional[str] = None,
        model: Optional[str] = None,
        cost_limit: Optional[float] = None,
        thinking_budget: Optional[int] = None,
        enable_interleaved_thinking: Optional[bool] = None,
        **kwargs
    ):
        """
        Initialize SystemInvariantAnalyst with ProjectKnowledgeGraph

        Args:
            project_graph: Project knowledge graph with cross-contract edges
            project_root: Project root directory
            backend: LLM backend
            backend_type: Backend type
            model: Model name
            cost_limit: Maximum cost
            thinking_budget: Thinking token budget
            enable_interleaved_thinking: Enable thinking between tool calls
        """
        super().__init__(
            name="SystemInvariant",
            description="Analyzes cross-contract invariants and system-wide vulnerabilities",
            project_root=project_root,
            backend=backend,
            backend_type=backend_type,
            model=model,
            cost_limit=cost_limit,
            thinking_budget=thinking_budget,
            enable_interleaved_thinking=enable_interleaved_thinking,
            **kwargs
        )
        self.pkg = project_graph

    def get_system_prompt(self) -> str:
        return """You are a System Invariant Analyst specializing in cross-contract vulnerabilities.

Your mission: Identify vulnerabilities that span multiple contracts.

Focus areas:
1. Token balance conservation across contracts
2. Access control consistency between related contracts
3. Re-entrancy guard coverage across call chains
4. Trust assumptions (Contract A trusts B, but B is upgradeable)
5. State synchronization issues
6. Economic loops and arbitrage opportunities

Use the Project Knowledge Graph to trace interactions between contracts."""

    def get_analysis_prompt(self, contract_source: str, contract_info: Dict[str, Any]) -> str:
        """
        Generate analysis prompt for system-wide invariant checking

        Note: This analyst works at the system level, not individual contracts.
        This method is kept for compatibility with the base class.
        """
        return f"""Analyze the system-wide invariants for this project.

Contract: {contract_info.get('name', 'Unknown')}

This contract is part of a larger system. Look for:
- Cross-contract vulnerabilities
- System-wide invariant violations
- Trust assumption issues

Use the tools available to trace interactions across contracts."""

    def analyze_system(self, knowledge_graph: Optional[KnowledgeGraph] = None) -> List[EnhancedAnalysisResult]:
        """
        Perform system-wide analysis using ProjectKnowledgeGraph

        Args:
            knowledge_graph: Optional individual contract KG (for compatibility)

        Returns:
            List of analysis results with system-wide findings
        """
        import time
        start_time = time.time()
        discoveries = []

        # 1. Deterministic Graph Analysis
        cycles = self.pkg.find_cycles()
        central_nodes = self.pkg.find_central_nodes()

        # Auto-report cycles as discoveries
        for cycle in cycles:
            # Filter out self-loops if any
            if len(cycle) < 2:
                continue

            affected_contracts = list(set([n.split(':')[0] for n in cycle]))
            discoveries.append(Discovery(
                round_num=0,  # System-wide analysis is round 0
                discovery_type="vulnerability",
                content=f"Circular Dependency Detected: Cycle found in {' -> '.join(cycle)}. This can lead to reentrancy or deadlock issues. Affected contracts: {', '.join(affected_contracts)}",
                confidence=0.8,
                evidence=[f"cycle: {' -> '.join(cycle)}", f"affected_contracts: {', '.join(affected_contracts)}"]
            ))

        # 2. LLM-based Analysis
        prompt = self._build_system_prompt(cycles, central_nodes)

        try:
            response = self.backend.generate(
                prompt=prompt,
                max_tokens=2000,
                temperature=0.1
            )
            # Handle both string (mock) and LLMResponse object
            text = response.text if hasattr(response, 'text') else str(response)
            llm_findings = self._parse_findings_to_discoveries(text)
            discoveries.extend(llm_findings)

            cost = getattr(response, 'cost', 0.0)
        except Exception as e:
            self.logger.error(f"[SystemInvariant] LLM analysis failed: {e}")
            cost = 0.0

        # 3. Build result
        duration = time.time() - start_time
        result = EnhancedAnalysisResult(
            discoveries=discoveries,
            graph_updates=[],
            tool_calls=[],
            functional_analyses=[],
            reflections=[],
            summary=f"System-wide analysis complete. Found {len(discoveries)} potential issues across {len(self.pkg.contracts)} contracts.",
            confidence=0.85,
            areas_covered=["cross_contract_calls", "circular_dependencies", "trust_assumptions"],
            total_discoveries=len(discoveries),
            cost=cost,
            duration_seconds=duration,
            analysis_complete=True
        )

        return [result]

    def _build_system_prompt(self, cycles: List[List[str]], central_nodes: List[tuple]) -> str:
        """Construct prompt for the LLM"""
        
        graph_summary = self.pkg.to_dict()
        
        # Format central nodes
        critical_components = "\n".join([f"- {node} (Score: {score:.4f})" for node, score in central_nodes])
        
        return f"""
You are a Senior System Architect and Security Auditor.
Your task is to analyze the entire smart contract system for cross-contract vulnerabilities.

## System Topology
- Nodes: {len(graph_summary['nodes'])}
- Edges: {len(graph_summary['edges'])}

## Critical Components (Centrality Analysis)
{critical_components}

## Detected Cycles
{cycles if cycles else "None detected."}

## Graph Data (JSON)
```json
{graph_summary}
```

## Instructions
Identify 3-5 potential system-level issues. Focus on:
1. **Broken Trust**: Contract A trusts B, but B is upgradeable or has weak access control.
2. **Inconsistent State**: Logic split across contracts that might get out of sync.
3. **Economic Loops**: Flash loan loops or arbitrage opportunities across multiple contracts.
4. **Missing Validation**: Inputs passed between contracts without re-validation.

## Output Format
Return a JSON list of findings:
[
    {{
        "title": "Brief Title",
        "description": "Detailed explanation of the cross-contract bug.",
        "severity": "High|Medium|Low",
        "affected_contracts": ["ContractA", "ContractB"]
    }}
]
"""



    def _parse_findings_to_discoveries(self, text: str) -> List[Discovery]:
        """Parse JSON response and convert to Discovery objects"""
        import json
        import re

        results = []
        try:
            # Extract JSON
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if not match:
                return []

            data = json.loads(match.group(0))

            for item in data:
                severity = item.get("severity", "Medium").lower()
                # Map severity to confidence
                confidence_map = {"high": 0.9, "medium": 0.7, "low": 0.5}
                confidence = confidence_map.get(severity, 0.7)

                affected_contracts = item.get("affected_contracts", [])
                title = item.get("title", "Unknown Issue")
                description = item.get("description", "")
                results.append(Discovery(
                    round_num=0,  # System-wide analysis is round 0
                    discovery_type="vulnerability",
                    content=f"{title}: {description} (Severity: {severity}). Affected contracts: {', '.join(affected_contracts) if affected_contracts else 'System-wide'}",
                    confidence=confidence,
                    evidence=[f"affected_contracts: {', '.join(affected_contracts)}", "source: llm_analysis"]
                ))
        except Exception as e:
            self.logger.warning(f"[SystemInvariant] Failed to parse findings: {e}")

        return results
