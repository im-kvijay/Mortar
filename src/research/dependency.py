"""
Dependency Analyst (V3)

Agentic specialist for external dependency and oracle analysis.
"""

from typing import Dict, Any, List, Tuple, Optional
import threading
from src.research.base_specialist import EnhancedAgenticSpecialist
from kb.knowledge_graph import KnowledgeGraph, EdgeType, NodeType


class EnhancedDependencyAnalyst(EnhancedAgenticSpecialist):
    """Dependency Specialist - finds exploitable external dependencies."""

    def __init__(self, **kwargs):
        super().__init__(
            name="DependencyAnalyst_V3",
            description="Finds exploitable external dependencies and oracle risks",
            **kwargs
        )
        self._taint_lock = threading.Lock()
        self._taint_traces: List[Tuple[str, str]] = []
        self._graph: Optional[KnowledgeGraph] = None
        self._contract_name: str = "unknown"

    def get_system_prompt(self) -> str:
        return """You are a dependency analyst. Find exploitable external dependencies.

YOUR DOMAIN:
1. External Dependencies: Oracles, AMMs, governance contracts
2. Trust Assumptions: What does contract assume about externals?
3. Oracle Risks: Can price feeds be manipulated?
4. Cross-Contract Calls: External call locations and risks
5. Integration Vulnerabilities: Exploitable external systems

NOT YOUR DOMAIN:
- Business logic -> BusinessLogic specialist
- Access control -> AccessControl specialist

APPROACH:
1. run_static_analysis() to find external calls
2. trace_state_variable() on external address variables
3. analyze_function_symbolically() on functions making external calls
4. check_invariant() for trust assumptions (price freshness, bounds)
5. reflect_on_finding() before recording
6. compare_with_pattern() for oracle_manipulation, reentrancy

KEY QUESTIONS:
- Can external data be manipulated (flash loan, TWAP attack)?
- Are there freshness/bounds checks on oracle prices?
- What's the impact if external returns malicious data?"""

    def get_analysis_prompt(
        self,
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> str:
        contract_name = contract_info.get("name", "Unknown")
        functions = contract_info.get("functions", [])
        state_vars = contract_info.get("state_vars", [])
        system_context = contract_info.get("system_context")
        system_block = f"\nSYSTEM CONTEXT:\n{system_context}\n" if system_context else ""

        return f"""Analyze this contract's external dependencies for vulnerabilities.

CONTRACT: {contract_name}

SOURCE:
```solidity
{contract_source}
```

METADATA:
- Functions: {', '.join(functions[:10])}
- State Variables: {', '.join(state_vars[:10])}
{system_block}

TASK: Find exploitable external dependencies - oracle manipulation, unsafe external calls.

WORKFLOW:
1. run_static_analysis() - find external calls
2. Identify dependencies (oracles, AMMs, interfaces, delegatecalls)
3. trace_state_variable() on external address vars
4. analyze_function_symbolically() on functions with external calls
5. check_invariant() for trust assumptions
6. reflect_on_finding() before recording
7. record_discovery() for each finding
8. analysis_complete() when done

Think between tool calls. Record findings immediately."""

    def attach_graph(self, graph: KnowledgeGraph, contract_name: str) -> None:
        self._graph = graph
        self._contract_name = contract_name

    def record_taint(self, source_var: str, sink_call: str) -> None:
        """
        Capture user-controlled input flowing to an external call.
        """
        if not self._graph:
            return
        trace_id = (source_var, sink_call)
        # Thread-safe check and append
        with self._taint_lock:
            if trace_id in self._taint_traces:
                return
            self._taint_traces.append(trace_id)

        call_node = f"call::{sink_call}"
        if not self._graph.get_node(call_node):
            self._graph.add_node(
                node_id=call_node,
                node_type=NodeType.DEPENDENCY,
                name=sink_call,
                data={"type": "external_call"},
                discovered_by=self.name,
                metadata={"component": "dependency"},
            )

        src_node = f"state::{source_var}"
        if not self._graph.get_node(src_node):
            self._graph.add_node(
                node_id=src_node,
                node_type=NodeType.STATE_VAR,
                name=source_var,
                data={},
                discovered_by=self.name,
                metadata={"component": "dependency"},
            )

        self._graph.add_edge(
            source=src_node,
            target=call_node,
            edge_type=EdgeType.DEPENDS_ON,
            data={"taint": True},
            discovered_by=self.name,
            metadata={"component": "dependency", "taint": True},
        )

# backwards compat
DependencyAnalyst = EnhancedDependencyAnalyst
