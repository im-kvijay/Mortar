"""
Consolidated tool definitions for specialist agents.
"""

from typing import List, Dict, Any, Optional
import re
import json


def get_consolidated_tools() -> List[Dict[str, Any]]:
    """get consolidated tool definitions - 5 core tools with multi-action support"""
    return [
        {
            "name": "analyze",
            "description": """unified analysis tool - perform code analysis.

combines multiple analysis capabilities:
- trace: track state variable mutations and reads
- symbolic: symbolic execution on functions
- static: run static security checks
- search: semantic code search

usage examples:

1. trace a state variable:
   analyze(action="trace", target="totalAssets")
   → returns: mutations, reads, functions that modify it

2. analyze a function symbolically:
   analyze(action="symbolic", target="deposit")
   → returns: preconditions, mutations, external calls, reentrancy risk

3. run static analysis:
   analyze(action="static", focus="reentrancy")
   → returns: security findings for the focus area

4. search codebase:
   analyze(action="search", target="fee calculation")
   → returns: relevant code snippets

tip: combine actions in sequence to build understanding:
  1. analyze(action="trace", target="balance") - understand state
  2. analyze(action="symbolic", target="withdraw") - analyze function
  3. analyze(action="static", focus="all") - check for issues""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["trace", "symbolic", "static", "search"],
                        "description": "Analysis action to perform"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target of analysis (variable name, function name, or search query)"
                    },
                    "focus": {
                        "type": "string",
                        "enum": ["all", "reentrancy", "overflow", "access", "calls"],
                        "description": "Focus area for static analysis (only used when action=static)"
                    },
                    "depth": {
                        "type": "string",
                        "enum": ["quick", "thorough"],
                        "description": "Analysis depth (default: thorough)"
                    }
                },
                "required": ["action", "target"]
            }
        },
        {
            "name": "verify",
            "description": """verification tool - validate findings and check invariants.

combines verification capabilities:
- invariant: check if an invariant holds
- reflect: self-critique a finding
- pattern: compare against known vulnerability patterns
- kb: query knowledge base for historical patterns

usage examples:

1. check an invariant:
   verify(action="invariant", claim="totalAssets == balanceOf(this)", evidence="require(...)")
   → returns: whether invariant holds, concerns

2. reflect on a finding (self-critique):
   verify(action="reflect", claim="deposit() vulnerable to reentrancy", confidence=0.8)
   → returns: adjusted confidence, reflection notes

3. compare with known patterns:
   verify(action="pattern", pattern="flash_loan_dos")
   → returns: match score, matching indicators

4. query knowledge base:
   verify(action="kb", query="reentrancy")
   → returns: historical patterns, relevant past findings

tip: always reflect before recording high-confidence findings!""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["invariant", "reflect", "pattern", "kb"],
                        "description": "Verification action to perform"
                    },
                    "claim": {
                        "type": "string",
                        "description": "The claim/invariant/finding to verify"
                    },
                    "evidence": {
                        "type": "string",
                        "description": "Code evidence supporting the claim (for invariant checks)"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Initial confidence (for reflection)"
                    },
                    "pattern": {
                        "type": "string",
                        "enum": ["flash_loan_dos", "oracle_manipulation", "reentrancy"],
                        "description": "Pattern to check against (for pattern action)"
                    },
                    "query": {
                        "type": "string",
                        "description": "Query for knowledge base (for kb action)"
                    }
                },
                "required": ["action"]
            }
        },
        {
            "name": "record",
            "description": """recording tool - save findings and build knowledge graph.

combines recording capabilities:
- discovery: record a significant finding
- graph_node: add a node to the knowledge graph
- graph_edge: add an edge (relationship) to the graph

critical: record discoveries immediately when you find them!
do not wait until the end to batch record!

usage examples:

1. record a discovery:
   record(action="discovery", type="vulnerability", content="deposit() lacks access control",
          confidence=0.85, evidence=["no onlyOwner modifier"])

2. add a graph node:
   record(action="graph_node", node_id="totalAssets", node_type="state_variable",
          data={"type": "uint256", "visibility": "public"})

3. add a graph edge:
   record(action="graph_edge", source="deposit", target="totalAssets",
          edge_type="modifies", data={"operation": "increases"})

tip: build the graph as you explore - relationships matter more than isolated facts!""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["discovery", "graph_node", "graph_edge"],
                        "description": "Recording action to perform"
                    },
                    "type": {
                        "type": "string",
                        "enum": ["invariant", "vulnerability", "assumption", "state_transition",
                                 "business_logic", "access_control", "economic_insight",
                                 "dependency", "edge_case"],
                        "description": "Discovery type (for discovery action)"
                    },
                    "content": {
                        "type": "string",
                        "description": "Discovery content/description"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Confidence in this finding"
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Evidence supporting the discovery"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Severity if this is a vulnerability"
                    },
                    "node_id": {
                        "type": "string",
                        "description": "Node ID (for graph operations)"
                    },
                    "node_type": {
                        "type": "string",
                        "enum": ["function", "state_variable", "invariant", "assumption",
                                 "business_logic", "dependency", "vulnerability"],
                        "description": "Node type (for graph_node)"
                    },
                    "source": {
                        "type": "string",
                        "description": "Source node ID (for graph_edge)"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target node ID (for graph_edge)"
                    },
                    "edge_type": {
                        "type": "string",
                        "enum": ["calls", "modifies", "reads", "depends_on", "validates", "violates"],
                        "description": "Relationship type (for graph_edge)"
                    },
                    "data": {
                        "type": "object",
                        "description": "Additional metadata"
                    }
                },
                "required": ["action"]
            }
        },
        {
            "name": "collaborate",
            "description": """collaboration tool - coordinate with peer specialists (a2a).

combines peer collaboration capabilities:
- check: check for new messages from peers
- publish: share a discovery with peers
- review: request peer review of a finding

usage examples:

1. check peer messages:
   collaborate(action="check", types=["discovery", "peer_review"])
   → returns: new messages from peers

2. publish a discovery:
   collaborate(action="publish", summary="Found reentrancy in withdraw()",
               area="reentrancy", confidence=0.9)

3. request peer review:
   collaborate(action="review", finding="deposit() may be vulnerable",
               question="Does this bypass the reentrancy guard?")

tip: check peers periodically to avoid duplicate work!""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["check", "publish", "review"],
                        "description": "Collaboration action to perform"
                    },
                    "types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Message types to check (for check action)"
                    },
                    "summary": {
                        "type": "string",
                        "description": "Discovery summary (for publish action)"
                    },
                    "area": {
                        "type": "string",
                        "description": "Area covered (for publish action)"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Confidence level"
                    },
                    "finding": {
                        "type": "string",
                        "description": "Finding to review (for review action)"
                    },
                    "question": {
                        "type": "string",
                        "description": "Question for peers (for review action)"
                    },
                    "target_specialist": {
                        "type": "string",
                        "description": "Optional: specific specialist to ask"
                    }
                },
                "required": ["action"]
            }
        },
        {
            "name": "complete",
            "description": """completion signal - signal that analysis is complete.

call this when you're satisfied you've thoroughly analyzed the contract.

before calling, ensure you've:
✓ traced all critical state variables
✓ analyzed all public/external functions
✓ checked for common vulnerabilities
✓ recorded all significant findings
✓ built the knowledge graph with key relationships
✓ explored multi-step attack paths

only call when you can confidently say:
"i have exhausted all analysis paths."

don't stop early - if you've only made 5-10 tool calls, keep going!""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Brief summary of your analysis"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Overall confidence in analysis completeness"
                    },
                    "discoveries_count": {
                        "type": "integer",
                        "description": "Number of discoveries made"
                    },
                    "areas_covered": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Areas you analyzed"
                    },
                    "next_steps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Recommended follow-up analysis"
                    }
                },
                "required": ["summary", "confidence"]
            }
        }
    ]


class ConsolidatedToolExecutor:
    """executor for consolidated tools - routes tool calls to underlying implementations"""

    def __init__(
        self,
        functional_tools: Any,  # FunctionalAnalysisTools instance
        knowledge_graph: Any,
        knowledge_base: Optional[Any] = None,
        a2a_bus: Optional[Any] = None,
        a2a_agent_id: Optional[str] = None,
        logger: Optional[Any] = None,
    ):
        self.functional_tools = functional_tools
        self.knowledge_graph = knowledge_graph
        self.knowledge_base = knowledge_base
        self.a2a_bus = a2a_bus
        self.a2a_agent_id = a2a_agent_id
        self.logger = logger

        # track discoveries for context compression
        self.discoveries: List[Dict[str, Any]] = []
        self.graph_updates: List[Dict[str, Any]] = []

    def execute(self, tool_name: str, tool_input: Dict[str, Any]) -> Dict[str, Any]:
        """execute a consolidated tool call"""
        if tool_name == "analyze":
            return self._execute_analyze(tool_input)
        elif tool_name == "verify":
            return self._execute_verify(tool_input)
        elif tool_name == "record":
            return self._execute_record(tool_input)
        elif tool_name == "collaborate":
            return self._execute_collaborate(tool_input)
        elif tool_name == "complete":
            return self._execute_complete(tool_input)
        else:
            return {"error": f"Unknown tool: {tool_name}"}

    def _execute_analyze(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """execute analyze tool"""
        action = params.get("action")
        target = params.get("target", "")

        if action == "trace":
            return self.functional_tools.trace_state_variable(target)

        elif action == "symbolic":
            return self.functional_tools.analyze_function_symbolically(target)

        elif action == "static":
            focus = params.get("focus", "all")
            return self.functional_tools.run_static_analysis(focus)

        elif action == "search":
            return self.functional_tools.get_relevant_code(target)

        return {"error": f"Unknown analyze action: {action}"}

    def _execute_verify(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """execute verify tool"""
        action = params.get("action")

        if action == "invariant":
            claim = params.get("claim", "")
            evidence = params.get("evidence", "")
            return self.functional_tools.check_invariant(claim, evidence)

        elif action == "reflect":
            claim = params.get("claim", "")
            confidence = params.get("confidence", 0.5)
            return self.functional_tools.reflect_on_finding(claim, confidence)

        elif action == "pattern":
            pattern = params.get("pattern", "")
            return self.functional_tools.compare_with_pattern(pattern)

        elif action == "kb":
            if not self.knowledge_base:
                return {"error": "Knowledge base not available"}

            query = params.get("query", "")
            try:
                patterns = self.knowledge_base.get_patterns_by_type(query)
                if not patterns:
                    patterns = self.knowledge_base.get_high_confidence_patterns()
                return {
                    "query": query,
                    "patterns_found": len(patterns),
                    "patterns": [
                        {
                            "id": getattr(p, "id", "unknown"),
                            "name": getattr(p, "name", "unknown"),
                            "type": getattr(p, "vuln_type", "unknown"),
                            "confidence": round(float(getattr(p, "confidence", 0)), 2),
                        }
                        for p in patterns[:5]
                    ]
                }
            except Exception as e:
                return {"error": f"KB query failed: {e}"}

        return {"error": f"Unknown verify action: {action}"}

    def _execute_record(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """execute record tool"""
        action = params.get("action")

        if action == "discovery":
            discovery = {
                "type": params.get("type", "unknown"),
                "content": params.get("content", ""),
                "confidence": params.get("confidence", 0.5),
                "evidence": params.get("evidence", []),
                "severity": params.get("severity"),
            }
            self.discoveries.append(discovery)

            if self.logger:
                self.logger.log_discovery(
                    agent_name="consolidated",
                    contract_name="unknown",
                    discovery_type=discovery["type"],
                    content=discovery["content"],
                    confidence=discovery["confidence"],
                    evidence=discovery["evidence"],
                )

            return {"status": "recorded", "discovery": discovery}

        elif action == "graph_node":
            node_id = params.get("node_id")
            node_type = params.get("node_type", "business_logic")
            data = params.get("data", {})

            if not node_id:
                return {"error": "node_id required for graph_node"}

            update = {
                "type": "node",
                "node_id": node_id,
                "node_type": node_type,
                "data": data,
            }
            self.graph_updates.append(update)

            # add to actual graph if available
            if self.knowledge_graph:
                try:
                    from kb.knowledge_graph import NodeType
                    type_map = {
                        "function": NodeType.FUNCTION,
                        "state_variable": NodeType.STATE_VAR,
                        "invariant": NodeType.INVARIANT,
                        "assumption": NodeType.ASSUMPTION,
                        "business_logic": NodeType.BUSINESS_LOGIC,
                        "dependency": NodeType.DEPENDENCY,
                        "vulnerability": NodeType.VULNERABILITY,
                    }
                    nt = type_map.get(node_type, NodeType.BUSINESS_LOGIC)
                    self.knowledge_graph.add_node(
                        node_id=node_id,
                        node_type=nt,
                        name=node_id,
                        data=data,
                        discovered_by="consolidated_tools",
                    )
                except Exception as e:
                    return {"status": "recorded_locally", "error": f"Graph add failed: {e}"}

            return {"status": "recorded", "node_id": node_id}

        elif action == "graph_edge":
            source = params.get("source")
            target = params.get("target")
            edge_type = params.get("edge_type", "depends_on")
            data = params.get("data", {})

            if not source or not target:
                return {"error": "source and target required for graph_edge"}

            update = {
                "type": "edge",
                "source": source,
                "target": target,
                "edge_type": edge_type,
                "data": data,
            }
            self.graph_updates.append(update)

            if self.knowledge_graph:
                try:
                    from kb.knowledge_graph import EdgeType
                    type_map = {
                        "calls": EdgeType.CALLS,
                        "modifies": EdgeType.MODIFIES,
                        "reads": EdgeType.READS,
                        "depends_on": EdgeType.DEPENDS_ON,
                        "validates": EdgeType.VALIDATES,
                        "violates": EdgeType.VIOLATES,
                    }
                    et = type_map.get(edge_type, EdgeType.DEPENDS_ON)
                    self.knowledge_graph.add_edge(
                        source=source,
                        target=target,
                        edge_type=et,
                        data=data,
                        discovered_by="consolidated_tools",
                    )
                except Exception as e:
                    return {"status": "recorded_locally", "error": f"Edge add failed: {e}"}

            return {"status": "recorded", "edge": f"{source} -> {target}"}

        return {"error": f"Unknown record action: {action}"}

    def _execute_collaborate(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """execute collaborate tool"""
        action = params.get("action")

        if not self.a2a_bus or not self.a2a_agent_id:
            return {"status": "A2A not enabled"}

        if action == "check":
            try:
                from agent.a2a_bus import A2AMessage, MessageType
                types = params.get("types", [])
                messages, _ = self.a2a_bus.get_messages(self.a2a_agent_id, message_types=types)

                if not messages:
                    return {"status": "no_messages"}

                return {
                    "status": "messages_found",
                    "count": len(messages),
                    "messages": [
                        {
                            "from": m.from_agent,
                            "type": m.message_type.value,
                            "payload": m.payload,
                        }
                        for m in messages[:5]
                    ]
                }
            except Exception as e:
                return {"error": f"Check failed: {e}"}

        elif action == "publish":
            try:
                from agent.a2a_bus import A2AMessage, MessageType
                import uuid
                import time as time_module

                message = A2AMessage(
                    message_id=str(uuid.uuid4()),
                    from_agent=self.a2a_agent_id,
                    to_agent="broadcast",
                    message_type=MessageType.DISCOVERY,
                    payload={
                        "discovery_summary": params.get("summary", ""),
                        "area_covered": params.get("area", ""),
                        "confidence": params.get("confidence", 0.8),
                    },
                    metadata={"timestamp": time_module.time()},
                )
                self.a2a_bus.publish(message)
                return {"status": "published"}
            except Exception as e:
                return {"error": f"Publish failed: {e}"}

        elif action == "review":
            try:
                from agent.a2a_bus import A2AMessage, MessageType
                import uuid
                import time as time_module

                message = A2AMessage(
                    message_id=str(uuid.uuid4()),
                    from_agent=self.a2a_agent_id,
                    to_agent=params.get("target_specialist", "broadcast"),
                    message_type=MessageType.PEER_REVIEW_REQUEST,
                    payload={
                        "finding": params.get("finding", ""),
                        "question": params.get("question", ""),
                    },
                    metadata={"timestamp": time_module.time()},
                )
                self.a2a_bus.publish(message)
                return {"status": "review_requested"}
            except Exception as e:
                return {"error": f"Review request failed: {e}"}

        return {"error": f"Unknown collaborate action: {action}"}

    def _execute_complete(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """execute complete tool"""
        return {
            "status": "complete",
            "summary": params.get("summary", ""),
            "confidence": params.get("confidence", 0.8),
            "discoveries_count": params.get("discoveries_count", len(self.discoveries)),
            "areas_covered": params.get("areas_covered", []),
            "next_steps": params.get("next_steps", []),
        }


def get_tool_consolidation_map() -> Dict[str, str]:
    """map from old tool names to new consolidated tool calls for backward compatibility"""
    return {
        # analyze tools
        "trace_state_variable": 'analyze(action="trace", target="{variable_name}")',
        "analyze_function_symbolically": 'analyze(action="symbolic", target="{function_name}")',
        "run_static_analysis": 'analyze(action="static", focus="{focus}")',
        "get_relevant_code": 'analyze(action="search", target="{query}")',

        # verify tools
        "check_invariant": 'verify(action="invariant", claim="{invariant}", evidence="{evidence}")',
        "reflect_on_finding": 'verify(action="reflect", claim="{finding}", confidence={confidence})',
        "compare_with_pattern": 'verify(action="pattern", pattern="{pattern_name}")',
        "query_knowledge_base": 'verify(action="kb", query="{vulnerability_type}")',
        "get_relevant_patterns": 'verify(action="kb", query="{contract_features}")',

        # record tools
        "record_discovery": 'record(action="discovery", type="{discovery_type}", ...)',
        "update_knowledge_graph": 'record(action="graph_node|graph_edge", ...)',

        # collaborate tools
        "check_peer_messages": 'collaborate(action="check", types=[...])',
        "publish_discovery": 'collaborate(action="publish", summary="...", area="...")',
        "request_peer_review": 'collaborate(action="review", finding="...", question="...")',

        # complete tool
        "analysis_complete": 'complete(summary="...", confidence=...)',
    }
