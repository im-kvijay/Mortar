"""specialist agent tools - recording and completion tools for agents."""

from typing import List, Dict, Any


def get_specialist_tools() -> List[Dict[str, Any]]:
    """get tool definitions for specialist agents."""
    return [
        {
            "name": "record_discovery",
            "description": """record a significant finding during analysis. call whenever you find something important. record early and often.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "discovery_type": {
                        "type": "string",
                        "enum": [
                            "invariant",
                            "vulnerability",
                            "assumption",
                            "state_transition",
                            "business_logic",
                            "access_control",
                            "economic_insight",
                            "dependency",
                            "edge_case"
                        ],
                        "description": "Type of discovery"
                    },
                    "content": {
                        "type": "string",
                        "description": "Detailed description of the discovery"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Your confidence in this finding (0.0-1.0)"
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Evidence supporting this discovery (code snippets, function names, etc.)"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Severity if this is a vulnerability"
                    }
                },
                "required": ["discovery_type", "content", "confidence"]
            }
        },
        {
            "name": "update_knowledge_graph",
            "description": """update knowledge graph with nodes/edges. when action='add_node', must provide node_type from enum.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["add_node", "add_edge"],
                        "description": "Whether to add a node or edge"
                    },
                    "node_type": {
                        "type": "string",
                        "enum": [
                            "function",
                            "state_variable",
                            "invariant",
                            "assumption",
                            "business_logic",
                            "dependency",
                            "vulnerability"
                        ],
                        "description": "REQUIRED for add_node. Type of node to create. Must be one of the enum values."
                    },
                    "node_id": {
                        "type": "string",
                        "description": "Unique identifier for this node"
                    },
                    "name": {
                        "type": "string",
                        "description": "Human-readable name"
                    },
                    "data": {
                        "type": "object",
                        "description": "Additional data about this node/edge"
                    },
                    "source": {
                        "type": "string",
                        "description": "Source node ID (for edges)"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target node ID (for edges)"
                    },
                    "edge_type": {
                        "type": "string",
                        "enum": ["calls", "modifies", "reads", "depends_on", "validates", "violates"],
                        "description": "Type of relationship (for edges)"
                    }
                },
                "required": ["action", "node_id", "node_type"]
            }
        },
        {
            "name": "query_knowledge_base",
            "description": """query historical vulnerability patterns. use early in analysis to learn from past contracts.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "vulnerability_type": {
                        "type": "string",
                        "description": "Vulnerability category to query (e.g., reentrancy, flash_loan)"
                    },
                    "context": {
                        "type": "string",
                        "description": "Optional extra context about what you're researching"
                    }
                }
            }
        },
        {
            "name": "get_relevant_patterns",
            "description": """retrieve patterns matching current contract features. use after initial pass.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "contract_features": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of important contract features (e.g., ['flash_loan','oracle'])"
                    }
                }
            }
        },
        {
            "name": "analysis_complete",
            "description": """signal analysis completion. only call when truly done.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Brief summary of your analysis"
                    },
                    "total_discoveries": {
                        "type": "integer",
                        "description": "Number of discoveries you made"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Your overall confidence in the analysis (0.0-1.0)"
                    },
                    "areas_covered": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "What areas you analyzed (functions, state vars, etc.)"
                    },
                    "recommended_next_steps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "What should be analyzed next (if anything)"
                    }
                },
                "required": ["summary", "confidence"]
            }
        },
        {
            "name": "check_peer_messages",
            "description": """check a2a bus for peer specialist messages. avoid duplication, coordinate analysis.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "message_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Types of messages to check: discovery, peer_review_request, status_update"
                    }
                },
                "required": []
            }
        },
        {
            "name": "publish_discovery",
            "description": """publish discovery to a2a bus for peer awareness. enables real-time collaboration.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "discovery_summary": {
                        "type": "string",
                        "description": "Brief summary of what you discovered"
                    },
                    "area_covered": {
                        "type": "string",
                        "description": "What area/function/variable you analyzed"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Your confidence in this discovery"
                    }
                },
                "required": ["discovery_summary", "area_covered"]
            }
        },
        {
            "name": "request_peer_review",
            "description": """request peer review for complex/uncertain findings. get peer validation.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "finding": {
                        "type": "string",
                        "description": "The finding you want reviewed"
                    },
                    "question": {
                        "type": "string",
                        "description": "Specific question for peers"
                    },
                    "target_specialist": {
                        "type": "string",
                        "description": "Optional: specific specialist to ask (leave empty for broadcast)"
                    }
                },
                "required": ["finding", "question"]
            }
        }
    ]


def get_attacker_tools() -> List[Dict[str, Any]]:
    """get tool definitions for attack agents."""
    return [
        {
            "name": "record_attack_hypothesis",
            "description": """record attack hypothesis. call for any potential attack vector. record even low-confidence ones.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "attack_type": {
                        "type": "string",
                        "enum": ["flash_loan", "oracle", "reentrancy", "logic", "access_control", "economic", "compositional"],
                        "description": "Type of attack"
                    },
                    "description": {
                        "type": "string",
                        "description": "What the attack does"
                    },
                    "target_function": {
                        "type": "string",
                        "description": "Primary function targeted"
                    },
                    "preconditions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "What must be true for this attack to work"
                    },
                    "steps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Step-by-step attack sequence"
                    },
                    "expected_impact": {
                        "type": "string",
                        "description": "What happens if successful"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Confidence this attack will work (0.0-1.0)"
                    },
                    "requires_research": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Questions that need JIT research"
                    }
                },
                "required": ["attack_type", "description", "target_function", "steps", "confidence"]
            }
        },
        {
            "name": "request_jit_research",
            "description": """request just-in-time research for knowledge gaps. spawns specialist agents to answer questions.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "Specific question to research"
                    },
                    "focus_area": {
                        "type": "string",
                        "enum": ["invariant", "state_flow", "business_logic", "access_control", "economic", "dependency"],
                        "description": "Which specialist should handle this"
                    },
                    "context": {
                        "type": "string",
                        "description": "Why you need this information"
                    },
                    "urgency": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": "How important is this question"
                    }
                },
                "required": ["question", "focus_area", "context"]
            }
        },
        {
            "name": "attack_analysis_complete",
            "description": """signal attack analysis completion. only call when all attack vectors explored.""",
            "input_schema": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Summary of attack analysis"
                    },
                    "total_hypotheses": {
                        "type": "integer",
                        "description": "Number of attack hypotheses found"
                    },
                    "high_confidence_attacks": {
                        "type": "integer",
                        "description": "Number of high-confidence (>0.8) attacks"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Overall confidence in analysis"
                    }
                },
                "required": ["summary", "confidence"]
            }
        }
    ]
