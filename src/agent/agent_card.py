"""module docstring"""

from dataclasses import dataclass, field, asdict
from typing import List, Tuple, Dict, Any, Optional
from enum import Enum
import json
from datetime import datetime, UTC


class AgentType(Enum):
    """Agent type classification"""
    RESEARCH = "research"  # V3 specialists (BusinessLogic, StateFlow, etc.)
    ATTACK = "attack"  # Attack agents (FlashLoan, Oracle, etc.)
    VERIFICATION = "verification"  # Verification layer agents
    AGGREGATION = "aggregation"  # Meta-aggregator, supervisor
    ORCHESTRATION = "orchestration"  # Orchestrator, coordinator


class AgentStatus(Enum):
    """Agent availability status"""
    AVAILABLE = "available"  # Ready to accept requests
    BUSY = "busy"  # Currently processing a request
    OFFLINE = "offline"  # Not available


@dataclass
class AgentCapability:
    """
    Specific capability that an agent provides

    Attributes:
        name: Capability name (e.g., "reentrancy_detection")
        description: Human-readable description
        input_format: Expected input structure
        output_format: Expected output structure
        confidence_range: Typical confidence range for this capability
        cost_estimate: Estimated cost per invocation (USD)
    """
    name: str
    description: str
    input_format: str  # e.g., "Dict[contract_code, function_name]"
    output_format: str  # e.g., "List[Discovery]"
    confidence_range: Tuple[float, float] = (0.0, 1.0)
    cost_estimate: float = 0.0  # USD


@dataclass
class AgentCard:
    """
    A2A Agent Card - advertises agent capabilities

    This is the core of A2A protocol. Each agent creates a card that describes
    what it can do, allowing other agents to discover and coordinate with it.

    Attributes:
        agent_id: Unique identifier (e.g., "BusinessLogicSpecialist_v3")
        agent_type: Type of agent (research, attack, verification, etc.)
        agent_name: Human-readable name
        specialization: Specific domain (e.g., "BusinessLogic", "FlashLoan")
        capabilities: List of capabilities this agent provides
        tools: List of tools available to this agent
        confidence_range: Overall confidence range for this agent
        cost_per_request: Estimated cost per request (USD)
        status: Current availability status
        peer_review_support: Can this agent review other agents' findings?
        delegation_support: Can this agent delegate to other agents?
        metadata: Additional metadata (version, creation_time, etc.)
    """
    agent_id: str
    agent_type: AgentType
    agent_name: str
    specialization: str
    capabilities: List[AgentCapability]
    tools: List[str] = field(default_factory=list)
    confidence_range: Tuple[float, float] = (0.0, 1.0)
    cost_per_request: float = 0.0  # USD
    status: AgentStatus = AgentStatus.AVAILABLE
    peer_review_support: bool = True
    delegation_support: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate and enrich metadata"""
        if 'created_at' not in self.metadata:
            self.metadata['created_at'] = datetime.now(UTC).isoformat()
        if 'version' not in self.metadata:
            self.metadata['version'] = '1.0.0'

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (for JSON serialization)"""
        return {
            'agent_id': self.agent_id,
            'agent_type': self.agent_type.value,
            'agent_name': self.agent_name,
            'specialization': self.specialization,
            'capabilities': [
                {
                    'name': cap.name,
                    'description': cap.description,
                    'input_format': cap.input_format,
                    'output_format': cap.output_format,
                    'confidence_range': cap.confidence_range,
                    'cost_estimate': cap.cost_estimate
                }
                for cap in self.capabilities
            ],
            'tools': self.tools,
            'confidence_range': self.confidence_range,
            'cost_per_request': self.cost_per_request,
            'status': self.status.value,
            'peer_review_support': self.peer_review_support,
            'delegation_support': self.delegation_support,
            'metadata': self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentCard':
        """Create from dictionary (for JSON deserialization)"""
        capabilities = [
            AgentCapability(
                name=cap['name'],
                description=cap['description'],
                input_format=cap['input_format'],
                output_format=cap['output_format'],
                confidence_range=tuple(cap['confidence_range']),
                cost_estimate=cap['cost_estimate']
            )
            for cap in data['capabilities']
        ]

        return cls(
            agent_id=data['agent_id'],
            agent_type=AgentType(data['agent_type']),
            agent_name=data['agent_name'],
            specialization=data['specialization'],
            capabilities=capabilities,
            tools=data['tools'],
            confidence_range=tuple(data['confidence_range']),
            cost_per_request=data['cost_per_request'],
            status=AgentStatus(data['status']),
            peer_review_support=data['peer_review_support'],
            delegation_support=data['delegation_support'],
            metadata=data['metadata']
        )

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> 'AgentCard':
        """Create from JSON string"""
        return cls.from_dict(json.loads(json_str))

    def has_capability(self, capability_name: str) -> bool:
        """Check if agent has a specific capability"""
        return any(cap.name == capability_name for cap in self.capabilities)

    def get_capability(self, capability_name: str) -> Optional[AgentCapability]:
        """Get a specific capability by name"""
        for cap in self.capabilities:
            if cap.name == capability_name:
                return cap
        return None

    def update_status(self, new_status: AgentStatus):
        """Update agent status"""
        self.status = new_status
        self.metadata['last_status_update'] = datetime.now(UTC).isoformat()


# factory functions: create agent cards for existing agents

def create_research_specialist_card(
    specialization: str,
    agent_id: Optional[str] = None,
    tools: Optional[List[str]] = None
) -> AgentCard:
    """
    Create Agent Card for V3 Research Specialist

    Args:
        specialization: Specialist type (BusinessLogic, StateFlow, etc.)
        agent_id: Optional custom ID (defaults to {specialization}Specialist_v3)
        tools: Optional tool list (defaults to standard V3 tools)

    Returns:
        Agent Card for research specialist
    """
    if agent_id is None:
        agent_id = f"{specialization}Specialist_v3"

    if tools is None:
        tools = [
            'trace_state_variable',
            'analyze_function_symbolically',
            'check_invariant',
            'compare_with_pattern',
            'search_similar_code',
            'simulate_execution_path',
            'reflect_on_finding',
            'record_discovery',
            'analysis_complete'
        ]

    # map specialization to capabilities
    capability_map = {
        'BusinessLogic': [
            AgentCapability(
                name='business_logic_analysis',
                description='Deep analysis of business logic flaws and edge cases',
                input_format='Dict[contract_code, target_functions]',
                output_format='List[Discovery]',
                confidence_range=(0.75, 0.95),
                cost_estimate=0.15
            ),
            AgentCapability(
                name='edge_case_detection',
                description='Identify edge cases and boundary condition bugs',
                input_format='Dict[contract_code, function_name]',
                output_format='List[Discovery]',
                confidence_range=(0.70, 0.90),
                cost_estimate=0.12
            )
        ],
        'StateFlow': [
            AgentCapability(
                name='state_transition_analysis',
                description='Analyze state transitions and flow vulnerabilities',
                input_format='Dict[contract_code, state_variables]',
                output_format='List[Discovery]',
                confidence_range=(0.75, 0.95),
                cost_estimate=0.15
            ),
            AgentCapability(
                name='state_corruption_detection',
                description='Detect state corruption and inconsistencies',
                input_format='Dict[contract_code, state_variables]',
                output_format='List[Discovery]',
                confidence_range=(0.70, 0.90),
                cost_estimate=0.12
            )
        ],
        'Invariant': [
            AgentCapability(
                name='invariant_violation_detection',
                description='Detect invariant violations and protocol breaks',
                input_format='Dict[contract_code, invariants]',
                output_format='List[Discovery]',
                confidence_range=(0.80, 0.95),
                cost_estimate=0.10
            )
        ],
        'Economic': [
            AgentCapability(
                name='economic_exploit_analysis',
                description='Analyze economic incentives and profit opportunities',
                input_format='Dict[contract_code, economic_model]',
                output_format='List[Discovery]',
                confidence_range=(0.75, 0.92),
                cost_estimate=0.18
            ),
            AgentCapability(
                name='flash_loan_analysis',
                description='Analyze flash loan attack vectors',
                input_format='Dict[contract_code, defi_integrations]',
                output_format='List[Discovery]',
                confidence_range=(0.70, 0.90),
                cost_estimate=0.15
            )
        ],
        'Dependency': [
            AgentCapability(
                name='dependency_vulnerability_analysis',
                description='Analyze external dependencies and oracle vulnerabilities',
                input_format='Dict[contract_code, external_calls]',
                output_format='List[Discovery]',
                confidence_range=(0.75, 0.92),
                cost_estimate=0.15
            ),
            AgentCapability(
                name='oracle_manipulation_detection',
                description='Detect oracle manipulation vulnerabilities',
                input_format='Dict[contract_code, price_oracles]',
                output_format='List[Discovery]',
                confidence_range=(0.70, 0.90),
                cost_estimate=0.15
            )
        ],
        'AccessControl': [
            AgentCapability(
                name='access_control_analysis',
                description='Analyze access control and permission bugs',
                input_format='Dict[contract_code, access_patterns]',
                output_format='List[Discovery]',
                confidence_range=(0.80, 0.95),
                cost_estimate=0.12
            ),
            AgentCapability(
                name='privilege_escalation_detection',
                description='Detect privilege escalation vulnerabilities',
                input_format='Dict[contract_code, roles]',
                output_format='List[Discovery]',
                confidence_range=(0.75, 0.92),
                cost_estimate=0.12
            )
        ]
    }

    capabilities = capability_map.get(specialization, [
        AgentCapability(
            name=f'{specialization.lower()}_analysis',
            description=f'General {specialization} analysis',
            input_format='Dict[contract_code]',
            output_format='List[Discovery]',
            confidence_range=(0.70, 0.90),
            cost_estimate=0.15
        )
    ])

    return AgentCard(
        agent_id=agent_id,
        agent_type=AgentType.RESEARCH,
        agent_name=f"{specialization} Research Specialist",
        specialization=specialization,
        capabilities=capabilities,
        tools=tools,
        confidence_range=(0.70, 0.95),
        cost_per_request=0.15,
        peer_review_support=True,
        delegation_support=False,
        metadata={
            'version': 'v3_enhanced',
            'thinking_enabled': True,
            'agentic': True
        }
    )


def create_attack_agent_card(
    attack_type: str,
    agent_id: Optional[str] = None
) -> AgentCard:
    """
    Create Agent Card for Attack Agent

    Args:
        attack_type: Attack type (FlashLoan, Oracle, Reentrancy, Logic)
        agent_id: Optional custom ID

    Returns:
        Agent Card for attack agent
    """
    if agent_id is None:
        agent_id = f"{attack_type}Attacker"

    capability_map = {
        'FlashLoan': [
            AgentCapability(
                name='flash_loan_attack_generation',
                description='Generate flash loan attack hypotheses',
                input_format='Dict[contract_code, defi_context]',
                output_format='List[AttackHypothesis]',
                confidence_range=(0.60, 0.90),
                cost_estimate=0.20
            )
        ],
        'Oracle': [
            AgentCapability(
                name='oracle_manipulation_attack',
                description='Generate oracle manipulation attack hypotheses',
                input_format='Dict[contract_code, oracle_integrations]',
                output_format='List[AttackHypothesis]',
                confidence_range=(0.60, 0.90),
                cost_estimate=0.20
            )
        ],
        'Reentrancy': [
            AgentCapability(
                name='reentrancy_attack_generation',
                description='Generate reentrancy attack hypotheses',
                input_format='Dict[contract_code, external_calls]',
                output_format='List[AttackHypothesis]',
                confidence_range=(0.65, 0.92),
                cost_estimate=0.18
            )
        ],
        'Logic': [
            AgentCapability(
                name='logic_bug_attack_generation',
                description='Generate business logic attack hypotheses',
                input_format='Dict[contract_code, business_logic]',
                output_format='List[AttackHypothesis]',
                confidence_range=(0.60, 0.88),
                cost_estimate=0.20
            )
        ]
    }

    capabilities = capability_map.get(attack_type, [
        AgentCapability(
            name=f'{attack_type.lower()}_attack',
            description=f'Generate {attack_type} attack hypotheses',
            input_format='Dict[contract_code]',
            output_format='List[AttackHypothesis]',
            confidence_range=(0.60, 0.90),
            cost_estimate=0.20
        )
    ])

    return AgentCard(
        agent_id=agent_id,
        agent_type=AgentType.ATTACK,
        agent_name=f"{attack_type} Attack Agent",
        specialization=attack_type,
        capabilities=capabilities,
        tools=['generate_hypothesis', 'request_specialist_input', 'share_finding'],
        confidence_range=(0.60, 0.90),
        cost_per_request=0.20,
        peer_review_support=True,
        delegation_support=True,
        metadata={
            'version': 'v1',
            'attack_focus': attack_type
        }
    )


def create_verification_agent_card(
    agent_id: str = "AdversarialVerifier"
) -> AgentCard:
    """Create Agent Card for Verification Layer"""
    return AgentCard(
        agent_id=agent_id,
        agent_type=AgentType.VERIFICATION,
        agent_name="Adversarial Verification Agent",
        specialization="Verification",
        capabilities=[
            AgentCapability(
                name='adversarial_verification',
                description='Adversarially critique attack hypotheses',
                input_format='List[AttackHypothesis]',
                output_format='List[VerificationResult]',
                confidence_range=(0.85, 0.99),
                cost_estimate=0.25
            ),
            AgentCapability(
                name='formal_verification',
                description='Formally verify attacks using Z3 SMT solver',
                input_format='AttackHypothesis',
                output_format='Z3VerificationResult',
                confidence_range=(0.90, 0.99),
                cost_estimate=0.15
            ),
            AgentCapability(
                name='peer_review',
                description='Review findings from other agents',
                input_format='Discovery',
                output_format='ReviewResult',
                confidence_range=(0.80, 0.95),
                cost_estimate=0.10
            )
        ],
        tools=['z3_verify', 'adversarial_critique', 'formal_proof'],
        confidence_range=(0.85, 0.99),
        cost_per_request=0.25,
        peer_review_support=True,
        delegation_support=False,
        metadata={
            'version': 'v1',
            'verification_types': ['adversarial', 'formal', 'peer_review']
        }
    )


def create_aggregator_card(
    agent_id: str = "MetaAggregator"
) -> AgentCard:
    """Create Agent Card for Meta-Aggregator (MoA)"""
    return AgentCard(
        agent_id=agent_id,
        agent_type=AgentType.AGGREGATION,
        agent_name="Meta-Aggregator (MoA)",
        specialization="Aggregation",
        capabilities=[
            AgentCapability(
                name='research_aggregation',
                description='Aggregate research findings from multiple specialists',
                input_format='List[Discovery]',
                output_format='AggregatedResearchResult',
                confidence_range=(0.80, 0.95),
                cost_estimate=0.20
            ),
            AgentCapability(
                name='consensus_building',
                description='Build consensus from conflicting findings',
                input_format='List[Discovery]',
                output_format='ConsensusResult',
                confidence_range=(0.75, 0.92),
                cost_estimate=0.15
            ),
            AgentCapability(
                name='peer_review_coordination',
                description='Coordinate peer review across agents',
                input_format='List[Discovery]',
                output_format='List[ReviewResult]',
                confidence_range=(0.80, 0.95),
                cost_estimate=0.25
            )
        ],
        tools=['aggregate_findings', 'request_reviews', 'build_consensus'],
        confidence_range=(0.80, 0.95),
        cost_per_request=0.20,
        peer_review_support=False,
        delegation_support=True,
        metadata={
            'version': 'v1',
            'aggregation_strategy': 'mixture_of_agents'
        }
    )
