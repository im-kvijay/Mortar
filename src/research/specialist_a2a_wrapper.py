"""
V3 Specialist A2A Integration

Wraps V3 specialists to enable peer-to-peer communication:
1. Register with A2A bus
2. Broadcast discoveries for peer review
3. Receive and respond to peer challenges
4. Negotiate confidence adjustments
5. Build consensus on critical findings

USAGE:
    # In supervisor.py
    wrapper = SpecialistA2AWrapper(
        specialist=business_logic_specialist,
        bus=self.a2a_bus,
        specialist_type="BusinessLogic"
    )

    result = wrapper.analyze_with_a2a(
        contract_source=contract_source,
        contract_info=contract_info,
        knowledge_graph=knowledge_graph
    )

    # Result now includes peer_reviewed=True and consensus_count
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import uuid

from agent.a2a_v3_protocol import A2ABusV3, A2AMessageV3, MessageType, AgentCardV3
from research.base_specialist import EnhancedAgenticSpecialist, EnhancedAnalysisResult


@dataclass
class PeerReviewRequest:
    """Request for peer review of a finding"""
    finding: Dict[str, Any]
    requesting_specialist: str
    evidence: List[str]
    confidence: float
    discovery_id: str


@dataclass
class PeerReviewResponse:
    """Response to peer review"""
    reviewer_id: str
    agrees: bool
    confidence_adjustment: float  # -0.3 to +0.3
    reasoning: str
    alternative_interpretation: Optional[str] = None


class SpecialistA2AWrapper:
    """
    Wraps a V3 specialist to enable A2A communication

    Key behaviors:
    1. Register specialist with bus at initialization
    2. After specialist generates discoveries, broadcast for peer review
    3. Listen for peer review requests from other specialists
    4. Respond with agreement/disagreement + reasoning
    5. Adjust confidence based on peer consensus
    """

    def __init__(
        self,
        specialist: EnhancedAgenticSpecialist,
        bus: A2ABusV3,
        specialist_type: str
    ):
        """
        Initialize A2A wrapper

        Args:
            specialist: V3 Enhanced specialist instance
            bus: A2A bus instance
            specialist_type: Type name (e.g., "BusinessLogic", "StateFlow")
        """
        self.specialist = specialist
        self.bus = bus
        self.specialist_type = specialist_type
        self.peer_responses: Dict[str, List[PeerReviewResponse]] = {}  # discovery_id -> responses

        # Create agent card
        self.card = AgentCardV3(
            agent_id=f"specialist_{specialist_type.lower()}",
            name=f"{specialist_type} Specialist",
            capabilities=[
                f"{specialist_type.lower()}_analysis",
                "peer_review",
                "consensus_negotiation"
            ],
            supported_contract_types=["DeFi", "NFT", "DAO", "Token"],
            status="available",
            protocol_version="0.3",
            streaming_supported=False,
            max_concurrent_tasks=1
        )

        # Register with bus, providing message handler for synchronous routing
        self.bus.register(self.card, handler=self._handle_message)

    def analyze_with_a2a(
        self,
        contract_source: str,
        contract_info: Dict[str, Any],
        knowledge_graph: Any
    ) -> List[EnhancedAnalysisResult]:
        """
        Run specialist analysis with A2A peer review

        Flow:
        1. Run specialist analysis (existing V3 code)
        2. Broadcast high-confidence discoveries for peer review
        3. Collect peer responses
        4. Adjust confidence based on consensus
        5. Return enhanced results

        Args:
            contract_source: Solidity source code
            contract_info: Contract metadata
            knowledge_graph: Knowledge graph instance

        Returns:
            List of analysis results with peer review metadata
        """
        # Reset response cache for this contract run
        self.peer_responses = {}

        # 1. Run normal specialist analysis
        results = self.specialist.analyze_contract(
            contract_source=contract_source,
            contract_info=contract_info,
            knowledge_graph=knowledge_graph
        )

        # 2. For each result, broadcast top discoveries for peer review
        for result in results:
            discoveries = result.discoveries if hasattr(result, 'discoveries') else []

            # Filter high-confidence discoveries (>=0.7)
            high_confidence = [
                d for d in discoveries
                if getattr(d, 'confidence', 0) >= 0.7
            ]

            # Broadcast top 5 for peer review
            for discovery in high_confidence[:5]:
                self._broadcast_for_peer_review(discovery)

        # 3. Adjust confidence based on peer consensus
        for result in results:
            if hasattr(result, 'discoveries'):
                for discovery in result.discoveries:
                    discovery_id = getattr(discovery, 'id', None)
                    if discovery_id is None:
                        continue

                    if discovery_id in self.peer_responses:
                        # Calculate consensus
                        responses = self.peer_responses[discovery_id]
                        agrees_count = sum(1 for r in responses if r.agrees)
                        total_count = len(responses)

                        # Adjust confidence based on consensus
                        if total_count > 0:
                            consensus_ratio = agrees_count / total_count

                            # Strong consensus (80%+) boosts confidence
                            if consensus_ratio >= 0.8:
                                adjustment = +0.1
                            # Weak consensus (40-60%) neutral
                            elif 0.4 <= consensus_ratio <= 0.6:
                                adjustment = 0.0
                            # Disagreement lowers confidence
                            else:
                                adjustment = -0.15

                            # Blend per-review suggested adjustments
                            avg_peer_adjustment = sum(
                                r.confidence_adjustment for r in responses
                            ) / total_count

                            adjustment += avg_peer_adjustment

                            # Apply adjustment
                            original_confidence = getattr(discovery, 'confidence', 0.7)
                            new_confidence = max(0.0, min(1.0, original_confidence + adjustment))

                            # Update discovery confidence
                            if hasattr(discovery, 'confidence'):
                                discovery.confidence = new_confidence

                            # Attach peer review metadata for downstream consumers
                            setattr(
                                discovery,
                                'peer_reviews',
                                [
                                    {
                                        'reviewer_id': r.reviewer_id,
                                        'agrees': r.agrees,
                                        'confidence_adjustment': r.confidence_adjustment,
                                        'reasoning': r.reasoning,
                                        'alternative_interpretation': r.alternative_interpretation
                                    }
                                    for r in responses
                                ]
                            )

                # Add peer review metadata to result
                result.peer_reviewed = True
                result.consensus_count = self._count_consensus(result.discoveries)

        return results

    def _broadcast_for_peer_review(self, discovery: Any):
        """
        Broadcast discovery for peer review

        Args:
            discovery: Discovery object to review
        """
        discovery_id = getattr(discovery, 'id', None)
        if not discovery_id:
            discovery_id = f"{self.card.agent_id}_{uuid.uuid4().hex}"
            setattr(discovery, 'id', discovery_id)

        # Create review request
        review_request = PeerReviewRequest(
            finding={
                'id': discovery_id,
                'description': getattr(discovery, 'description', 'Unknown'),
                'category': getattr(discovery, 'category', 'Unknown'),
                'confidence': getattr(discovery, 'confidence', 0.0),
                'severity': getattr(discovery, 'severity', 'Unknown'),
            },
            requesting_specialist=self.specialist_type,
            evidence=getattr(discovery, 'evidence', []),
            confidence=getattr(discovery, 'confidence', 0.0),
            discovery_id=discovery_id
        )

        # Broadcast message to all specialists
        message = A2AMessageV3(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.PEER_REVIEW.value,
            from_agent=self.card.agent_id,
            to_agent=None,  # Broadcast to all
            payload={
                'request': {
                    'finding': review_request.finding,
                    'requesting_specialist': review_request.requesting_specialist,
                    'evidence': review_request.evidence,
                    'confidence': review_request.confidence,
                    'discovery_id': review_request.discovery_id
                }
            }
        )

        # Send via bus (broadcast to all registered specialists)
        self.bus.send(message)

    def handle_peer_review_request(self, message: A2AMessageV3) -> Optional[A2AMessageV3]:
        """
        Handle peer review request from another specialist

        1. Extract finding from request
        2. Evaluate finding based on specialist's expertise
        3. Send back agreement/disagreement with reasoning

        Args:
            message: Peer review request message

        Returns:
            Response message with review
        """
        request_content = message.payload.get('request', {})
        finding = request_content.get('finding', {})
        discovery_id = request_content.get('discovery_id', 'unknown')

        # Simple heuristic for peer review:
        # - Agree if finding category matches specialist's domain
        # - Or if specialist's expertise overlaps

        finding_category = finding.get('category', '').lower()
        specialist_domain = self.specialist_type.lower()

        # Domain overlap logic
        domain_overlap = {
            'businesslogic': ['logic', 'business', 'access'],
            'stateflow': ['state', 'flow', 'transition'],
            'invariant': ['invariant', 'property', 'guarantee'],
            'economic': ['economic', 'defi', 'flashloan', 'oracle'],
            'dependency': ['dependency', 'external', 'oracle'],
            'accesscontrol': ['access', 'permission', 'role']
        }

        specialist_keywords = domain_overlap.get(specialist_domain, [])
        agrees = any(keyword in finding_category for keyword in specialist_keywords)

        # Create response
        response = PeerReviewResponse(
            reviewer_id=self.card.agent_id,
            agrees=agrees,
            confidence_adjustment=0.1 if agrees else -0.2,
            reasoning=f"{self.specialist_type} specialist {'confirms' if agrees else 'questions'} this finding based on domain expertise",
            alternative_interpretation=None if agrees else "May require additional validation from domain specialist"
        )

        # Create response message
        response_message = A2AMessageV3(
            message_id=str(uuid.uuid4()),
            message_type=MessageType.RESPONSE.value,
            from_agent=self.card.agent_id,
            to_agent=message.from_agent,
            payload={
                'response': {
                    'agrees': response.agrees,
                    'confidence_adjustment': response.confidence_adjustment,
                    'reasoning': response.reasoning,
                    'alternative_interpretation': response.alternative_interpretation
                },
                'discovery_id': discovery_id
            },
            reply_to=message.message_id
        )

        self.bus.send(response_message)
        return None

    def _handle_message(self, message: A2AMessageV3) -> Optional[A2AMessageV3]:
        """
        Primary message handler registered with the A2A bus.

        Routes peer review requests to the appropriate handler and records
        responses for later consensus scoring.
        """
        msg_type = MessageType(message.message_type)

        if msg_type == MessageType.PEER_REVIEW:
            return self.handle_peer_review_request(message)

        if msg_type == MessageType.RESPONSE:
            return self._record_peer_response(message)

        # Placeholder for future consensus/stream handling
        return None

    def _record_peer_response(self, message: A2AMessageV3) -> None:
        """
        Record peer review responses that arrive via the bus.
        """
        discovery_id = message.payload.get('discovery_id')
        response_payload = message.payload.get('response', {})

        if not discovery_id or not response_payload:
            return

        peer_response = PeerReviewResponse(
            reviewer_id=message.from_agent,
            agrees=response_payload.get('agrees', False),
            confidence_adjustment=response_payload.get('confidence_adjustment', 0.0),
            reasoning=response_payload.get('reasoning', ''),
            alternative_interpretation=response_payload.get('alternative_interpretation')
        )

        self.peer_responses.setdefault(discovery_id, []).append(peer_response)

    def _count_consensus(self, discoveries: List[Any]) -> int:
        """
        Count how many discoveries have 2+ peer agreements

        Args:
            discoveries: List of discovery objects

        Returns:
            Count of discoveries with consensus
        """
        consensus_count = 0

        for discovery in discoveries:
            discovery_id = getattr(discovery, 'id', None)
            if discovery_id and discovery_id in self.peer_responses:
                responses = self.peer_responses[discovery_id]
                agrees_count = sum(1 for r in responses if r.agrees)

                # Consensus = 2+ agreements
                if agrees_count >= 2:
                    consensus_count += 1

        return consensus_count
