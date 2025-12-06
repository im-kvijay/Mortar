"""module docstring"""

from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
import json
import uuid

from agent.agent_card import (
    AgentCard, AgentType, AgentStatus,
    create_research_specialist_card,
    create_attack_agent_card,
    create_verification_agent_card,
    create_aggregator_card
)
from agent.a2a_bus import (
    A2ABus, A2AMessage, MessageType, MessagePriority,
    PeerReviewRequest, PeerReviewResponse,
    ConsensusRequest, ConsensusResponse,
    get_a2a_bus
)


class A2AResearchSpecialist:
    """
    A2A wrapper for V3 Research Specialist

    Wraps existing specialist with A2A communication capabilities.
    Registers on bus, handles messages, enables peer review.
    """

    def __init__(
        self,
        specialist: Any,  # EnhancedAgenticSpecialist instance
        bus: Optional[A2ABus] = None,
        auto_register: bool = True
    ):
        """
        Initialize A2A wrapper

        Args:
            specialist: V3 specialist instance
            bus: A2A bus instance (or use global)
            auto_register: Automatically register on bus
        """
        self.specialist = specialist
        self.bus = bus or get_a2a_bus()
        self.card: Optional[AgentCard] = None
        self._registered = False

        if auto_register:
            self.register()

    def register(self) -> bool:
        """Register specialist on A2A bus"""
        if self._registered:
            return True

        # create agent card
        self.card = create_research_specialist_card(
            specialization=self.specialist.name,
            agent_id=f"{self.specialist.name}Specialist_v3"
        )

        # register with message handler
        success = self.bus.register_agent(
            card=self.card,
            message_handler=self._handle_message
        )

        if success:
            self._registered = True
            self.bus.update_agent_status(self.card.agent_id, AgentStatus.AVAILABLE)

        return success

    def unregister(self):
        """Unregister from bus"""
        if self._registered and self.card:
            self.bus.unregister_agent(self.card.agent_id)
            self._registered = False

    def _handle_message(self, message: A2AMessage) -> Optional[A2AMessage]:
        """Handle incoming A2A messages"""
        # update status to busy
        if self.card:
            self.bus.update_agent_status(self.card.agent_id, AgentStatus.BUSY)

        try:
            if message.message_type == MessageType.REQUEST:
                return self._handle_request(message)
            elif message.message_type == MessageType.PEER_REVIEW:
                return self._handle_peer_review(message)
            elif message.message_type == MessageType.CONSENSUS:
                return self._handle_consensus(message)
            else:
                return self._create_error_response(
                    message,
                    f"Unsupported message type: {message.message_type}"
                )
        finally:
            # update status back to available
            if self.card:
                self.bus.update_agent_status(self.card.agent_id, AgentStatus.AVAILABLE)

    def _handle_request(self, message: A2AMessage) -> A2AMessage:
        """Handle analysis request"""
        payload = message.payload

        # extract request data
        contract_code = payload.get('contract_code')
        contract_name = payload.get('contract_name', 'Unknown')
        context = payload.get('context', {})

        if not contract_code:
            return self._create_error_response(message, "Missing contract_code")

        # run specialist analysis
        # note: actual integration would call specialist.analyze()
        # for now, create mock response
        result = {
            'specialist': self.specialist.name,
            'discoveries': [],  # Would be actual discoveries
            'confidence': 0.85,
            'summary': f"{self.specialist.name} analysis completed"
        }

        return A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent=self.card.agent_id,
            to_agent=message.from_agent,
            message_type=MessageType.RESPONSE,
            payload={'result': result},
            in_reply_to=message.message_id
        )

    def _handle_peer_review(self, message: A2AMessage) -> A2AMessage:
        """Handle peer review request"""
        review_req = message.payload.get('review_request')
        if not review_req:
            return self._create_error_response(message, "Missing review_request")

        finding = review_req.get('finding')
        context = review_req.get('context', {})
        criteria = review_req.get('review_criteria', [])

        # perform peer review
        # note: would use specialist's reflection/critique capabilities
        review = PeerReviewResponse(
            reviewer_id=self.card.agent_id,
            finding_id=finding.get('id', 'unknown'),
            approved=True,  # Mock - would be actual review
            confidence=0.80,
            critique="Finding appears valid",
            issues_found=[],
            suggestions=[]
        )

        return A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent=self.card.agent_id,
            to_agent=message.from_agent,
            message_type=MessageType.REVIEW_RESPONSE,
            payload={'review': review.__dict__},
            in_reply_to=message.message_id
        )

    def _handle_consensus(self, message: A2AMessage) -> A2AMessage:
        """Handle consensus negotiation"""
        consensus_req = message.payload.get('consensus_request')
        if not consensus_req:
            return self._create_error_response(message, "Missing consensus_request")

        findings = consensus_req.get('findings', [])
        context = consensus_req.get('context', {})

        # provide consensus position
        # note: would use specialist's reasoning capabilities
        consensus = ConsensusResponse(
            agent_id=self.card.agent_id,
            position="Findings are complementary, not contradictory",
            reasoning="Both findings target different aspects of the vulnerability",
            confidence=0.85,
            willing_to_compromise=True
        )

        return A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent=self.card.agent_id,
            to_agent=message.from_agent,
            message_type=MessageType.CONSENSUS,
            payload={'consensus': consensus.__dict__},
            in_reply_to=message.message_id
        )

    def _create_error_response(self, message: A2AMessage, error: str) -> A2AMessage:
        """Create error response"""
        return A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent=self.card.agent_id,
            to_agent=message.from_agent,
            message_type=MessageType.ERROR,
            payload={'error': error},
            in_reply_to=message.message_id
        )

    def request_specialist_input(
        self,
        capability: str,
        payload: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Request input from another specialist via A2A

        Args:
            capability: Required capability
            payload: Request payload

        Returns:
            Response payload or None
        """
        if not self.card:
            return None

        # create request to any agent with capability
        request = A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent=self.card.agent_id,
            to_agent=f"capability:{capability}",
            message_type=MessageType.REQUEST,
            payload=payload
        )

        response = self.bus.send_message(request, wait_for_response=True)
        if response and response.message_type == MessageType.CAPABILITY_RESPONSE:
            agents = response.payload.get('agents', [])
            if agents:
                # send request to first available agent
                target_agent = agents[0]['agent_id']
                actual_request = A2AMessage(
                    message_id=str(uuid.uuid4()),
                    from_agent=self.card.agent_id,
                    to_agent=target_agent,
                    message_type=MessageType.REQUEST,
                    payload=payload
                )
                actual_response = self.bus.send_message(actual_request, wait_for_response=True)
                if actual_response and actual_response.message_type == MessageType.RESPONSE:
                    return actual_response.payload

        return None


class A2AAttackAgent:
    """
    A2A wrapper for Attack Agent

    Enables attack agents to communicate via A2A protocol.
    """

    def __init__(
        self,
        attacker: Any,  # BaseAttacker instance
        attack_type: str,
        bus: Optional[A2ABus] = None,
        auto_register: bool = True
    ):
        """
        Initialize A2A wrapper

        Args:
            attacker: Attack agent instance
            attack_type: Attack type (FlashLoan, Oracle, etc.)
            bus: A2A bus instance
            auto_register: Auto-register on bus
        """
        self.attacker = attacker
        self.attack_type = attack_type
        self.bus = bus or get_a2a_bus()
        self.card: Optional[AgentCard] = None
        self._registered = False

        if auto_register:
            self.register()

    def register(self) -> bool:
        """Register on A2A bus"""
        if self._registered:
            return True

        self.card = create_attack_agent_card(
            attack_type=self.attack_type,
            agent_id=f"{self.attack_type}Attacker"
        )

        success = self.bus.register_agent(
            card=self.card,
            message_handler=self._handle_message
        )

        if success:
            self._registered = True
            self.bus.update_agent_status(self.card.agent_id, AgentStatus.AVAILABLE)

        return success

    def unregister(self):
        """Unregister from bus"""
        if self._registered and self.card:
            self.bus.unregister_agent(self.card.agent_id)
            self._registered = False

    def _handle_message(self, message: A2AMessage) -> Optional[A2AMessage]:
        """Handle incoming messages"""
        if self.card:
            self.bus.update_agent_status(self.card.agent_id, AgentStatus.BUSY)

        try:
            if message.message_type == MessageType.REQUEST:
                return self._handle_attack_request(message)
            elif message.message_type == MessageType.PEER_REVIEW:
                return self._handle_peer_review(message)
            else:
                return self._create_error_response(
                    message,
                    f"Unsupported message type: {message.message_type}"
                )
        finally:
            if self.card:
                self.bus.update_agent_status(self.card.agent_id, AgentStatus.AVAILABLE)

    def _handle_attack_request(self, message: A2AMessage) -> A2AMessage:
        """Handle attack generation request"""
        # mock implementation - would call actual attacker
        result = {
            'attack_type': self.attack_type,
            'hypotheses': [],  # Would be actual attack hypotheses
            'count': 0
        }

        return A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent=self.card.agent_id,
            to_agent=message.from_agent,
            message_type=MessageType.RESPONSE,
            payload={'result': result},
            in_reply_to=message.message_id
        )

    def _handle_peer_review(self, message: A2AMessage) -> A2AMessage:
        """Handle peer review request"""
        review_req = message.payload.get('review_request')
        finding = review_req.get('finding') if review_req else None

        review = PeerReviewResponse(
            reviewer_id=self.card.agent_id,
            finding_id=finding.get('id', 'unknown') if finding else 'unknown',
            approved=True,
            confidence=0.75,
            critique="Attack vector appears feasible",
            issues_found=[],
            suggestions=[]
        )

        return A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent=self.card.agent_id,
            to_agent=message.from_agent,
            message_type=MessageType.REVIEW_RESPONSE,
            payload={'review': review.__dict__},
            in_reply_to=message.message_id
        )

    def _create_error_response(self, message: A2AMessage, error: str) -> A2AMessage:
        """Create error response"""
        return A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent=self.card.agent_id,
            to_agent=message.from_agent,
            message_type=MessageType.ERROR,
            payload={'error': error},
            in_reply_to=message.message_id
        )

    def request_specialist_analysis(
        self,
        capability: str,
        contract_code: str,
        context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Request analysis from research specialist via A2A

        This replaces direct calls to JIT research gateway.

        Args:
            capability: Required capability (e.g., "economic_analysis")
            contract_code: Contract source code
            context: Additional context

        Returns:
            Analysis result or None
        """
        if not self.card:
            return None

        payload = {
            'contract_code': contract_code,
            'context': context,
            'requested_by': self.card.agent_id
        }

        # first, discover agents with capability
        request = A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent=self.card.agent_id,
            to_agent=f"capability:{capability}",
            message_type=MessageType.REQUEST,
            payload=payload
        )

        response = self.bus.send_message(request, wait_for_response=True)
        if response and response.message_type == MessageType.CAPABILITY_RESPONSE:
            agents = response.payload.get('agents', [])
            if agents:
                # send to first available specialist
                target = agents[0]['agent_id']
                actual_request = A2AMessage(
                    message_id=str(uuid.uuid4()),
                    from_agent=self.card.agent_id,
                    to_agent=target,
                    message_type=MessageType.REQUEST,
                    payload=payload
                )
                actual_response = self.bus.send_message(actual_request, wait_for_response=True)
                if actual_response and actual_response.message_type == MessageType.RESPONSE:
                    return actual_response.payload.get('result')

        return None

    def share_attack_graph(
        self,
        graph: Dict[str, Any],
        broadcast: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Share attack graph with other attackers (for Graph of Thoughts)

        Args:
            graph: Attack graph (nodes, edges, paths)
            broadcast: Broadcast to all attackers or specific ones

        Returns:
            List of responses from other attackers
        """
        if not self.card:
            return []

        payload = {
            'graph': graph,
            'shared_by': self.card.agent_id
        }

        if broadcast:
            message = A2AMessage(
                message_id=str(uuid.uuid4()),
                from_agent=self.card.agent_id,
                to_agent="broadcast",
                message_type=MessageType.REQUEST,
                payload=payload
            )
        else:
            # send to other attack agents only
            # this would need refinement for actual implementation
            message = A2AMessage(
                message_id=str(uuid.uuid4()),
                from_agent=self.card.agent_id,
                to_agent="broadcast",
                message_type=MessageType.REQUEST,
                payload=payload
            )

        response = self.bus.send_message(message, wait_for_response=True)
        if response and response.message_type == MessageType.RESPONSE:
            responses = response.payload.get('responses', [])
            return [r['payload'] for r in responses if 'payload' in r]

        return []
