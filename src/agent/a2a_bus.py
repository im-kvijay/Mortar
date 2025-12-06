"""module docstring"""

from typing import Dict, Any, List, Optional, Callable, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime, UTC
import json
import uuid
from threading import Lock, RLock, Condition
import time

from agent.agent_card import AgentCard, AgentType, AgentStatus, AgentCapability


class MessageType(Enum):
    """A2A Message types"""
    REQUEST = "request"  # Request for service from another agent
    RESPONSE = "response"  # Response to a request
    BROADCAST = "broadcast"  # Broadcast to all agents (or filtered subset)
    DISCOVERY = "discovery"  # Discovery announcement (MoA)
    PEER_REVIEW = "peer_review"  # Request peer review
    PEER_REVIEW_REQUEST = "peer_review_request"  # Alias for peer review (MoA)
    REVIEW_RESPONSE = "review_response"  # Response to peer review request
    CONSENSUS = "consensus"  # Consensus negotiation message
    DELEGATION = "delegation"  # Delegate task to another agent
    CAPABILITY_QUERY = "capability_query"  # Query for agents with capability
    CAPABILITY_RESPONSE = "capability_response"  # Response to capability query
    STATUS_UPDATE = "status_update"  # Agent status change notification
    ERROR = "error"  # Error message


class MessagePriority(Enum):
    """Message priority levels"""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class A2AMessage:
    """
    A2A Protocol Message

    Attributes:
        message_id: Unique message ID
        from_agent: Sender agent ID
        to_agent: Recipient agent ID (or "broadcast" or "capability:X")
        message_type: Type of message
        payload: Message payload (arbitrary data)
        priority: Message priority
        timestamp: Message creation timestamp
        in_reply_to: ID of message this is replying to (for request/response)
        metadata: Additional metadata
    """
    message_id: str
    from_agent: str
    to_agent: str  # Agent ID, "broadcast", or "capability:xyz"
    message_type: MessageType
    payload: Dict[str, Any]
    priority: MessagePriority = MessagePriority.NORMAL
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    in_reply_to: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'message_id': self.message_id,
            'from_agent': self.from_agent,
            'to_agent': self.to_agent,
            'message_type': self.message_type.value,
            'payload': self.payload,
            'priority': self.priority.value,
            'timestamp': self.timestamp,
            'in_reply_to': self.in_reply_to,
            'metadata': self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'A2AMessage':
        """Create from dictionary"""
        return cls(
            message_id=data['message_id'],
            from_agent=data['from_agent'],
            to_agent=data['to_agent'],
            message_type=MessageType(data['message_type']),
            payload=data['payload'],
            priority=MessagePriority(data['priority']),
            timestamp=data['timestamp'],
            in_reply_to=data.get('in_reply_to'),
            metadata=data.get('metadata', {})
        )

    def to_json(self) -> str:
        """Convert to JSON"""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class PeerReviewRequest:
    """Peer review request payload"""
    finding: Dict[str, Any]  # Discovery or AttackHypothesis
    context: Dict[str, Any]  # Additional context
    review_criteria: List[str]  # What to review for
    deadline: Optional[str] = None  # ISO timestamp


@dataclass
class PeerReviewResponse:
    """Peer review response payload"""
    reviewer_id: str
    finding_id: str
    approved: bool
    confidence: float
    critique: str
    issues_found: List[str]
    suggestions: List[str]


@dataclass
class ConsensusRequest:
    """Consensus negotiation request"""
    findings: List[Dict[str, Any]]  # Conflicting findings
    context: Dict[str, Any]
    negotiation_criteria: List[str]  # What to negotiate on


@dataclass
class ConsensusResponse:
    """Consensus negotiation response"""
    agent_id: str
    position: str  # Agent's position on the matter
    reasoning: str
    confidence: float
    willing_to_compromise: bool


class A2ABus:
    """
    A2A Communication Bus

    Central message router for agent-to-agent communication.
    Enables discovery, messaging, peer review, and consensus.

    THREAD-SAFE: Uses locks for concurrent access
    """

    def __init__(self):
        """Initialize A2A bus"""
        self._agents: Dict[str, AgentCard] = {}  # agent_id -> AgentCard
        self._capability_index: Dict[str, Set[str]] = defaultdict(set)  # capability -> {agent_ids}
        self._type_index: Dict[AgentType, Set[str]] = defaultdict(set)  # type -> {agent_ids}
        self._message_handlers: Dict[str, Callable] = {}  # agent_id -> message_handler
        self._message_queue: List[A2AMessage] = []  # Pending messages
        # use deque with maxlen to prevent unbounded growth (keep last 1000 messages for debugging)
        self._message_history: deque = deque(maxlen=1000)  # Bounded history (for debugging)
        self._lock = RLock()  # Allow re-entrant access during handler callbacks
        self._condition = Condition(self._lock)
        self._pending_responses: Dict[str, List[A2AMessage]] = defaultdict(list)  # message_id -> responses
        self._message_sequence = 0  # Monotonic sequence for history cursors

    # registration & discovery

    def register_agent(
        self,
        card: AgentCard,
        message_handler: Optional[Callable[[A2AMessage], Optional[A2AMessage]]] = None
    ) -> bool:
        """
        Register agent on the bus

        Args:
            card: Agent card
            message_handler: Optional message handler function
                            Takes A2AMessage, returns optional response

        Returns:
            True if registered successfully
        """
        with self._lock:
            if card.agent_id in self._agents:
                return False  # Already registered

            # register agent
            self._agents[card.agent_id] = card

            # index capabilities
            for capability in card.capabilities:
                self._capability_index[capability.name].add(card.agent_id)

            # index agent type
            self._type_index[card.agent_type].add(card.agent_id)

            # register message handler
            if message_handler:
                self._message_handlers[card.agent_id] = message_handler

            return True

    def unregister_agent(self, agent_id: str) -> bool:
        """Unregister agent from bus"""
        with self._lock:
            if agent_id not in self._agents:
                return False

            card = self._agents[agent_id]

            # remove from capability index
            for capability in card.capabilities:
                self._capability_index[capability.name].discard(agent_id)

            # remove from type index
            self._type_index[card.agent_type].discard(agent_id)

            # remove message handler
            if agent_id in self._message_handlers:
                del self._message_handlers[agent_id]

            # remove agent
            del self._agents[agent_id]

            return True

    def discover_agents(
        self,
        capability: Optional[str] = None,
        agent_type: Optional[AgentType] = None,
        specialization: Optional[str] = None,
        status: Optional[AgentStatus] = None
    ) -> List[AgentCard]:
        """
        Discover agents by criteria

        Args:
            capability: Filter by capability
            agent_type: Filter by agent type
            specialization: Filter by specialization
            status: Filter by status

        Returns:
            List of matching agent cards
        """
        with self._lock:
            # start with all agents
            candidates = set(self._agents.keys())

            # filter by capability
            if capability:
                if capability in self._capability_index:
                    candidates &= self._capability_index[capability]
                else:
                    return []  # No agents with this capability

            # filter by type
            if agent_type:
                if agent_type in self._type_index:
                    candidates &= self._type_index[agent_type]
                else:
                    return []

            # filter by specialization
            if specialization:
                candidates = {
                    aid for aid in candidates
                    if self._agents[aid].specialization == specialization
                }

            # filter by status
            if status:
                candidates = {
                    aid for aid in candidates
                    if self._agents[aid].status == status
                }

            return [self._agents[aid] for aid in candidates]

    def get_agent(self, agent_id: str) -> Optional[AgentCard]:
        """Get agent card by ID"""
        with self._lock:
            return self._agents.get(agent_id)

    def list_all_agents(self) -> List[AgentCard]:
        """List all registered agents"""
        with self._lock:
            return list(self._agents.values())

    def update_agent_status(self, agent_id: str, new_status: AgentStatus) -> bool:
        """Update agent status"""
        with self._lock:
            if agent_id not in self._agents:
                return False
            self._agents[agent_id].update_status(new_status)
            return True

    # messaging

    def send_message(
        self,
        message: A2AMessage,
        wait_for_response: bool = False,
        timeout_seconds: float = 30.0
    ) -> Optional[A2AMessage]:
        """
        Send message via bus

        Args:
            message: Message to send
            wait_for_response: If True, block until response received
            timeout_seconds: Timeout for waiting

        Returns:
            Response message (if wait_for_response=True), else None
        """
        handler_calls: List[Tuple[Callable, A2AMessage]] = []
        responses: List[A2AMessage] = []

        with self._lock:
            # assign sequence number and record original message
            self._message_history.append(message)
            self._message_sequence += 1
            self._condition.notify_all()

            # handle capability query inside lock and return immediately
            if message.to_agent.startswith("capability:"):
                capability = message.to_agent.split(":", 1)[1]
                return self._handle_capability_query(message, capability)

            # broadcast routing
            if message.to_agent == "broadcast":
                for agent_id, handler in self._message_handlers.items():
                    if agent_id == message.from_agent:
                        continue

                    dispatch = A2AMessage(
                        message_id=str(uuid.uuid4()),
                        from_agent=message.from_agent,
                        to_agent=agent_id,
                        message_type=message.message_type,
                        payload=message.payload,
                        priority=message.priority,
                        in_reply_to=message.message_id,
                        metadata=message.metadata
                    )
                    handler_calls.append((handler, dispatch))

                # even if no handlers, respond with empty aggregated response
            else:
                if message.to_agent not in self._agents:
                    return A2AMessage(
                        message_id=str(uuid.uuid4()),
                        from_agent="bus",
                        to_agent=message.from_agent,
                        message_type=MessageType.ERROR,
                        payload={'error': f'Agent {message.to_agent} not found'},
                        in_reply_to=message.message_id
                    )

                handler = self._message_handlers.get(message.to_agent)
                if handler:
                    handler_calls.append((handler, message))
                else:
                    # queue message for later retrieval
                    self._message_queue.append(message)
                    # optionally wait for response from queue (not implemented)
                    if wait_for_response:
                        # wait until response arrives in pending responses
                        deadline = time.time() + timeout_seconds
                        while time.time() < deadline:
                            pending = self._pending_responses.get(message.message_id)
                            if pending:
                                return pending.pop(0)
                            self._condition.wait(timeout=0.05)
                        return None

        # invoke handlers outside lock to avoid deadlocks
        for handler, dispatch in handler_calls:
            try:
                response = handler(dispatch)
            except Exception as exc:
                response = A2AMessage(
                    message_id=str(uuid.uuid4()),
                    from_agent="bus",
                    to_agent=dispatch.from_agent,
                    message_type=MessageType.ERROR,
                    payload={'error': f'Handler error: {exc}'},
                    in_reply_to=dispatch.message_id
                )
            if response:
                responses.append(response)

        # handle broadcast aggregation
        if message.to_agent == "broadcast":
            aggregated = A2AMessage(
                message_id=str(uuid.uuid4()),
                from_agent="bus",
                to_agent=message.from_agent,
                message_type=MessageType.RESPONSE,
                payload={'responses': [r.to_dict() for r in responses]},
                in_reply_to=message.message_id
            )
            with self._lock:
                self._message_history.append(aggregated)
                for resp in responses:
                    self._message_history.append(resp)
                self._message_sequence = len(self._message_history)
                self._condition.notify_all()
            return aggregated

        # direct message responses
        if responses:
            with self._lock:
                for resp in responses:
                    self._message_history.append(resp)
                self._message_sequence = len(self._message_history)
                self._pending_responses[message.message_id].extend(responses)
                self._condition.notify_all()

            if wait_for_response:
                return responses[0]

        return None

    def _handle_broadcast(self, message: A2AMessage) -> A2AMessage:
        """Handle broadcast message"""
        responses = []
        for agent_id, handler in self._message_handlers.items():
            if agent_id != message.from_agent:  # Don't broadcast to self
                msg = A2AMessage(
                    message_id=str(uuid.uuid4()),
                    from_agent=message.from_agent,
                    to_agent=agent_id,
                    message_type=message.message_type,
                    payload=message.payload,
                    priority=message.priority,
                    in_reply_to=message.message_id,
                    metadata=message.metadata
                )
                response = handler(msg)
                if response:
                    responses.append(response)
                    self._message_history.append(response)

        # return aggregated responses
        return A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent="bus",
            to_agent=message.from_agent,
            message_type=MessageType.RESPONSE,
            payload={'responses': [r.to_dict() for r in responses]},
            in_reply_to=message.message_id
        )

    def _handle_capability_query(self, message: A2AMessage, capability: str) -> A2AMessage:
        """Handle capability query"""
        agents = self.discover_agents(capability=capability, status=AgentStatus.AVAILABLE)
        return A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent="bus",
            to_agent=message.from_agent,
            message_type=MessageType.CAPABILITY_RESPONSE,
            payload={
                'capability': capability,
                'agents': [a.to_dict() for a in agents]
            },
            in_reply_to=message.message_id
        )

    def create_request(
        self,
        from_agent: str,
        to_agent: str,
        payload: Dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL
    ) -> A2AMessage:
        """Create request message"""
        return A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=MessageType.REQUEST,
            payload=payload,
            priority=priority
        )

    def create_response(
        self,
        from_agent: str,
        to_agent: str,
        payload: Dict[str, Any],
        in_reply_to: str
    ) -> A2AMessage:
        """Create response message"""
        return A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent=from_agent,
            to_agent=to_agent,
            message_type=MessageType.RESPONSE,
            payload=payload,
            in_reply_to=in_reply_to
        )

    # peer review

    def request_peer_review(
        self,
        from_agent: str,
        finding: Dict[str, Any],
        context: Dict[str, Any],
        review_criteria: List[str],
        filter_by_type: Optional[AgentType] = None
    ) -> List[PeerReviewResponse]:
        """
        Request peer review from other agents

        Args:
            from_agent: Requesting agent ID
            finding: Finding to review (Discovery or AttackHypothesis)
            context: Additional context
            review_criteria: What to review for
            filter_by_type: Optional filter by agent type

        Returns:
            List of peer review responses
        """
        # create review request
        request = PeerReviewRequest(
            finding=finding,
            context=context,
            review_criteria=review_criteria
        )

        # discover reviewers (agents with peer_review_support=true)
        all_agents = self.list_all_agents()
        reviewers = [
            a for a in all_agents
            if a.peer_review_support and a.agent_id != from_agent
        ]

        # filter by type if specified
        if filter_by_type:
            reviewers = [a for a in reviewers if a.agent_type == filter_by_type]

        # send review requests
        responses = []
        for reviewer in reviewers:
            message = A2AMessage(
                message_id=str(uuid.uuid4()),
                from_agent=from_agent,
                to_agent=reviewer.agent_id,
                message_type=MessageType.PEER_REVIEW,
                payload={'review_request': request.__dict__}
            )

            response = self.send_message(message, wait_for_response=True)
            if response and response.message_type == MessageType.REVIEW_RESPONSE:
                review_data = response.payload.get('review')
                if review_data:
                    responses.append(PeerReviewResponse(**review_data))

        return responses

    # consensus

    def negotiate_consensus(
        self,
        from_agent: str,
        findings: List[Dict[str, Any]],
        context: Dict[str, Any],
        negotiation_criteria: List[str],
        involved_agents: List[str]
    ) -> List[ConsensusResponse]:
        """
        Negotiate consensus among agents

        Args:
            from_agent: Requesting agent (usually aggregator)
            findings: Conflicting findings
            context: Additional context
            negotiation_criteria: What to negotiate on
            involved_agents: Agents involved in negotiation

        Returns:
            List of consensus responses
        """
        # create consensus request
        request = ConsensusRequest(
            findings=findings,
            context=context,
            negotiation_criteria=negotiation_criteria
        )

        # send to involved agents
        responses = []
        for agent_id in involved_agents:
            message = A2AMessage(
                message_id=str(uuid.uuid4()),
                from_agent=from_agent,
                to_agent=agent_id,
                message_type=MessageType.CONSENSUS,
                payload={'consensus_request': request.__dict__}
            )

            response = self.send_message(message, wait_for_response=True)
            if response and response.message_type == MessageType.CONSENSUS:
                consensus_data = response.payload.get('consensus')
                if consensus_data:
                    responses.append(ConsensusResponse(**consensus_data))

        return responses

    # utilities

    def get_message_history(
        self,
        agent_id: Optional[str] = None,
        message_type: Optional[MessageType] = None,
        limit: int = 100
    ) -> List[A2AMessage]:
        """
        Get message history

        Args:
            agent_id: Filter by agent (from or to)
            message_type: Filter by message type
            limit: Max messages to return

        Returns:
            List of messages
        """
        with self._lock:
            messages = self._message_history

            # filter by agent
            if agent_id:
                messages = [
                    m for m in messages
                    if m.from_agent == agent_id or m.to_agent == agent_id
                ]

            # filter by type
            if message_type:
                messages = [m for m in messages if m.message_type == message_type]

            return messages[-limit:]

    def clear_message_history(self):
        """Clear message history (for testing)"""
        with self._lock:
            self._message_history.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get bus statistics"""
        with self._lock:
            return {
                'total_agents': len(self._agents),
                'agents_by_type': {
                    t.value: len(aids) for t, aids in self._type_index.items()
                },
                'total_capabilities': len(self._capability_index),
                'total_messages': len(self._message_history),
                'pending_messages': len(self._message_queue)
            }

    # moa helpers (simplified a2a for mixture of agents)

    def publish(self, message: A2AMessage):
        """
        Simplified publish for MoA specialists

        Publishes a message to the bus (broadcast or directed).
        Used by specialists during parallel execution to share discoveries.

        WARNING: This method only appends to _message_history.
        It does NOT trigger registered handlers (send_message, request, respond, etc.).
        For handler-based workflows, messages published via this method will never be seen.
        Use polling-based access via get_messages() instead.

        If you need handler-based messaging, use the full A2A protocol methods:
        - send_message() for direct messaging with handler callbacks
        - request() / respond() for request-response patterns
        """
        with self._lock:
            self._message_history.append(message)
            self._message_sequence += 1
            self._condition.notify_all()

    def get_messages(
        self,
        agent_id: str,
        message_types: Optional[List[str]] = None,
        since_index: int = 0,
        timeout: float = 0.0,
        max_messages: Optional[int] = None
    ) -> Tuple[List[A2AMessage], int]:
        """
        Simplified message retrieval for MoA specialists

        Gets messages addressed to agent_id or broadcast to all and returns
        a cursor pointing to the next unread position.

        Args:
            agent_id: Agent ID to get messages for
            message_types: Optional filter by message types (as strings)
            since_index: Only return messages after this index (for polling)
            timeout: Maximum seconds to wait for new messages (0 = non-blocking)
            max_messages: Optional cap on messages returned in a single poll

        Returns:
            Tuple of (messages for this agent, next_since_index)
        """
        with self._condition:
            deadline = time.time() + timeout if timeout > 0 else None

            while True:
                start_index = max(since_index, 0)
                history_len = len(self._message_history)
                messages: List[A2AMessage] = []

                if start_index < history_len:
                    # convert deque to list for slicing (deque doesn't support slice)
                    history_list = list(self._message_history)
                    for msg in history_list[start_index:]:
                        if msg.to_agent == agent_id or msg.to_agent == "broadcast":
                            if msg.from_agent == agent_id:
                                continue
                            if message_types and msg.message_type.value not in message_types:
                                continue
                            messages.append(msg)
                            if max_messages and len(messages) >= max_messages:
                                break

                    next_index = history_len
                    if messages or timeout == 0:
                        return messages, next_index
                else:
                    next_index = history_len
                    if timeout == 0:
                        return [], next_index

                if deadline is not None:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        return messages, next_index
                    self._condition.wait(timeout=remaining)
                else:
                    self._condition.wait()


# singleton instance

# global a2a bus instance (singleton pattern)
_global_bus: Optional[A2ABus] = None


def get_a2a_bus() -> A2ABus:
    """Get global A2A bus instance (singleton)"""
    global _global_bus
    if _global_bus is None:
        _global_bus = A2ABus()
    return _global_bus


def reset_a2a_bus():
    """Reset global bus (for testing)"""
    global _global_bus
    _global_bus = None
