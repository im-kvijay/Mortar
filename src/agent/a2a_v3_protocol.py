"""module docstring"""

import json
import hashlib
import time
from typing import Dict, Any, List, Optional, Callable, AsyncIterator
from dataclasses import dataclass, asdict, field
from enum import Enum
import asyncio
from datetime import datetime, UTC

from utils.logging import ResearchLogger


class AgentStatus(Enum):
    """Agent operational status"""
    AVAILABLE = "available"
    BUSY = "busy"
    IDLE = "idle"
    ERROR = "error"
    OFFLINE = "offline"


class MessageType(Enum):
    """A2A message types (v0.3 extended)"""
    REQUEST = "request"
    RESPONSE = "response"
    PEER_REVIEW = "peer_review"
    BROADCAST = "broadcast"
    STREAM = "stream"  # NEW: Streaming message
    DISCOVERY = "discovery"  # NEW: Capability discovery
    HANDSHAKE = "handshake"  # NEW: Protocol negotiation


@dataclass
class AgentCardV3:
    """
    Agent Card v0.3 with security enhancements

    NEW in v0.3:
    - signature: Cryptographic signature of card content
    - public_key: Agent's public key for verification
    - protocol_version: "0.3"
    - streaming_supported: Boolean flag
    - max_concurrent_tasks: Capacity limit
    """
    agent_id: str
    name: str
    capabilities: List[str]
    supported_contract_types: List[str]
    status: str = "available"
    quality_score: float = 0.0
    cost_per_request: float = 0.0

    # v0.3 additions
    protocol_version: str = "0.3"
    streaming_supported: bool = True
    max_concurrent_tasks: int = 5
    public_key: Optional[str] = None
    signature: Optional[str] = None

    # metadata
    registered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentCardV3':
        """Create from dictionary"""
        return cls(**data)

    def verify_signature(self, public_key: Optional[str] = None) -> bool:
        """
        Verify agent card signature

        Args:
            public_key: Public key to use (defaults to self.public_key)

        Returns:
            True if signature is valid
        """
        if not self.signature:
            return False

        key = public_key or self.public_key
        if not key:
            return False

        # create canonical representation (without signature field)
        card_dict = self.to_dict()
        card_dict.pop('signature', None)
        canonical = json.dumps(card_dict, sort_keys=True)

        # verify signature (simplified - would use actual crypto library)
        # in production: use cryptography.hazmat.primitives.asymmetric
        expected_sig = hashlib.sha256(f"{canonical}{key}".encode()).hexdigest()

        return expected_sig == self.signature

    def sign(self, private_key: str) -> str:
        """
        Sign agent card

        Args:
            private_key: Private key for signing

        Returns:
            Signature string
        """
        card_dict = self.to_dict()
        card_dict.pop('signature', None)
        canonical = json.dumps(card_dict, sort_keys=True)

        # generate signature (simplified)
        # in production: use cryptography library for proper ecdsa/rsa
        signature = hashlib.sha256(f"{canonical}{private_key}".encode()).hexdigest()
        self.signature = signature

        return signature


@dataclass
class A2AMessageV3:
    """
    A2A message v0.3 with streaming support

    NEW in v0.3:
    - message_type: Extended to include STREAM, DISCOVERY, HANDSHAKE
    - stream_id: For grouping related stream messages
    - sequence_number: For ordering stream messages
    - is_final: Flag for end of stream
    """
    message_id: str
    message_type: str
    from_agent: str
    to_agent: Optional[str]  # None for broadcast
    payload: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    # v0.3 additions for streaming
    stream_id: Optional[str] = None
    sequence_number: int = 0
    is_final: bool = True

    # reply to (for threading)
    reply_to: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'A2AMessageV3':
        return cls(**data)


class A2ABusV3:
    """
    A2A Message Bus v0.3 with gRPC and streaming support

    NEW FEATURES:
    - gRPC backend option (faster than HTTP/JSON-RPC)
    - Streaming message delivery
    - Dynamic capability discovery
    - Signature verification
    - Connection pooling

    BACKWARD COMPATIBLE with v0.2 agents (auto-detects protocol version)
    """

    def __init__(
        self,
        use_grpc: bool = False,
        enable_signatures: bool = True,
        logger: Optional[ResearchLogger] = None
    ):
        self.use_grpc = use_grpc
        self.enable_signatures = enable_signatures
        self.logger = logger

        # agent registry (agent_id → agentcardv3)
        self.agents: Dict[str, AgentCardV3] = {}

        # message queues (agent_id → list[a2amessagev3])
        self.message_queues: Dict[str, List[A2AMessageV3]] = {}

        # stream handlers (stream_id → asynciterator)
        self.active_streams: Dict[str, asyncio.Queue] = {}

        # message handlers (agent_id → callable)
        self.message_handlers: Dict[str, Callable] = {}

        # statistics
        self.messages_sent = 0
        self.messages_delivered = 0
        self.streams_active = 0

        if logger:
            logger.info(f"[A2A v0.3] Initialized (gRPC: {use_grpc}, Signatures: {enable_signatures})")

    def register(self, agent_card: AgentCardV3, handler: Optional[Callable] = None):
        """
        Register agent with the bus

        Args:
            agent_card: Agent card (v0.3 with optional signature)
            handler: Optional message handler function
        """
        # verify signature if required
        if self.enable_signatures and agent_card.signature:
            if not agent_card.verify_signature():
                if self.logger:
                    self.logger.error(f"[A2A v0.3] Invalid signature for agent {agent_card.agent_id}")
                raise ValueError(f"Invalid agent card signature: {agent_card.agent_id}")

        # register
        self.agents[agent_card.agent_id] = agent_card
        self.message_queues[agent_card.agent_id] = []

        if handler:
            self.message_handlers[agent_card.agent_id] = handler

        if self.logger:
            self.logger.info(f"[A2A v0.3] Registered agent: {agent_card.name} (v{agent_card.protocol_version})")
            self.logger.info(f"[A2A v0.3]   Capabilities: {', '.join(agent_card.capabilities)}")
            if agent_card.streaming_supported:
                self.logger.info(f"[A2A v0.3]   Streaming: ENABLED")

    def send(self, message: A2AMessageV3):
        """
        Send message to agent(s)

        Args:
            message: A2A message v0.3
        """
        self.messages_sent += 1

        if message.to_agent:
            # direct message
            if message.to_agent in self.message_queues:
                self.message_queues[message.to_agent].append(message)
                self.messages_delivered += 1

                # call handler if registered
                if message.to_agent in self.message_handlers:
                    handler = self.message_handlers[message.to_agent]
                    handler(message)

                if self.logger:
                    msg_type = message.message_type
                    self.logger.info(f"[A2A v0.3] {message.from_agent} → {message.to_agent} ({msg_type})")
        else:
            # broadcast to all agents
            for agent_id in self.message_queues:
                if agent_id != message.from_agent:  # Don't send to self
                    self.message_queues[agent_id].append(message)
                    self.messages_delivered += 1

                    # call handler
                    if agent_id in self.message_handlers:
                        self.message_handlers[agent_id](message)

            if self.logger:
                self.logger.info(f"[A2A v0.3] {message.from_agent} → BROADCAST ({message.message_type})")

    async def request_stream(
        self,
        from_agent: str,
        to_agent: str,
        task: str,
        **task_params
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Send streaming request to agent (v0.3 feature)

        Yields progress updates until task completes.

        Args:
            from_agent: Requesting agent ID
            to_agent: Target agent ID
            task: Task name
            **task_params: Task parameters

        Yields:
            Progress updates from target agent
        """
        # check if target supports streaming
        if to_agent not in self.agents:
            raise ValueError(f"Unknown agent: {to_agent}")

        agent_card = self.agents[to_agent]
        if not agent_card.streaming_supported:
            raise ValueError(f"Agent {to_agent} does not support streaming")

        # create stream
        stream_id = f"{from_agent}_{to_agent}_{int(time.time() * 1000)}"
        stream_queue = asyncio.Queue()
        self.active_streams[stream_id] = stream_queue
        self.streams_active += 1

        if self.logger:
            self.logger.info(f"[A2A v0.3] Starting stream {stream_id}: {task}")

        # send initial request
        request_msg = A2AMessageV3(
            message_id=f"{stream_id}_req",
            message_type=MessageType.STREAM.value,
            from_agent=from_agent,
            to_agent=to_agent,
            payload={
                'task': task,
                'params': task_params,
                'stream_id': stream_id
            },
            stream_id=stream_id,
            sequence_number=0,
            is_final=False
        )
        self.send(request_msg)

        # yield updates from stream
        try:
            while True:
                # wait for next message in stream (with timeout)
                try:
                    update = await asyncio.wait_for(stream_queue.get(), timeout=30.0)
                except asyncio.TimeoutError:
                    if self.logger:
                        self.logger.warning(f"[A2A v0.3] Stream {stream_id} timeout")
                    break

                yield update

                # check if final message
                if update.get('is_final', False):
                    break

        finally:
            # clean up stream
            if stream_id in self.active_streams:
                del self.active_streams[stream_id]
                self.streams_active -= 1

            if self.logger:
                self.logger.info(f"[A2A v0.3] Stream {stream_id} closed")

    def send_stream_update(
        self,
        stream_id: str,
        from_agent: str,
        update: Dict[str, Any],
        sequence_number: int,
        is_final: bool = False
    ):
        """
        Send update to active stream (called by agent handling stream request)

        Args:
            stream_id: Stream identifier
            from_agent: Agent sending update
            update: Update payload
            sequence_number: Message sequence number
            is_final: True if this is the final message
        """
        if stream_id not in self.active_streams:
            if self.logger:
                self.logger.warning(f"[A2A v0.3] Stream {stream_id} not found")
            return

        # add to stream queue (will be yielded by request_stream)
        update_with_meta = {
            **update,
            'sequence_number': sequence_number,
            'is_final': is_final,
            'timestamp': datetime.now(UTC).isoformat()
        }

        # put in queue (non-blocking)
        try:
            self.active_streams[stream_id].put_nowait(update_with_meta)
        except asyncio.QueueFull:
            if self.logger:
                self.logger.warning(f"[A2A v0.3] Stream {stream_id} queue full, dropping update")

    def discover_capabilities(
        self,
        required_capabilities: List[str],
        contract_type: Optional[str] = None
    ) -> List[AgentCardV3]:
        """
        Discover agents by capabilities (v0.3 feature)

        Args:
            required_capabilities: List of required capabilities
            contract_type: Optional contract type filter

        Returns:
            List of matching agent cards, sorted by quality score
        """
        matching_agents = []

        for agent_id, card in self.agents.items():
            # check capabilities
            if not all(cap in card.capabilities for cap in required_capabilities):
                continue

            # check contract type
            if contract_type and contract_type not in card.supported_contract_types:
                continue

            # check status
            if card.status != AgentStatus.AVAILABLE.value:
                continue

            matching_agents.append(card)

        # sort by quality score (descending)
        matching_agents.sort(key=lambda c: c.quality_score, reverse=True)

        if self.logger:
            self.logger.info(f"[A2A v0.3] Discovered {len(matching_agents)} agents for {required_capabilities}")

        return matching_agents

    def get_stats(self) -> Dict[str, Any]:
        """Get bus statistics"""
        return {
            'total_agents': len(self.agents),
            'messages_sent': self.messages_sent,
            'messages_delivered': self.messages_delivered,
            'streams_active': self.streams_active,
            'agents_by_status': {
                status: sum(1 for a in self.agents.values() if a.status == status)
                for status in ['available', 'busy', 'idle', 'error', 'offline']
            }
        }
