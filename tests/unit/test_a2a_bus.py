"""s for the A2A bus concurrency guarantees."""

import unittest
import uuid
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if PROJECT_ROOT.name == "tests":
    PROJECT_ROOT = PROJECT_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
src_path = str(PROJECT_ROOT / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from src.agent.a2a_bus import A2ABus, A2AMessage, MessageType
from src.agent.agent_card import AgentCard, AgentType, AgentStatus, AgentCapability

def _make_capability(name: str) -> AgentCapability:
    return AgentCapability(
        name=name,
        description=f"{name} capability",
        input_format="dict",
        output_format="dict"
    )

def _make_agent_card(agent_id: str, specialization: str) -> AgentCard:
    return AgentCard(
        agent_id=agent_id,
        agent_type=AgentType.RESEARCH,
        agent_name=specialization,
        specialization=specialization,
        capabilities=[_make_capability(f"{specialization.lower()}_analysis")]
    )

class TestA2ABus(unittest.TestCase):
    """ """

    def test_handler_can_call_back_into_bus_without_deadlock(self):
        bus = A2ABus()
        card = _make_agent_card("agent_busy", "BusyAgent")

        def handler(message: A2AMessage):
            # re-enter bus apis while processing the message; this used to deadlock.
            bus.update_agent_status(card.agent_id, AgentStatus.BUSY)
            bus.publish(A2AMessage(
                message_id=str(uuid.uuid4()),
                from_agent=card.agent_id,
                to_agent="broadcast",
                message_type=MessageType.STATUS_UPDATE,
                payload={}
            ))
            bus.update_agent_status(card.agent_id, AgentStatus.AVAILABLE)
            return None

        registered = bus.register_agent(card, message_handler=handler)
        self.assertTrue(registered)

        request = bus.create_request(
            from_agent="tester",
            to_agent=card.agent_id,
            payload={"ping": True}
        )
        bus.send_message(request, wait_for_response=False)
        self.assertEqual(bus.get_agent(card.agent_id).status, AgentStatus.AVAILABLE)

    def test_broadcast_collects_responses(self):
        bus = A2ABus()
        card_one = _make_agent_card("agent_one", "One")
        card_two = _make_agent_card("agent_two", "Two")

        def handler_factory(agent_id: str):
            def handler(message: A2AMessage):
                return bus.create_response(
                    from_agent=agent_id,
                    to_agent=message.from_agent,
                    payload={"ack": agent_id},
                    in_reply_to=message.message_id
                )
            return handler

        bus.register_agent(card_one, message_handler=handler_factory(card_one.agent_id))
        bus.register_agent(card_two, message_handler=handler_factory(card_two.agent_id))

        broadcast = A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent="initiator",
            to_agent="broadcast",
            message_type=MessageType.BROADCAST,
            payload={"question": "status"}
        )

        response = bus.send_message(broadcast, wait_for_response=True)
        self.assertIsNotNone(response)
        self.assertEqual(response.message_type, MessageType.RESPONSE)

        payload_responses = response.payload.get("responses", [])
        self.assertEqual(len(payload_responses), 2)
        responder_ids = {entry['from_agent'] for entry in payload_responses}
        self.assertSetEqual(responder_ids, {card_one.agent_id, card_two.agent_id})

    def test_get_messages_respects_since_index(self):
        bus = A2ABus()
        card = _make_agent_card("agent_mailbox", "Mailbox")
        bus.register_agent(card)

        direct_message = A2AMessage(
            message_id=str(uuid.uuid4()),
            from_agent="sender",
            to_agent=card.agent_id,
            message_type=MessageType.REQUEST,
            payload={}
        )
        bus.publish(direct_message)

        messages, cursor = bus.get_messages(card.agent_id)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].message_id, direct_message.message_id)

        follow_up, cursor_two = bus.get_messages(card.agent_id, since_index=cursor)
        self.assertEqual(len(follow_up), 0)
        self.assertGreaterEqual(cursor_two, cursor)

if __name__ == "__main__":  # pragma: no cover
    unittest.main()
