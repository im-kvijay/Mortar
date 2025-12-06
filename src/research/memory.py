"""specialist memory system - hybrid memory for specialist agents"""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime
import json


@dataclass
class Discovery:
    """A single discovery made by a specialist"""
    round_num: int
    discovery_type: str  # "function", "invariant", "vulnerability", etc.
    content: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for consensus scoring and logging"""
        return {
            "round_num": self.round_num,
            "type": self.discovery_type,
            "content": self.content,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "timestamp": self.timestamp
        }


@dataclass
class RoundSummary:
    """Summary of a single analysis round"""
    round_num: int
    discoveries: List[Discovery]
    functions_analyzed: List[str]
    reasoning: str
    decision: str  # "continue", "stop", "need_more_info"
    confidence: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class SpecialistMemory:
    """
    Hybrid memory system for specialist agents

    Persistent State:
    - Key discoveries
    - Functions analyzed
    - State variables traced
    - Open questions
    - Confidence scores

    Recent Context:
    - Last 2-3 rounds of analysis
    """

    def __init__(self, agent_name: str, max_recent_rounds: int = 3):
        """
        Initialize specialist memory

        Args:
            agent_name: Name of the specialist agent
            max_recent_rounds: How many recent rounds to keep in context
        """
        self.agent_name = agent_name
        self.max_recent_rounds = max_recent_rounds

        # Persistent state (across all rounds)
        self.key_discoveries: List[Discovery] = []
        self.analyzed_functions: Set[str] = set()
        self.traced_state_vars: Set[str] = set()
        self.open_questions: List[str] = []
        self.confidence_scores: Dict[str, float] = {}
        self.total_rounds = 0

        # Recent context (last N rounds)
        self.recent_rounds: deque[RoundSummary] = deque(maxlen=max_recent_rounds)

        # Metadata
        self.created_at = datetime.now().isoformat()
        self.last_updated = datetime.now().isoformat()

    def add_discovery(
        self,
        round_num: int,
        discovery_type: str,
        content: str,
        confidence: float,
        evidence: Optional[List[str]] = None
    ):
        """
        Add a discovery to persistent memory

        Args:
            round_num: Which round this was discovered in
            discovery_type: Type of discovery
            content: Description of discovery
            confidence: Confidence score (0.0-1.0)
            evidence: Supporting evidence
        """
        discovery = Discovery(
            round_num=round_num,
            discovery_type=discovery_type,
            content=content,
            confidence=confidence,
            evidence=evidence or []
        )
        self.key_discoveries.append(discovery)
        self.last_updated = datetime.now().isoformat()

    def mark_function_analyzed(self, function_name: str):
        """Mark a function as analyzed"""
        self.analyzed_functions.add(function_name)
        self.last_updated = datetime.now().isoformat()

    def mark_state_var_traced(self, var_name: str):
        """Mark a state variable as traced"""
        self.traced_state_vars.add(var_name)
        self.last_updated = datetime.now().isoformat()

    def add_question(self, question: str):
        """Add an open question"""
        if question not in self.open_questions:
            self.open_questions.append(question)
            self.last_updated = datetime.now().isoformat()

    def resolve_question(self, question: str):
        """Remove a resolved question"""
        if question in self.open_questions:
            self.open_questions.remove(question)
            self.last_updated = datetime.now().isoformat()

    def set_confidence(self, key: str, confidence: float):
        """Set confidence score for a specific aspect"""
        self.confidence_scores[key] = confidence
        self.last_updated = datetime.now().isoformat()

    def add_round_summary(
        self,
        round_num: int,
        discoveries: List[Discovery],
        functions_analyzed: List[str],
        reasoning: str,
        decision: str,
        confidence: float
    ):
        """
        Add a round summary to recent context

        Args:
            round_num: Round number
            discoveries: Discoveries made this round
            functions_analyzed: Functions analyzed this round
            reasoning: Reasoning for this round
            decision: Decision (continue/stop/need_more_info)
            confidence: Overall confidence this round
        """
        summary = RoundSummary(
            round_num=round_num,
            discoveries=discoveries,
            functions_analyzed=functions_analyzed,
            reasoning=reasoning,
            decision=decision,
            confidence=confidence
        )
        self.recent_rounds.append(summary)
        self.total_rounds = max(self.total_rounds, round_num)
        self.last_updated = datetime.now().isoformat()

    def prepare_prompt_context(self, round_num: int, contract_info: Dict[str, Any]) -> str:
        """
        Prepare context for AI prompt

        Includes:
        - Persistent state (key discoveries, analyzed functions, etc.)
        - Recent context (last N rounds)
        - Open questions
        - Progress tracking

        Args:
            round_num: Current round number
            contract_info: Info about the contract being analyzed

        Returns:
            Formatted context string for prompt
        """
        context_parts = []

        # Header
        context_parts.append(f"=== {self.agent_name} Analysis - Round {round_num} ===\n")

        # Contract info
        context_parts.append(f"Contract: {contract_info.get('name', 'Unknown')}")
        context_parts.append(f"Total Functions: {contract_info.get('total_functions', '?')}")
        context_parts.append(f"Total State Variables: {contract_info.get('total_state_vars', '?')}\n")

        # Progress tracking
        context_parts.append("=== PROGRESS ===")
        context_parts.append(f"Functions Analyzed: {len(self.analyzed_functions)}/{contract_info.get('total_functions', '?')}")
        context_parts.append(f"State Variables Traced: {len(self.traced_state_vars)}/{contract_info.get('total_state_vars', '?')}")
        context_parts.append(f"Total Discoveries: {len(self.key_discoveries)}")
        context_parts.append(f"Total Rounds: {self.total_rounds}\n")

        # Key discoveries (persistent)
        if self.key_discoveries:
            context_parts.append("=== KEY DISCOVERIES (Persistent Memory) ===")
            for i, disc in enumerate(self.key_discoveries[-10:], 1):  # Last 10 discoveries
                context_parts.append(
                    f"{i}. [{disc.discovery_type}] (Round {disc.round_num}, confidence={disc.confidence:.2f}): {disc.content}"
                )
            if len(self.key_discoveries) > 10:
                context_parts.append(f"... and {len(self.key_discoveries) - 10} more discoveries")
            context_parts.append("")

        # Recent rounds (recent context)
        if self.recent_rounds:
            context_parts.append(f"=== RECENT ANALYSIS (Last {len(self.recent_rounds)} Rounds) ===")
            for summary in self.recent_rounds:
                context_parts.append(f"\nRound {summary.round_num}:")
                context_parts.append(f"  Decision: {summary.decision}")
                context_parts.append(f"  Confidence: {summary.confidence:.2f}")
                context_parts.append(f"  Discoveries: {len(summary.discoveries)}")
                if summary.discoveries:
                    for disc in summary.discoveries[:3]:  # Show top 3
                        context_parts.append(f"    - {disc.content}")
                context_parts.append(f"  Reasoning: {summary.reasoning[:200]}...")
            context_parts.append("")

        # Open questions
        if self.open_questions:
            context_parts.append("=== OPEN QUESTIONS ===")
            for i, q in enumerate(self.open_questions, 1):
                context_parts.append(f"{i}. {q}")
            context_parts.append("")

        # Analyzed functions
        if self.analyzed_functions:
            context_parts.append(f"=== ANALYZED FUNCTIONS ({len(self.analyzed_functions)}) ===")
            context_parts.append(", ".join(sorted(list(self.analyzed_functions)[:20])))
            if len(self.analyzed_functions) > 20:
                context_parts.append(f"... and {len(self.analyzed_functions) - 20} more")
            context_parts.append("")

        # Confidence scores
        if self.confidence_scores:
            context_parts.append("=== CONFIDENCE SCORES ===")
            for key, score in sorted(self.confidence_scores.items(), key=lambda x: x[1], reverse=True):
                context_parts.append(f"  {key}: {score:.2f}")
            context_parts.append("")

        return "\n".join(context_parts)

    def get_overall_confidence(self) -> float:
        """
        Calculate overall confidence score

        Based on:
        - Number of discoveries
        - Confidence scores
        - Coverage (functions analyzed)
        """
        if not self.key_discoveries:
            return 0.0

        # Average discovery confidence
        avg_discovery_conf = sum(d.confidence for d in self.key_discoveries) / len(self.key_discoveries)

        # Average explicit confidence scores
        avg_explicit_conf = sum(self.confidence_scores.values()) / len(self.confidence_scores) if self.confidence_scores else 0.5

        # Overall confidence (weighted average)
        return (avg_discovery_conf * 0.6 + avg_explicit_conf * 0.4)

    def to_dict(self) -> Dict[str, Any]:
        """Convert memory to dictionary for serialization"""
        return {
            "agent_name": self.agent_name,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "total_rounds": self.total_rounds,
            "key_discoveries": [
                {
                    "round_num": d.round_num,
                    "discovery_type": d.discovery_type,
                    "content": d.content,
                    "confidence": d.confidence,
                    "evidence": d.evidence,
                    "timestamp": d.timestamp
                }
                for d in self.key_discoveries
            ],
            "analyzed_functions": list(self.analyzed_functions),
            "traced_state_vars": list(self.traced_state_vars),
            "open_questions": self.open_questions,
            "confidence_scores": self.confidence_scores,
            "recent_rounds": [
                {
                    "round_num": r.round_num,
                    "discoveries": [
                        {
                            "round_num": d.round_num,
                            "discovery_type": d.discovery_type,
                            "content": d.content,
                            "confidence": d.confidence,
                            "evidence": d.evidence,
                            "timestamp": d.timestamp
                        }
                        for d in r.discoveries
                    ],
                    "functions_analyzed": r.functions_analyzed,
                    "reasoning": r.reasoning,
                    "decision": r.decision,
                    "confidence": r.confidence,
                    "timestamp": r.timestamp
                }
                for r in self.recent_rounds
            ],
            "overall_confidence": self.get_overall_confidence()
        }

    def save_to_json(self, filepath: str):
        """Save memory to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_json(cls, filepath: str) -> "SpecialistMemory":
        """Load memory from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)

        memory = cls(agent_name=data["agent_name"])
        memory.created_at = data["created_at"]
        memory.last_updated = data["last_updated"]
        memory.total_rounds = data["total_rounds"]

        # Load key discoveries
        for disc_data in data["key_discoveries"]:
            discovery = Discovery(
                round_num=disc_data["round_num"],
                discovery_type=disc_data["discovery_type"],
                content=disc_data["content"],
                confidence=disc_data["confidence"],
                evidence=disc_data["evidence"],
                timestamp=disc_data["timestamp"]
            )
            memory.key_discoveries.append(discovery)

        # Load analyzed functions and state vars
        memory.analyzed_functions = set(data["analyzed_functions"])
        memory.traced_state_vars = set(data["traced_state_vars"])
        memory.open_questions = data["open_questions"]
        memory.confidence_scores = data["confidence_scores"]

        # Load recent rounds
        for round_data in data["recent_rounds"]:
            discoveries = [
                Discovery(
                    round_num=d["round_num"],
                    discovery_type=d["discovery_type"],
                    content=d["content"],
                    confidence=d["confidence"],
                    evidence=d["evidence"],
                    timestamp=d["timestamp"]
                )
                for d in round_data["discoveries"]
            ]
            summary = RoundSummary(
                round_num=round_data["round_num"],
                discoveries=discoveries,
                functions_analyzed=round_data["functions_analyzed"],
                reasoning=round_data["reasoning"],
                decision=round_data["decision"],
                confidence=round_data["confidence"],
                timestamp=round_data["timestamp"]
            )
            memory.recent_rounds.append(summary)

        return memory


# Example usage
if __name__ == "__main__":
    # Create memory
    memory = SpecialistMemory("StateFlow")

    # Simulate Round 1
    memory.add_discovery(
        round_num=1,
        discovery_type="function",
        content="flashLoan() is external and allows borrowing entire vault balance",
        confidence=0.95,
        evidence=["Line 42: function flashLoan(uint256 amount) external"]
    )
    memory.mark_function_analyzed("flashLoan")
    memory.add_question("How is totalAssets updated during flashLoan?")

    memory.add_round_summary(
        round_num=1,
        discoveries=[memory.key_discoveries[0]],
        functions_analyzed=["flashLoan"],
        reasoning="Analyzed flashLoan function, found critical state interactions",
        decision="continue",
        confidence=0.8
    )

    # Simulate Round 2
    memory.add_discovery(
        round_num=2,
        discovery_type="state_flow",
        content="totalAssets is read but not modified during flashLoan",
        confidence=0.9,
        evidence=["Line 48: require(totalAssets >= amount)"]
    )
    memory.mark_state_var_traced("totalAssets")
    memory.resolve_question("How is totalAssets updated during flashLoan?")

    memory.add_round_summary(
        round_num=2,
        discoveries=[memory.key_discoveries[1]],
        functions_analyzed=["flashLoan", "deposit"],
        reasoning="Traced totalAssets modifications, answered open question",
        decision="continue",
        confidence=0.85
    )

    # Print context
    contract_info = {
        "name": "UnstoppableVault",
        "total_functions": 10,
        "total_state_vars": 5
    }

    context = memory.prepare_prompt_context(round_num=3, contract_info=contract_info)
    print(context)

    # Save memory
    memory.save_to_json("/tmp/memory_test.json")
    print("\n[OK] Memory saved to /tmp/memory_test.json")

    # Load memory
    loaded = SpecialistMemory.load_from_json("/tmp/memory_test.json")
    print(f"[OK] Memory loaded: {loaded.agent_name}, {len(loaded.key_discoveries)} discoveries")
