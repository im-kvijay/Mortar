"""module docstring"""

import json
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, UTC

from utils.llm_backend import LLMBackend
from utils.logging import ResearchLogger


@dataclass
class PlaybookEntry:
    """
    Single lesson/pattern in the evolving playbook

    Attributes:
        id: Unique identifier
        pattern_name: Short name (e.g., "flash_loan_dos")
        context: When this pattern applies
        approach: How to analyze this pattern
        pitfalls: Common mistakes to avoid
        success_rate: How often this worked (0.0-1.0)
        created: Timestamp
        last_used: Last successful application
        use_count: Number of times applied
    """
    id: str
    pattern_name: str
    context: str  # "When analyzing flash loan integrations..."
    approach: str  # "Check for balance caching before transfer..."
    pitfalls: str  # "Don't assume all ERC20s have same decimals..."
    success_rate: float  # 0.0-1.0
    created: str  # ISO timestamp
    last_used: Optional[str] = None
    use_count: int = 0


class ACEPlaybook:
    """
    Evolving playbook (context) that grows with experience

    Stores successful patterns, approaches, and lessons learned.
    Automatically curated based on performance feedback.
    """

    def __init__(self, playbook_path: str, logger: ResearchLogger):
        self.playbook_path = playbook_path
        self.logger = logger
        self.entries: List[PlaybookEntry] = []

        # load existing playbook if available
        self.load()

    def load(self):
        """Load playbook from disk"""
        if os.path.exists(self.playbook_path):
            with open(self.playbook_path, 'r') as f:
                data = json.load(f)
                self.entries = [PlaybookEntry(**entry) for entry in data.get('entries', [])]
            self.logger.info(f"[ACE Playbook] Loaded {len(self.entries)} patterns from {self.playbook_path}")
        else:
            self.logger.info(f"[ACE Playbook] No existing playbook found, starting fresh")
            self.entries = []

    def save(self):
        """Save playbook to disk"""
        os.makedirs(os.path.dirname(self.playbook_path), exist_ok=True)
        with open(self.playbook_path, 'w') as f:
            json.dump({
                'entries': [asdict(entry) for entry in self.entries],
                'last_updated': datetime.now(UTC).isoformat()
            }, f, indent=2)
        self.logger.info(f"[ACE Playbook] Saved {len(self.entries)} patterns to {self.playbook_path}")

    def add_entry(self, entry: PlaybookEntry):
        """Add new pattern to playbook"""
        self.entries.append(entry)
        self.save()

    def update_success_rate(self, entry_id: str, successful: bool):
        """Update success rate for an entry (Bayesian update)"""
        for entry in self.entries:
            if entry.id == entry_id:
                # bayesian update
                alpha = 2  # Prior successes (optimistic)
                beta = 1   # Prior failures

                n = entry.use_count
                k = int(entry.success_rate * n) if n > 0 else 0

                if successful:
                    k += 1
                n += 1

                # posterior mean
                entry.success_rate = (k + alpha) / (n + alpha + beta)
                entry.use_count = n
                entry.last_used = datetime.now(UTC).isoformat()
                self.save()
                break

    def get_relevant_entries(self, context: str, top_k: int = 5) -> List[PlaybookEntry]:
        """
        Get most relevant playbook entries for current context

        Args:
            context: Current analysis context (e.g., contract type, functions)
            top_k: Number of entries to return

        Returns:
            Top-k most relevant entries, sorted by success rate
        """
        # simple keyword matching + success rate ranking
        # (could be enhanced with embeddings for semantic matching)

        scored_entries = []
        context_lower = context.lower()

        for entry in self.entries:
            # score based on keyword overlap + success rate
            keywords = entry.context.lower().split()
            overlap = sum(1 for kw in keywords if kw in context_lower)
            score = overlap * entry.success_rate

            if score > 0:
                scored_entries.append((score, entry))

        # sort by score descending
        scored_entries.sort(key=lambda x: x[0], reverse=True)

        return [entry for score, entry in scored_entries[:top_k]]

    def to_context_string(self, relevant_entries: List[PlaybookEntry]) -> str:
        """
        Convert playbook entries to context string for LLM

        Returns:
            Formatted context with lessons and patterns
        """
        if not relevant_entries:
            return ""

        context_parts = ["=== LEARNED PATTERNS (ACE Playbook) ===\n"]
        context_parts.append("Lessons from previous analyses:\n\n")

        for i, entry in enumerate(relevant_entries, 1):
            context_parts.append(f"{i}. {entry.pattern_name} (success rate: {entry.success_rate:.1%}, used {entry.use_count}x)\n")
            context_parts.append(f"   WHEN: {entry.context}\n")
            context_parts.append(f"   APPROACH: {entry.approach}\n")
            context_parts.append(f"   PITFALLS: {entry.pitfalls}\n\n")

        context_parts.append("Apply these lessons when relevant, but adapt to the specific contract.\n")
        context_parts.append("=" * 60 + "\n\n")

        return "".join(context_parts)


class ACEReflector:
    """
    Reflector role: Analyzes agent performance and extracts lessons

    Reviews:
    - What worked? → Extract successful patterns
    - What failed? → Identify pitfalls
    - What can improve? → Suggest refinements
    """

    def __init__(self, backend: LLMBackend, logger: ResearchLogger):
        self.backend = backend
        self.logger = logger

    def reflect(
        self,
        contract_analysis: str,
        discoveries: List[Dict[str, Any]],
        feedback: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """
        Reflect on analysis performance and extract lessons

        Args:
            contract_analysis: The analysis that was performed
            discoveries: Discoveries made (for success analysis)
            feedback: Optional feedback (e.g., from verification, PoC results)

        Returns:
            List of lessons learned (pattern_name, context, approach, pitfalls)
        """
        self.logger.info("[ACE Reflector] Analyzing performance and extracting lessons...")

        # build reflection prompt
        prompt = f"""You are the Reflector in an Agentic Context Engineering (ACE) system.

Your role: Analyze the agent's performance and extract reusable lessons for future analyses.

AGENT'S ANALYSIS:
{contract_analysis}

DISCOVERIES MADE:
{json.dumps([{'type': d['type'], 'confidence': d.get('confidence', 0.0)} for d in discoveries], indent=2)}

{f"FEEDBACK FROM VALIDATION:{feedback}" if feedback else ""}

YOUR TASK:
Extract 1-3 specific, actionable lessons that should be added to the evolving playbook.

For each lesson, provide:
1. pattern_name: Short, memorable name (e.g., "flash_loan_balance_caching")
2. context: When this pattern applies (e.g., "When analyzing contracts with flash loan borrowing...")
3. approach: What worked well (e.g., "Check if balance is cached before transfers to prevent DoS...")
4. pitfalls: What to avoid (e.g., "Don't assume ERC20.balanceOf always returns current state...")

Focus on NOVEL insights, not obvious best practices. What did this specific analysis teach us?

Output JSON array:
[
  {{
    "pattern_name": "...",
    "context": "...",
    "approach": "...",
    "pitfalls": "..."
  }}
]
"""

        try:
            # Use Extended Thinking for deep reflection
            response = self.backend.generate(
                messages=[{"role": "user", "content": prompt}],
                thinking_budget=5000,  # Moderate thinking for reflection
                temperature=0.3  # More focused
            )

            # Parse JSON response
            content = response.content[0].text if hasattr(response.content[0], 'text') else str(response.content[0])

            # Extract JSON array
            import re
            json_match = re.search(r'\[\s*\{.*?\}\s*\]', content, re.DOTALL)
            if json_match:
                lessons = json.loads(json_match.group(0))
                self.logger.info(f"[ACE Reflector] Extracted {len(lessons)} lessons")
                return lessons
            else:
                self.logger.warning("[ACE Reflector] No valid JSON found in reflection output")
                return []

        except Exception as e:
            self.logger.error(f"[ACE Reflector] Reflection failed: {e}")
            return []


class ACEFramework:
    """
    Main ACE (Agentic Context Engineering) framework

    Wraps any specialist agent and adds self-improving capabilities through:
    1. Evolving playbook (context grows with experience)
    2. Reflection after each analysis
    3. Automatic curation of successful patterns

    NO FINE-TUNING REQUIRED - Pure context manipulation for self-improvement.
    """

    def __init__(
        self,
        base_specialist,  # Any specialist (e.g., BusinessLogicAnalyst_V3_Enhanced)
        backend: LLMBackend,
        logger: ResearchLogger,
        playbook_path: str
    ):
        self.base_specialist = base_specialist
        self.backend = backend
        self.logger = logger

        # Initialize components
        self.playbook = ACEPlaybook(playbook_path=playbook_path, logger=logger)
        self.reflector = ACEReflector(backend=backend, logger=logger)

        self.logger.info(f"[ACE Framework] Initialized with {len(self.playbook.entries)} existing patterns")

    def analyze_contract(
        self,
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Run analysis with ACE enhancement

        Flow:
        1. Get relevant playbook entries for this contract
        2. Inject playbook context into specialist's system prompt
        3. Run specialist analysis (Generator role)
        4. Reflect on results (Reflector role)
        5. Update playbook with lessons (Curator role)
        6. Return enhanced results

        Args:
            contract_source: Solidity source code
            contract_info: Contract metadata

        Returns:
            Analysis results with ACE metadata
        """
        contract_name = contract_info.get("name", "Unknown")
        self.logger.info(f"[ACE Framework] Starting ACE-enhanced analysis of {contract_name}")

        # STEP 1: Get relevant playbook entries
        context_desc = f"smart contract {contract_name} with functions: {', '.join(contract_info.get('functions', [])[:5])}"
        relevant_entries = self.playbook.get_relevant_entries(context=context_desc, top_k=5)

        self.logger.info(f"[ACE Framework] Retrieved {len(relevant_entries)} relevant playbook patterns")

        # STEP 2: Inject playbook context
        playbook_context = self.playbook.to_context_string(relevant_entries)

        # Prepend to specialist's system prompt (if specialist supports it)
        if hasattr(self.base_specialist, 'system_prompt'):
            original_prompt = self.base_specialist.system_prompt
            self.base_specialist.system_prompt = playbook_context + original_prompt

        # STEP 3: Run specialist analysis (Generator role)
        try:
            result = self.base_specialist.analyze_contract(
                contract_source=contract_source,
                contract_info=contract_info
            )

            discoveries = result.get('discoveries', [])
            analysis_summary = result.get('summary', '')

            self.logger.info(f"[ACE Framework] Generator completed: {len(discoveries)} discoveries")

        finally:
            # Restore original prompt
            if hasattr(self.base_specialist, 'system_prompt'):
                self.base_specialist.system_prompt = original_prompt

        # STEP 4: Reflect on results (Reflector role)
        lessons = self.reflector.reflect(
            contract_analysis=analysis_summary,
            discoveries=discoveries,
            feedback=None  # Could add PoC validation feedback here
        )

        # STEP 5: Update playbook (Curator role)
        for lesson in lessons:
            entry = PlaybookEntry(
                id=f"{contract_name}_{lesson['pattern_name']}_{datetime.now(UTC).timestamp()}",
                pattern_name=lesson['pattern_name'],
                context=lesson['context'],
                approach=lesson['approach'],
                pitfalls=lesson['pitfalls'],
                success_rate=0.7,  # Optimistic prior (will be updated with feedback)
                created=datetime.now(UTC).isoformat(),
                use_count=0
            )
            self.playbook.add_entry(entry)
            self.logger.info(f"[ACE Framework] Curated new pattern: {entry.pattern_name}")

        # Mark used entries as successful (simple heuristic: if discoveries were made)
        if len(discoveries) > 0:
            for entry in relevant_entries:
                self.playbook.update_success_rate(entry.id, successful=True)

        # STEP 6: Return enhanced results
        result['ace_metadata'] = {
            'playbook_size': len(self.playbook.entries),
            'patterns_used': len(relevant_entries),
            'new_patterns_learned': len(lessons),
            'compound_improvement': f"{len(self.playbook.entries)} total patterns (up from 0 initially)"
        }

        self.logger.info(f"[ACE Framework] Playbook now contains {len(self.playbook.entries)} patterns (+{len(lessons)} this iteration)")

        return result

    def update_from_feedback(self, entry_ids: List[str], feedback: Dict[str, bool]):
        """
        Update playbook success rates based on external feedback

        Args:
            entry_ids: List of playbook entry IDs that were used
            feedback: Dict mapping entry_id to success (True/False)

        Example:
            # after poc validation
            ace.update_from_feedback(
                entry_ids=["pattern_1", "pattern_2"],
                feedback={"pattern_1": True, "pattern_2": False}  # pattern_1 led to valid PoC
            )
        """
        for entry_id, successful in feedback.items():
            self.playbook.update_success_rate(entry_id, successful)
            self.logger.info(f"[ACE Framework] Updated {entry_id}: {'SUCCESS' if successful else 'FAILURE'}")
