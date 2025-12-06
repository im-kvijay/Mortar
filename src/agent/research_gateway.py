"""module docstring"""

from typing import Dict, Any, Optional
from dataclasses import dataclass

from config import config
from utils.llm_backend import LLMBackend
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager
from agent.research_cache import ResearchCache


@dataclass
class JITResponse:
    """
    Response from JIT research

    Attributes:
        question: Original question
        answer: Research answer
        confidence: 0.0-1.0 confidence score
        specialist_type: Which specialist answered
        mode: single/cached
        cost: Cost for this request
        cached: True if answer came from cache
        evidence: Supporting evidence
    """
    question: str
    answer: str
    confidence: float
    specialist_type: str
    mode: str
    cost: float
    cached: bool
    evidence: list


class ResearchGateway:
    """
    JIT research gateway

    Routes research requests from attackers to research specialists.

    Manages:
    - Request routing (which specialist to use)
    - Caching (avoid duplicate research)
    - Cost tracking
    - Logging
    """

    def __init__(
        self,
        backend: LLMBackend,
        logger: ResearchLogger,
        cost_manager: CostManager,
        cache_file: Optional[str] = None,
    ):
        """
        Initialize JIT research gateway

        Args:
            backend: LLM backend
            logger: Audit logger
            cost_manager: Cost tracking
            cache_file: Path to cache file
        """
        self.backend = backend
        self.logger = logger
        self.cost_manager = cost_manager

        # use config default if not specified
        if cache_file is None:
            cache_file = str(config.JIT_CACHE_FILE)

        self.cache = ResearchCache(cache_file)

        self.logger.info("[JIT Gateway] Initialized (single-specialist mode)")

    def request_analysis(
        self,
        question: str,
        specialist_type: str,
        context: str,
        contract_source: Optional[str] = None,
        contract_info: Optional[Dict[str, Any]] = None,
        urgency: str = "medium",
        max_cost: float = 0.10,
        timeout: int = 60,
        attacker_name: Optional[str] = None,
        contract_name: Optional[str] = None,
    ) -> JITResponse:
        """
        Request JIT research analysis

        Args:
            question: Specific question to research
            specialist_type: Which specialist (invariant, state_flow, etc)
            context: Why this question matters
            contract_source: Solidity source (optional)
            contract_info: Contract metadata (optional)
            urgency: high/medium/low
            max_cost: Budget limit
            timeout: Max seconds

        Returns:
            JITResponse with answer
        """
        self.logger.info(f"[JIT Gateway] Request: {question[:100]}...")
        self.logger.info(f"[JIT Gateway] Specialist: {specialist_type}, Urgency: {urgency}")

        # check cache first
        cache_key = self.cache.make_key(question, specialist_type)
        cached_response = self.cache.get(cache_key)

        if cached_response:
            self.logger.info("[JIT Gateway] Cache hit!")
            return JITResponse(
                question=question,
                answer=cached_response["answer"],
                confidence=cached_response["confidence"],
                specialist_type=specialist_type,
                mode="cached",
                cost=0.0,
                cached=True,
                evidence=cached_response.get("evidence", [])
            )

        # execute research (single-specialist mode)
        response = self._execute_single_research(
            question=question,
            specialist_type=specialist_type,
            context=context,
            contract_source=contract_source,
            contract_info=contract_info,
            max_cost=max_cost
        )

        # cache response
        self.cache.set(cache_key, {
            "answer": response.answer,
            "confidence": response.confidence,
            "evidence": response.evidence,
            "specialist_type": specialist_type,
            "mode": "single"
        })

        # log jit request
        self.logger.log_jit_request(
            attacker_name=attacker_name or "UnknownAttacker",
            contract_name=contract_name or contract_info.get("name", "Unknown") if contract_info else "UnknownContract",
            question=question,
            specialist_type=specialist_type,
            urgency=urgency,
            mode=response.mode,
            response=response,
            cost=response.cost,
            metadata={
                "context": context,
                "cached": response.cached,
            }
        )

        return response

    def _execute_single_research(
        self,
        question: str,
        specialist_type: str,
        context: str,
        contract_source: Optional[str],
        contract_info: Optional[Dict[str, Any]],
        max_cost: float
    ) -> JITResponse:
        """
        Execute JIT research with single specialist

        Args:
            question: Research question
            specialist_type: Which specialist
            context: Why this matters
            contract_source: Solidity source
            contract_info: Contract metadata
            max_cost: Budget limit

        Returns:
            JITResponse
        """
        self.logger.info("[JIT Gateway] Executing single specialist research...")

        # spawn specialist
        specialist = self._spawn_specialist(specialist_type)

        # build focused prompt
        prompt = self._build_jit_prompt(
            question=question,
            context=context,
            contract_source=contract_source,
            contract_info=contract_info
        )

        # call specialist with focused prompt
        system_prompt = specialist.get_system_prompt()
        llm_response = self.backend.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            max_tokens=config.JIT_MAX_TOKENS,
            temperature=config.EXTENDED_THINKING_TEMPERATURE,
            thinking_budget=config.JIT_THINKING_BUDGET_SINGLE
        )

        # track cost
        contract_name = contract_info.get("name", "Unknown") if contract_info else "Unknown"
        self.cost_manager.log_cost(
            agent_name=f"JIT_{specialist_type}",
            contract_name=contract_name,
            round_num=0,  # JIT research is ad-hoc, not round-based
            operation="jit_research",
            cost=llm_response.cost
        )

        # extract answer and confidence from response
        answer = self._extract_answer(llm_response.text)
        confidence = self._extract_confidence(llm_response.text)
        evidence = self._extract_evidence(llm_response.text)

        return JITResponse(
            question=question,
            answer=answer,
            confidence=confidence,
            specialist_type=specialist_type,
            mode="single",
            cost=llm_response.cost,
            cached=False,
            evidence=evidence
        )

    def _spawn_specialist(self, specialist_type: str):
        """
        Spawn a specialist instance

        Args:
            specialist_type: invariant, state_flow, etc

        Returns:
            Specialist instance
        """
        from research.business_logic import BusinessLogicAnalyst
        from research.state_flow import StateFlowAnalyst
        from research.invariant import InvariantAnalyst
        from research.economic import EconomicAnalyst
        from research.dependency import DependencyAnalyst
        from research.access_control import AccessControlAnalyst

        specialist_map = {
            "business_logic": BusinessLogicAnalyst,
            "state_flow": StateFlowAnalyst,
            "invariant": InvariantAnalyst,
            "economic": EconomicAnalyst,
            "dependency": DependencyAnalyst,
            "access_control": AccessControlAnalyst
        }

        specialist_class = specialist_map.get(specialist_type, InvariantAnalyst)

        # create instance
        specialist = specialist_class(
            backend=self.backend,
            thinking_budget=6000,  # Half of normal (focused question)
            cost_limit=0.10  # Max cost for JIT request
        )

        return specialist

    def _build_jit_prompt(
        self,
        question: str,
        context: str,
        contract_source: Optional[str],
        contract_info: Optional[Dict[str, Any]]
    ) -> str:
        """
        Build focused JIT research prompt

        Args:
            question: Specific question
            context: Why this matters
            contract_source: Solidity source
            contract_info: Contract metadata

        Returns:
            Focused prompt
        """
        prompt = f"""JUST-IN-TIME RESEARCH REQUEST

Question: {question}

Context: {context}

Your task: Provide a focused, high-confidence answer to this specific question.
"""

        if contract_source:
            prompt += f"""

Contract source:
```solidity
{contract_source[:2000]}  # Truncate for focused analysis
```
"""

        if contract_info:
            prompt += f"""

Contract info:
- Name: {contract_info.get('name', 'Unknown')}
- Functions: {contract_info.get('total_functions', '?')}
"""

        prompt += """

Output format:
ANSWER: [Your focused answer to the question]
CONFIDENCE: [0.0-1.0]
EVIDENCE: [Code references or reasoning]
"""

        return prompt

    def _extract_answer(self, response: str) -> str:
        """Extract answer from LLM response"""
        import re
        match = re.search(r'ANSWER:\s*(.+?)(?:\n|CONFIDENCE:|EVIDENCE:|$)', response, re.DOTALL)
        if match:
            return match.group(1).strip()
        # fallback: return first paragraph
        lines = [l.strip() for l in response.split('\n') if l.strip()]
        return lines[0] if lines else response[:200]

    def _extract_confidence(self, response: str) -> float:
        """Extract confidence from LLM response"""
        import re
        match = re.search(r'CONFIDENCE:\s*([\d.]+)', response, re.IGNORECASE)
        if match:
            try:
                return float(match.group(1))
            except Exception as exc:
                self.logger.warning(f"[JIT Gateway] Failed to parse confidence: {exc}")
        return 0.75  # Default medium confidence

    def _extract_evidence(self, response: str) -> list:
        """Extract evidence from LLM response"""
        import re
        match = re.search(r'EVIDENCE:\s*(.+?)(?:\n\n|$)', response, re.DOTALL)
        if match:
            evidence_text = match.group(1).strip()
            # split by newlines or commas
            return [e.strip() for e in re.split(r'[\n,]', evidence_text) if e.strip()]
        return []
