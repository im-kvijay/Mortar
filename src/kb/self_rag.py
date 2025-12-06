"""self-reflective retrieval with quality assessment"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, UTC
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from cache.selfrag_cache import SelfRAGCache
from config import config
from kb.graph_rag import GraphRAG
from kb.knowledge_base import VulnerabilityPattern
from kb.self_rag_schema import PatternJudgment, SelfRAGResponse
from utils.json_sanitizer import safe_json_loads
from utils.llm_backend import create_backend
from utils.llm_backend.base import LLMResponse

logger = logging.getLogger(__name__)

PROMPT_VERSION = "2025-11-structured-v1"
SYSTEM_PROMPT = (
    "You are a labeling function for vulnerability patterns. "
    "Always respond with JSON that matches the provided schema. "
    "Do not add prose, explanations, or code fences."
)


def call_llm(
    prompt,
    backend="grok",
    thinking_budget=3000,
    temperature=0.3,
    max_tokens=300,
    system_prompt: Optional[str] = None,
):
    """call llm backend"""
    llm_backend = create_backend(backend_type=backend)
    response = llm_backend.generate(
        prompt=prompt,
        system_prompt=system_prompt,
        temperature=temperature,
        max_tokens=max_tokens
    )
    if isinstance(response, LLMResponse):
        return response.text
    if hasattr(response, "text"):
        return response.text  # type: ignore[attr-defined]
    if hasattr(response, "content"):
        return response.content  # type: ignore[attr-defined]
    return str(response)


class ReflectionToken(Enum):
    """reflection assessment tokens"""
    RELEVANT = "Relevant"
    IRRELEVANT = "Irrelevant"
    SUPPORTS = "Supports"
    CONTRADICTS = "Contradicts"
    HIGH_QUALITY = "HighQuality"
    LOW_QUALITY = "LowQuality"


@dataclass
class ReflectionResult:
    """reflection result on a pattern"""
    pattern: VulnerabilityPattern
    relevance: ReflectionToken  # RELEVANT or IRRELEVANT
    quality: ReflectionToken  # HIGH_QUALITY or LOW_QUALITY
    support: Optional[ReflectionToken] = None  # SUPPORTS or CONTRADICTS (for multi-pattern)
    reasoning: str = ""  # Why this assessment


@dataclass
class SelfRAGResult:
    """self-rag retrieval result"""
    relevant_patterns: List[VulnerabilityPattern]
    irrelevant_patterns: List[VulnerabilityPattern]
    reflections: List[ReflectionResult]
    total_retrieved: int
    total_relevant: int
    precision: float  # relevant / retrieved


class SelfRAG:
    """self-reflective rag with quality assessment"""

    def __init__(
        self,
        graph_rag: GraphRAG,
        llm_backend: str = "grok",
        thinking_budget: int = 3000  # Budget for reflection
    ):
        """
        Initialize Self-RAG

        Args:
            graph_rag: GraphRAG instance for retrieval
            llm_backend: Which model to use for reflection
            thinking_budget: Tokens for extended thinking
        """
        self.graph_rag = graph_rag
        self.llm_backend = llm_backend
        self.thinking_budget = thinking_budget
        self.reflection_cost = 0.0
        self.prompt_version = PROMPT_VERSION
        self.cache = SelfRAGCache()
        self.telemetry_path = config.DATA_DIR / "logs" / "selfrag_metrics.ndjson"
        self.telemetry_path.parent.mkdir(parents=True, exist_ok=True)
        self.min_relevant = 3

    def retrieve_with_reflection(
        self,
        query: str,
        query_pattern_id: Optional[str] = None,
        k: int = 10,
        hops: int = 2,
        quality_threshold: float = 0.5
    ) -> SelfRAGResult:
        """
        Retrieve patterns with self-reflection

        Process:
        1. Retrieve candidates from GraphRAG
        2. Reflect on each candidate's relevance
        3. Filter to keep only relevant patterns
        4. Return filtered results

        Args:
            query: Natural language query (e.g., "flash loan reentrancy")
            query_pattern_id: Optional starting pattern for graph traversal
            k: Number of candidates to retrieve
            hops: Graph traversal hops
            quality_threshold: Min quality score to include (0.0-1.0)

        Returns:
            SelfRAGResult with filtered patterns
        """
        query = self._normalize_query(query)
        print(f"[SelfRAG] Retrieving patterns for query: '{query}'")

        # Step 1: Retrieve candidates from GraphRAG
        if query_pattern_id:
            candidates = self.graph_rag.retrieve_context(
                query_pattern_id=query_pattern_id,
                k=k,
                hops=hops
            )
        else:
            # Fallback: Get all patterns and rank by similarity to query
            candidates = self._retrieve_by_text_query(query, k)

        print(f"[SelfRAG] Retrieved {len(candidates)} candidate patterns")

        if not candidates:
            return SelfRAGResult(
                relevant_patterns=[],
                irrelevant_patterns=[],
                reflections=[],
                total_retrieved=0,
                total_relevant=0,
                precision=0.0
            )

        # Step 2: Reflect on each candidate (with caching)
        reflections: List[ReflectionResult] = []
        for candidate in candidates:
            reflection = self.assess_relevance(query, candidate)
            reflections.append(reflection)

        # Step 3: Filter by relevance and quality
        relevant = []
        irrelevant = []

        fallback_used = False
        for reflection in reflections:
            # Must be RELEVANT and meet quality threshold
            if (reflection.relevance == ReflectionToken.RELEVANT and
                reflection.quality == ReflectionToken.HIGH_QUALITY):
                relevant.append(reflection.pattern)
            elif (reflection.relevance == ReflectionToken.RELEVANT and
                  reflection.pattern.confidence >= quality_threshold):
                # Allow lower quality if confidence is high enough
                relevant.append(reflection.pattern)
            else:
                irrelevant.append(reflection.pattern)

        # Ensure we always return a minimum number of relevant patterns
        if len(relevant) < self.min_relevant:
            boost = self._select_fallback_patterns(
                query=query,
                exclude_ids={p.id for p in relevant},
                needed=self.min_relevant - len(relevant)
            )
            if boost:
                fallback_used = True
                relevant.extend(boost)

        precision = len(relevant) / len(candidates) if candidates else 0.0

        print(f"[SelfRAG] Filtered: {len(relevant)} relevant, {len(irrelevant)} irrelevant")
        print(f"[SelfRAG] Precision: {precision:.2%}")
        self._log_summary(
            query=query,
            total_candidates=len(candidates),
            total_relevant=len(relevant),
            precision=precision,
            fallback_used=fallback_used
        )

        return SelfRAGResult(
            relevant_patterns=relevant,
            irrelevant_patterns=irrelevant,
            reflections=reflections,
            total_retrieved=len(candidates),
            total_relevant=len(relevant),
            precision=precision
        )

    def assess_relevance(
        self,
        query: str,
        pattern: VulnerabilityPattern
    ) -> ReflectionResult:
        """
        Assess whether a pattern is relevant to the query

        Uses LLM to reflect on relevance and quality.

        Args:
            query: User query
            pattern: Pattern to assess

        Returns:
            ReflectionResult with assessment
        """
        normalized_query = self._normalize_query(query)
        prompt = f"""You are assessing the relevance of a vulnerability pattern to a query.

QUERY:
{normalized_query}

PATTERN:
Name: {pattern.name}
Type: {pattern.vuln_type}
Description: {pattern.description}
Confidence: {pattern.confidence:.2f}
Successful exploits: {pattern.successful_exploits}
Failed attempts: {pattern.failed_attempts}

TASK:
Assess this pattern on two dimensions:

1. RELEVANCE: Is this pattern relevant to the query?
   - [Relevant]: Directly related to the query
   - [Irrelevant]: Not related or only tangentially related

2. QUALITY: Is this pattern well-validated and reliable?
   - [HighQuality]: High confidence (>0.7), successful exploits, low FPs
   - [LowQuality]: Low confidence (<0.5), no exploits, or high FPs

OUTPUT FORMAT (JSON):
{{
    "relevance": "Relevant" or "Irrelevant",
    "quality": "HighQuality" or "LowQuality",
    "reasoning": "Brief explanation (1-2 sentences)"
}}

OUTPUT:"""

        try:
            judgment = self._get_judgment(normalized_query, pattern)
        except Exception as e:
            print(f"[SelfRAG] Reflection failed: {e}")
            # Fallback: Use heuristics
            return self._fallback_assessment(normalized_query, pattern)

        relevance = ReflectionToken.RELEVANT if judgment.relevance == "Relevant" else ReflectionToken.IRRELEVANT
        quality = ReflectionToken.HIGH_QUALITY if judgment.quality == "HighQuality" else ReflectionToken.LOW_QUALITY
        return ReflectionResult(
            pattern=pattern,
            relevance=relevance,
            quality=quality,
            reasoning=judgment.reason
        )

    def assess_support(
        self,
        pattern1: VulnerabilityPattern,
        pattern2: VulnerabilityPattern
    ) -> ReflectionToken:
        """
        Assess whether two patterns support or contradict each other

        Used for cross-pattern validation.

        Args:
            pattern1, pattern2: Patterns to compare

        Returns:
            SUPPORTS or CONTRADICTS
        """
        prompt = f"""You are assessing whether two vulnerability patterns support or contradict each other.

PATTERN 1:
Name: {pattern1.name}
Type: {pattern1.vuln_type}
Description: {pattern1.description}

PATTERN 2:
Name: {pattern2.name}
Type: {pattern2.vuln_type}
Description: {pattern2.description}

TASK:
Determine if these patterns:
- [Supports]: Compatible, complementary, or reinforce each other
- [Contradicts]: Incompatible, mutually exclusive, or contradict each other

OUTPUT: Just "Supports" or "Contradicts"
"""

        try:
            response = call_llm(
                prompt=prompt,
                backend=self.llm_backend,
                thinking_budget=self.thinking_budget // 2,
                temperature=0.2,
                max_tokens=50
            )

            self.reflection_cost += 0.003

            if "Supports" in response:
                return ReflectionToken.SUPPORTS
            else:
                return ReflectionToken.CONTRADICTS

        except Exception as e:
            print(f"[SelfRAG] Support assessment failed: {e}")
            # Default: Assume support
            return ReflectionToken.SUPPORTS

    def _retrieve_by_text_query(
        self,
        query: str,
        k: int
    ) -> List[VulnerabilityPattern]:
        """
        Retrieve patterns by text similarity when no pattern_id is provided

        Uses simple keyword matching + type matching.

        Args:
            query: Text query
            k: Number to retrieve

        Returns:
            List of k best matching patterns
        """
        query = self._normalize_query(query)
        query_lower = query.lower()
        query_words = set(query_lower.split())

        # Score all patterns
        scored = []
        for pattern_id, pattern in self.graph_rag.kb.patterns.items():
            score = 0.0

            # Keyword overlap in name
            name_words = set(pattern.name.lower().split())
            name_overlap = len(query_words & name_words) / max(len(query_words), 1)
            score += 0.4 * name_overlap

            # Keyword overlap in description
            desc_words = set(pattern.description.lower().split())
            desc_overlap = len(query_words & desc_words) / max(len(query_words), 1)
            score += 0.3 * desc_overlap

            # Type match
            if any(word in pattern.vuln_type.lower() for word in query_words):
                score += 0.2

            # Confidence boost
            score += 0.1 * pattern.confidence

            scored.append((score, pattern))

        # Sort and return top-k
        scored.sort(reverse=True, key=lambda x: x[0])
        return [pattern for _, pattern in scored[:k]]

    def _fallback_assessment(
        self,
        query: str,
        pattern: VulnerabilityPattern
    ) -> ReflectionResult:
        """
        Fallback heuristic assessment when LLM fails

        Args:
            query: Query string
            pattern: Pattern to assess

        Returns:
            ReflectionResult based on heuristics
        """
        query = self._normalize_query(query)
        query_lower = query.lower()
        query_words = set(query_lower.split())

        # Check relevance via keyword matching
        name_words = set(pattern.name.lower().split())
        desc_words = set(pattern.description.lower().split())
        overlap = len(query_words & (name_words | desc_words))

        relevance = ReflectionToken.RELEVANT if overlap >= 2 else ReflectionToken.IRRELEVANT

        # Check quality via confidence
        quality = ReflectionToken.HIGH_QUALITY if pattern.confidence >= 0.7 else ReflectionToken.LOW_QUALITY

        result = ReflectionResult(
            pattern=pattern,
            relevance=relevance,
            quality=quality,
            reasoning="Heuristic assessment (LLM reflection failed)"
        )
        self._log_event(pattern.id, query, source="fallback", success=True)
        return result

    @staticmethod
    def _normalize_query(query: str) -> str:
        """Normalize queries (replace underscores with spaces, collapse whitespace)."""
        if not query:
            return ""
        query = query.replace("_", " ")
        return " ".join(query.split())

    def batch_retrieve(
        self,
        queries: List[str],
        k_per_query: int = 5
    ) -> Dict[str, SelfRAGResult]:
        """
        Retrieve patterns for multiple queries

        Args:
            queries: List of queries
            k_per_query: How many patterns per query

        Returns:
            Dict mapping query -> SelfRAGResult
        """
        results = {}

        for query in queries:
            print(f"\n[SelfRAG] Processing query: {query}")
            result = self.retrieve_with_reflection(query=query, k=k_per_query)
            results[query] = result

        print(f"\n[SelfRAG] Batch retrieval complete: {len(results)} queries")
        print(f"[SelfRAG] Total cost: ${self.reflection_cost:.3f}")

        return results

    def get_stats(self) -> Dict[str, float]:
        """Get statistics about Self-RAG performance"""
        return {
            "total_reflection_cost": self.reflection_cost
        }

    def _get_judgment(self, query: str, pattern: VulnerabilityPattern) -> PatternJudgment:
        """Fetch a pattern judgment using cache + structured outputs."""
        cache_key = self._cache_key(pattern, query)
        cached = self.cache.get(cache_key)
        if cached:
            try:
                judgment = PatternJudgment.model_validate(cached)
                self._log_event(pattern.id, query, source="cache", success=True)
                return judgment
            except (ValueError, TypeError) as exc:
                # Cached data is invalid or schema changed - fall through to LLM
                logger.debug(f"[SelfRAG] Cache validation failed for {pattern.id}: {exc}")

        prompt = self._build_reflection_prompt(query=query, pattern=pattern)
        response_text = call_llm(
            prompt=prompt,
            backend=self.llm_backend,
            thinking_budget=self.thinking_budget,
            temperature=0.2,
            max_tokens=400,
            system_prompt=SYSTEM_PROMPT
        )
        self.reflection_cost += 0.005

        payload = safe_json_loads(response_text)
        if "judgments" not in payload:
            payload = {"prompt_version": self.prompt_version, "judgments": [payload]}
        try:
            parsed = SelfRAGResponse.model_validate(payload)
        except Exception as exc:
            self._log_event(pattern.id, query, source="llm", success=False)
            raise ValueError(f"Structured reflection validation failed: {exc}") from exc

        judgment = next(
            (j for j in parsed.judgments if j.pattern_id == pattern.id),
            parsed.judgments[0]
        )
        # Cache the clean dict for future reuse
        try:
            self.cache.put(cache_key, judgment.model_dump())
        except (IOError, OSError) as exc:
            # Cache write failure - not critical, continue without caching
            logger.warning(f"[SelfRAG] Failed to cache judgment for {pattern.id}: {exc}")
        self._log_event(pattern.id, query, source="llm", success=True)
        return judgment

    def _cache_key(self, pattern: VulnerabilityPattern, query: str) -> str:
        fingerprint = "|".join([
            pattern.id,
            pattern.updated_at.isoformat(),
            f"{pattern.confidence:.4f}",
            query,
            self.prompt_version
        ])
        return hashlib.sha1(fingerprint.encode()).hexdigest()

    def _build_reflection_prompt(self, query: str, pattern: VulnerabilityPattern) -> str:
        return f"""
You will label a single vulnerability pattern.

SCHEMA:
{{
  "prompt_version": "{self.prompt_version}",
  "judgments": [
    {{
      "pattern_id": "{pattern.id}",
      "relevance": "Relevant|Irrelevant",
      "quality": "HighQuality|LowQuality",
      "confidence": float (0-1),
      "reason": "one short sentence"
    }}
  ]
}}

QUERY: {query}

PATTERN:
Name: {pattern.name}
Type: {pattern.vuln_type}
Description: {pattern.description}
Confidence: {pattern.confidence:.2f}
Successful exploits: {pattern.successful_exploits}
Failed attempts: {pattern.failed_attempts}

ONLY RETURN JSON THAT MATCHES THE SCHEMA.
""".strip()

    def _select_fallback_patterns(
        self,
        query: str,
        exclude_ids: Set[str],
        needed: int
    ) -> List[VulnerabilityPattern]:
        if needed <= 0:
            return []
        candidates = self._retrieve_by_text_query(query, k=max(self.min_relevant * 2, needed * 2))
        extras: List[VulnerabilityPattern] = []
        for pattern in candidates:
            if pattern.id in exclude_ids:
                continue
            extras.append(pattern)
            exclude_ids.add(pattern.id)
            self._log_event(pattern.id, query, source="fallback", success=True)
            if len(extras) >= needed:
                break
        return extras

    def _log_event(self, pattern_id: str, query: str, source: str, success: bool) -> None:
        try:
            with self.telemetry_path.open("a", encoding="utf-8") as f:
                f.write(
                    f'{{"pattern_id":"{pattern_id}","query":"{query}","source":"{source}",'
                    f'"success":{str(success).lower()}}}\n'
                )
        except (IOError, OSError) as exc:
            # Telemetry logging is best-effort - don't fail if we can't write
            logger.debug(f"[SelfRAG] Failed to log telemetry event: {exc}")

    def _log_summary(
        self,
        query: str,
        total_candidates: int,
        total_relevant: int,
        precision: float,
        fallback_used: bool
    ) -> None:
        payload = {
            "type": "summary",
            "query": query,
            "total_candidates": total_candidates,
            "total_relevant": total_relevant,
            "precision": precision,
            "fallback_used": fallback_used,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        try:
            with self.telemetry_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
        except (IOError, OSError) as exc:
            # Summary logging is best-effort - don't fail if we can't write
            logger.debug(f"[SelfRAG] Failed to log summary: {exc}")
