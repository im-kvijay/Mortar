"""pattern synthesis for exponential knowledge growth"""

import itertools
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, replace
import hashlib
from collections import defaultdict

from src.kb.knowledge_base import VulnerabilityPattern
from src.utils.llm_backend import create_backend


def call_llm(
    prompt,
    backend="grok",
    model=None,
    thinking_budget=4000,
    temperature=0.7,
    max_tokens=1000
):
    """call llm backend"""
    llm_backend = create_backend(backend_type=backend, model=model)
    response = llm_backend.generate(
        prompt=prompt,
        temperature=temperature,
        max_tokens=max_tokens
    )
    return response.content if hasattr(response, 'content') else str(response)


@dataclass
class SynthesisResult:
    """synthesis result"""
    synthesized: List[VulnerabilityPattern]
    duplicates_removed: int
    synthesis_cost: float
    level: int  # 1, 2, or 3


class PatternSynthesizer:
    """synthesize new patterns from existing ones"""

    def __init__(
        self,
        llm_backend: str = "grok",
        llm_model: Optional[str] = None,
        thinking_budget: int = 4000,
        dedup_threshold: float = 0.85
    ):
        """init synthesizer"""
        self.llm_backend = llm_backend
        self.llm_model = llm_model
        self.thinking_budget = thinking_budget
        self.dedup_threshold = dedup_threshold
        self.synthesis_cost = 0.0

    def synthesize_level_1(
        self,
        patterns: List[VulnerabilityPattern],
        max_combinations: Optional[int] = None
    ) -> SynthesisResult:
        """level 1: combine pairs"""
        print(f"[PatternSynthesizer] Starting Level 1 synthesis on {len(patterns)} patterns...")

        synthesized = []
        duplicates = 0
        seen_hashes = set()

        # Generate all pairs
        pairs = list(itertools.combinations(patterns, 2))
        if max_combinations:
            pairs = pairs[:max_combinations]

        print(f"[PatternSynthesizer] Processing {len(pairs)} pattern pairs...")

        for i, (p1, p2) in enumerate(pairs):
            if i % 50 == 0 and i > 0:
                print(f"[PatternSynthesizer] Processed {i}/{len(pairs)} pairs...")

            # Synthesize new pattern
            new_pattern = self._synthesize_pair(p1, p2)

            if new_pattern:
                # Check for duplicates
                pattern_hash = self._hash_pattern(new_pattern)
                if pattern_hash in seen_hashes:
                    duplicates += 1
                    continue

                seen_hashes.add(pattern_hash)
                synthesized.append(new_pattern)

        print(f"[PatternSynthesizer] Level 1 complete: {len(synthesized)} new patterns, {duplicates} duplicates removed")

        return SynthesisResult(
            synthesized=synthesized,
            duplicates_removed=duplicates,
            synthesis_cost=self.synthesis_cost,
            level=1
        )

    def synthesize_level_2(
        self,
        level1_patterns: List[VulnerabilityPattern],
        base_patterns: List[VulnerabilityPattern],
        max_combinations: Optional[int] = None
    ) -> SynthesisResult:
        """level 2: combine triples and mutate"""
        print(f"[PatternSynthesizer] Starting Level 2 synthesis...")
        print(f"  - Level 1 patterns: {len(level1_patterns)}")
        print(f"  - Base patterns: {len(base_patterns)}")

        synthesized = []
        duplicates = 0
        seen_hashes = set()

        # Strategy 1: Level 1 + Base = Triples
        triples = []
        for l1_pattern in level1_patterns[:100]:  # Limit to avoid explosion
            for base_pattern in base_patterns[:20]:
                triples.append((l1_pattern, base_pattern))

        if max_combinations:
            triples = triples[:max_combinations]

        print(f"[PatternSynthesizer] Synthesizing {len(triples)} triples...")

        for i, (l1, base) in enumerate(triples):
            if i % 20 == 0 and i > 0:
                print(f"[PatternSynthesizer] Processed {i}/{len(triples)} triples...")

            new_pattern = self._synthesize_pair(l1, base)

            if new_pattern:
                pattern_hash = self._hash_pattern(new_pattern)
                if pattern_hash in seen_hashes:
                    duplicates += 1
                    continue

                seen_hashes.add(pattern_hash)
                synthesized.append(new_pattern)

        # Strategy 2: Mutations (apply transformations)
        print(f"[PatternSynthesizer] Applying mutations to top patterns...")
        for pattern in level1_patterns[:50]:  # Mutate top 50
            mutated = self._mutate_pattern(pattern)
            if mutated:
                pattern_hash = self._hash_pattern(mutated)
                if pattern_hash not in seen_hashes:
                    seen_hashes.add(pattern_hash)
                    synthesized.append(mutated)
                else:
                    duplicates += 1

        print(f"[PatternSynthesizer] Level 2 complete: {len(synthesized)} new patterns, {duplicates} duplicates removed")

        return SynthesisResult(
            synthesized=synthesized,
            duplicates_removed=duplicates,
            synthesis_cost=self.synthesis_cost,
            level=2
        )

    def _synthesize_pair(
        self,
        p1: VulnerabilityPattern,
        p2: VulnerabilityPattern
    ) -> Optional[VulnerabilityPattern]:
        """synthesize pattern from two patterns"""
        # Build synthesis prompt
        prompt = f"""You are a smart contract security expert synthesizing vulnerability patterns.

PATTERN 1:
Name: {p1.name}
Type: {p1.vuln_type}
Description: {p1.description}
Preconditions: {', '.join(p1.preconditions) if p1.preconditions else 'None'}
Attack Steps: {'; '.join(p1.attack_steps[:3]) if p1.attack_steps else 'None'}

PATTERN 2:
Name: {p2.name}
Type: {p2.vuln_type}
Description: {p2.description}
Preconditions: {', '.join(p2.preconditions) if p2.preconditions else 'None'}
Attack Steps: {'; '.join(p2.attack_steps[:3]) if p2.attack_steps else 'None'}

TASK:
Synthesize a NEW vulnerability pattern that meaningfully combines these two patterns.
The combination should be:
1. Semantically valid (not just concatenation)
2. Represent a real attack scenario
3. more complex than either pattern alone

If these patterns cannot be meaningfully combined, respond with "INVALID".

OUTPUT FORMAT (JSON):
{{
    "name": "Combined pattern name",
    "vuln_type": "vulnerability type",
    "description": "Clear description of the combined vulnerability",
    "preconditions": ["precondition 1", "precondition 2"],
    "attack_steps": ["step 1", "step 2", "step 3"],
    "valid": true
}}

OUTPUT:"""

        try:
            response = call_llm(
                prompt=prompt,
                backend=self.llm_backend,
                model=self.llm_model,
                thinking_budget=self.thinking_budget,
                temperature=0.7,  # Slightly creative
                max_tokens=1000
            )

            # Track cost
            self.synthesis_cost += 0.01  # Approximate

            # Parse response
            import json
            # Extract JSON from response
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0].strip()
            else:
                json_str = response.strip()

            data = json.loads(json_str)

            if not data.get("valid", False):
                return None

            # Create new pattern
            new_pattern = VulnerabilityPattern(
                id=f"synth_{data['name'][:20].replace(' ', '_').lower()}",
                name=data["name"],
                vuln_type=data["vuln_type"],
                description=data["description"],
                preconditions=data.get("preconditions", []),
                attack_steps=data.get("attack_steps", []),
                indicators=p1.indicators + p2.indicators,  # Combine indicators
                confidence=self._combine_confidence(p1.confidence, p2.confidence),
                successful_exploits=0,
                failed_attempts=0,
                synthesized=True,
                source_patterns=[p1.id, p2.id],
                discovered_by="system_synthesis"
            )

            return new_pattern

        except Exception as e:
            print(f"[PatternSynthesizer] Synthesis failed: {e}")
            return None

    def _mutate_pattern(self, pattern: VulnerabilityPattern) -> Optional[VulnerabilityPattern]:
        """mutate pattern"""
        prompt = f"""You are mutating a vulnerability pattern to create a new variant.

ORIGINAL PATTERN:
Name: {pattern.name}
Type: {pattern.vuln_type}
Description: {pattern.description}
Preconditions: {', '.join(pattern.preconditions) if pattern.preconditions else 'None'}

TASK:
Create a VARIANT of this pattern by:
1. Generalizing (remove specific constraints) OR
2. Specializing (add specific constraints) OR
3. Changing the attack vector while keeping the core vulnerability

The variant should be semantically distinct but related.

OUTPUT FORMAT (JSON):
{{
    "name": "Variant pattern name",
    "vuln_type": "vulnerability type",
    "description": "Description of the variant",
    "preconditions": ["precondition 1", "precondition 2"],
    "attack_steps": ["step 1", "step 2"],
    "valid": true
}}

OUTPUT:"""

        try:
            response = call_llm(
                prompt=prompt,
                backend=self.llm_backend,
                thinking_budget=self.thinking_budget // 2,  # Half budget for mutations
                temperature=0.8,  # More creative
                max_tokens=800
            )

            self.synthesis_cost += 0.008

            # Parse
            import json
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0].strip()
            else:
                json_str = response.strip()

            data = json.loads(json_str)

            if not data.get("valid", False):
                return None

            # Create mutated pattern
            mutated = VulnerabilityPattern(
                id=f"mutant_{data['name'][:20].replace(' ', '_').lower()}",
                name=data["name"],
                vuln_type=data["vuln_type"],
                description=data["description"],
                preconditions=data.get("preconditions", []),
                attack_steps=data.get("attack_steps", []),
                indicators=pattern.indicators,
                confidence=pattern.confidence * 0.9,  # Slightly lower confidence
                successful_exploits=0,
                failed_attempts=0
            )

            return mutated

        except Exception as e:
            print(f"[PatternSynthesizer] Mutation failed: {e}")
            return None

    def _combine_confidence(self, conf1: float, conf2: float) -> float:
        """combine confidence scores"""
        # Geometric mean with penalty
        combined = (conf1 * conf2) ** 0.5
        penalty = 0.9  # Synthesized patterns are less certain
        return combined * penalty

    def _hash_pattern(self, pattern: VulnerabilityPattern) -> str:
        """hash pattern for dedup"""
        content = f"{pattern.name}|{pattern.vuln_type}|{pattern.description}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def deduplicate(
        self,
        patterns: List[VulnerabilityPattern]
    ) -> Tuple[List[VulnerabilityPattern], int]:
        """remove duplicates"""
        seen_hashes = set()
        unique = []
        duplicates = 0

        for pattern in patterns:
            pattern_hash = self._hash_pattern(pattern)
            if pattern_hash in seen_hashes:
                duplicates += 1
            else:
                seen_hashes.add(pattern_hash)
                unique.append(pattern)

        return unique, duplicates

    def batch_synthesize(
        self,
        patterns: List[VulnerabilityPattern],
        target_level: int = 1,
        max_patterns: Optional[int] = None
    ) -> List[VulnerabilityPattern]:
        """batch synthesis to target level"""
        all_synthesized = []

        # Level 1
        print(f"\n{'='*60}")
        print(f"STARTING LEVEL 1 SYNTHESIS")
        print(f"{'='*60}\n")

        level1_result = self.synthesize_level_1(patterns, max_combinations=max_patterns)
        all_synthesized.extend(level1_result.synthesized)

        print(f"\nLevel 1 Results:")
        print(f"  - Synthesized: {len(level1_result.synthesized)}")
        print(f"  - Duplicates removed: {level1_result.duplicates_removed}")
        print(f"  - Cost: ${level1_result.synthesis_cost:.2f}")

        if target_level >= 2 and level1_result.synthesized:
            print(f"\n{'='*60}")
            print(f"STARTING LEVEL 2 SYNTHESIS")
            print(f"{'='*60}\n")

            level2_result = self.synthesize_level_2(
                level1_result.synthesized,
                patterns,
                max_combinations=max_patterns
            )
            all_synthesized.extend(level2_result.synthesized)

            print(f"\nLevel 2 Results:")
            print(f"  - Synthesized: {len(level2_result.synthesized)}")
            print(f"  - Duplicates removed: {level2_result.duplicates_removed}")
            print(f"  - Cost: ${level2_result.synthesis_cost:.2f}")

        # Final deduplication
        final_patterns, final_dups = self.deduplicate(all_synthesized)

        print(f"\n{'='*60}")
        print(f"SYNTHESIS COMPLETE")
        print(f"{'='*60}")
        print(f"Total synthesized: {len(final_patterns)}")
        print(f"Total duplicates removed: {final_dups}")
        print(f"Total cost: ${self.synthesis_cost:.2f}")
        print(f"Growth factor: {len(final_patterns) / len(patterns):.1f}x")

        return final_patterns
