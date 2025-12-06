"""deduplication layer"""

import hashlib
import json
import re
from typing import Dict, Any, Tuple, List, Optional
from dataclasses import dataclass
from pathlib import Path

from config import config
from utils.metrics_logger import log_metric

_REGEX_SINGLE_LINE_COMMENT = re.compile(r'//.*?$', flags=re.MULTILINE)
_REGEX_MULTI_LINE_COMMENT = re.compile(r'/\*.*?\*/', flags=re.DOTALL)
_REGEX_WHITESPACE = re.compile(r'\s+')
_REGEX_STRING_LITERALS = re.compile(r'"[^"]*"')
_REGEX_WORD_TOKENS = re.compile(r'\w+')
_REGEX_FUNCTION_SIGNATURE = re.compile(r'function\s+(\w+)\s*\(')

@dataclass
class DuplicateMatch:
    """result of duplicate detection"""
    is_duplicate: bool
    original_contract: Optional[str]
    similarity: float
    match_type: str
    transfer_strategy: str

class DeduplicationLayer:
    """detect and handle duplicate contracts"""

    def __init__(
        self,
        kb: Any = None,
        bytecode_threshold: float = 1.0,
        ast_threshold: float = 0.95,
        source_threshold: float = 0.85,
        *,
        mode: Optional[str] = None,
        cache_dir: Optional[Path] = None,
    ):
        self.kb = kb
        self.bytecode_threshold = bytecode_threshold
        self.ast_threshold = ast_threshold
        self.source_threshold = source_threshold

        normalized_mode = (mode or getattr(config, "DEDUP_MODE", "exact")).lower()
        if normalized_mode not in {"off", "exact", "hints"}:
            normalized_mode = "exact"
        self.mode = normalized_mode

        self.contract_cache: Dict[str, str] = {}
        self.cache_dir = Path(cache_dir) if cache_dir else config.CACHE_DIR / "dedup"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "index.json"
        self.source_hash_index: Dict[str, Dict[str, Any]] = self._load_source_index()

        if self.kb:
            self._build_cache_from_kb()

    def _load_source_index(self) -> Dict[str, Dict[str, Any]]:
        if not self.cache_file.exists():
            return {}
        try:
            return json.loads(self.cache_file.read_text())
        except Exception:
            return {}

    def _persist_source_index(self) -> None:
        try:
            self.cache_file.write_text(json.dumps(self.source_hash_index, indent=2))
        except Exception:
            pass

    def _no_match_result(
        self,
        contract_name: Optional[str],
        match_type: str = "no_match"
    ) -> DuplicateMatch:
        result = DuplicateMatch(
            is_duplicate=False,
            original_contract=None,
            similarity=0.0,
            match_type=match_type,
            transfer_strategy="full_analysis"
        )
        self._log_metrics(result, contract_name)
        return result

    def _build_cache_from_kb(self):
        if not hasattr(self.kb, 'contract_knowledge'):
            return

        for contract_name, knowledge in self.kb.contract_knowledge.items():
            # Store contract info for dedup checking
            contract_info = knowledge.get("contract_info", {})

            # We'll compute hashes when checking duplicates
            # For now, just store the name
            self.contract_cache[contract_name] = knowledge
            stored_source = knowledge.get("source")
            if stored_source:
                normalized = self._normalize_source(stored_source)
                source_hash = self._compute_source_hash(normalized)
                self.source_hash_index.setdefault(
                    source_hash,
                    {
                        "contract_name": contract_name,
                        "path": contract_info.get("path"),
                    },
                )

        if self.source_hash_index:
            self._persist_source_index()

    def check_duplicate(
        self,
        contract_source: str,
        contract_info: Dict[str, Any],
        contract_name: Optional[str] = None
    ) -> DuplicateMatch:
        """check if contract is a duplicate of previously analyzed contract"""
        if self.mode == "off":
            return self._no_match_result(contract_name, "disabled")

        normalized_source = self._normalize_source(contract_source)
        source_hash = self._compute_source_hash(normalized_source)

        hash_match = self.source_hash_index.get(source_hash)
        if hash_match:
            original_name = hash_match.get("contract_name")
            if not contract_name or original_name != contract_name:
                result = DuplicateMatch(
                    is_duplicate=True,
                    original_contract=original_name,
                    similarity=1.0,
                    match_type="source_hash",
                    transfer_strategy="copy_all"
                )
                self._log_metrics(result, contract_name)
                return result

        if self.mode == "exact":
            return self._no_match_result(contract_name, "hash_only_miss")

        bytecode_match = self._check_bytecode_match(contract_source, contract_info)
        if bytecode_match:
            result = DuplicateMatch(
                is_duplicate=True,
                original_contract=bytecode_match,
                similarity=1.0,
                match_type="bytecode_hash",
                transfer_strategy="copy_all"
            )
            self._log_metrics(result, contract_name)
            return result

        sig_match, sig_similarity = self._check_signature_match(contract_source, contract_info)
        if sig_match and sig_similarity >= self.ast_threshold:
            result = DuplicateMatch(
                is_duplicate=True,
                original_contract=sig_match,
                similarity=sig_similarity,
                match_type="function_signatures",
                transfer_strategy="transfer_with_adjustment"
            )
            self._log_metrics(result, contract_name)
            return result

        source_match, source_similarity = self._check_source_similarity(contract_source, contract_info)
        if source_match and source_similarity >= self.source_threshold:
            result = DuplicateMatch(
                is_duplicate=True,
                original_contract=source_match,
                similarity=source_similarity,
                match_type="source_similarity",
                transfer_strategy="transfer_patterns_only"
            )
            self._log_metrics(result, contract_name)
            return result

        lib_match = self._check_library_pattern(contract_source, contract_info)
        if lib_match:
            result = DuplicateMatch(
                is_duplicate=True,
                original_contract=lib_match,
                similarity=0.90,
                match_type="library_pattern",
                transfer_strategy="transfer_patterns_only"
            )
            self._log_metrics(result, contract_name)
            return result

        # No match found
        return self._no_match_result(contract_name, "no_match")

    def _log_metrics(self, result: DuplicateMatch, contract_name: Optional[str]) -> None:
        try:
            log_metric(
                component="dedup",
                event="match",
                payload={
                    "contract": contract_name,
                    "duplicate": result.is_duplicate,
                    "original": result.original_contract,
                    "similarity": round(result.similarity, 4),
                    "match_type": result.match_type,
                    "strategy": result.transfer_strategy,
                },
            )
        except Exception:
            pass

    def _check_bytecode_match(
        self,
        source: str,
        info: Dict[str, Any]
    ) -> Optional[str]:
        """check for exact bytecode match."""
        return None

    def _check_signature_match(
        self,
        source: str,
        info: Dict[str, Any]
    ) -> Tuple[Optional[str], float]:
        """check for function signature similarity (clone detection)"""

        current_sigs = self._extract_function_signatures(source, info)

        if not current_sigs:
            return None, 0.0

        best_match = None
        best_similarity = 0.0

        if not self.kb or not hasattr(self.kb, 'contract_knowledge'):
            return None, 0.0

        for contract_name, knowledge in self.kb.contract_knowledge.items():
            # Get stored contract info
            stored_info = knowledge.get("contract_info", {})
            stored_sigs = set(
                f.get("name", "") for f in stored_info.get("functions", [])
                if f.get("name")
            )

            if not stored_sigs:
                continue

            intersection = len(current_sigs.intersection(stored_sigs))
            union = len(current_sigs.union(stored_sigs))

            if union == 0:
                continue

            similarity = intersection / union

            if similarity > best_similarity:
                best_similarity = similarity
                best_match = contract_name

        return best_match, best_similarity

    def _check_source_similarity(
        self,
        source: str,
        info: Dict[str, Any]
    ) -> Tuple[Optional[str], float]:
        """check normalized source code similarity"""
        # Normalize source (remove comments, whitespace, etc.)
        normalized_current = self._normalize_source(source)

        best_match = None
        best_similarity = 0.0

        if not self.kb or not hasattr(self.kb, 'contract_knowledge'):
            return None, 0.0

        for contract_name, knowledge in self.kb.contract_knowledge.items():
            stored_source = knowledge.get("source", "")
            if not stored_source:
                continue

            normalized_stored = self._normalize_source(stored_source)

            similarity = self._calculate_source_similarity(
                normalized_current,
                normalized_stored
            )

            if similarity > best_similarity:
                best_similarity = similarity
                best_match = contract_name

        return best_match, best_similarity

    def _check_library_pattern(
        self,
        source: str,
        info: Dict[str, Any]
    ) -> Optional[str]:
        """check for common library patterns (openzeppelin, etc.)"""

        oz_patterns = [
            "@openzeppelin/contracts/token/ERC20/ERC20.sol",
            "@openzeppelin/contracts/token/ERC721/ERC721.sol",
            "@openzeppelin/contracts/token/ERC1155/ERC1155.sol",
        ]

        for pattern in oz_patterns:
            if pattern in source:

                contract_name = info.get("name", "")

                # Look for similar OZ contracts in KB
                if not self.kb or not hasattr(self.kb, 'contract_knowledge'):
                    return None

                for stored_name, knowledge in self.kb.contract_knowledge.items():
                    stored_source = knowledge.get("source", "")

                    # If both import same OZ contract, likely similar
                    if pattern in stored_source:
                        return stored_name

        return None

    def transfer_findings(
        self,
        original_contract: str,
        target_contract: Dict[str, Any],
        match: DuplicateMatch
    ) -> Dict[str, Any]:
        """kb additive philosophy: transfer findings as seed hypotheses, not replacements."""
        if not self.kb or not hasattr(self.kb, 'contract_knowledge'):
            return {"seed_hypotheses": [], "pattern_hints": [], "quality_score": 0.0}

        original_knowledge = self.kb.contract_knowledge.get(original_contract)
        if not original_knowledge:
            return {"seed_hypotheses": [], "pattern_hints": [], "quality_score": 0.0}

        discoveries = original_knowledge.get("discoveries", [])
        target_name = target_contract.get("name", "unknown")

        # Generate seed hypotheses from discoveries
        seed_hypotheses = self._discoveries_to_seed_hypotheses(
            discoveries=discoveries,
            original_contract=original_contract,
            target_contract=target_name,
            match=match
        )

        pattern_hints = self._extract_pattern_hints(discoveries, match)

        result = {
            "seed_hypotheses": seed_hypotheses,
            "pattern_hints": pattern_hints,
            "original_contract": original_contract,
            "similarity": match.similarity,
            "match_type": match.match_type,
            "transfer_strategy": match.transfer_strategy,
            "note": f"KB ADDITIVE: {len(seed_hypotheses)} seed hypotheses from {original_contract} ({match.similarity:.0%} match)",
            "quality_score": 0.0,  # Always require full analysis
        }

        log_metric(
            component="dedup",
            event="transfer",
            payload={
                "original": original_contract,
                "target": target_name,
                "similarity": round(match.similarity, 4),
                "num_seeds": len(seed_hypotheses),
                "num_hints": len(pattern_hints),
            },
        )

        return result

    def _discoveries_to_seed_hypotheses(
        self,
        discoveries: List[Dict[str, Any]],
        original_contract: str,
        target_contract: str,
        match: DuplicateMatch
    ) -> List[Dict[str, Any]]:
        """kb additive philosophy: convert discoveries to seed hypotheses."""
        seeds = []

        # Confidence reduction based on similarity
        # Even identical contracts get reduced confidence to ensure verification
        confidence_map = {
            "copy_all": 0.7,  # Identical: high confidence but still verify
            "transfer_with_adjustment": 0.6,  # Very similar: moderate confidence
            "transfer_patterns_only": 0.5,  # Similar: lower confidence
            "full_analysis": 0.4,  # Different: pattern hint only
        }
        base_confidence = confidence_map.get(match.transfer_strategy, 0.5)

        for idx, discovery in enumerate(discoveries):
            historical_confidence = discovery.get("confidence", 0.85)
            discovery_desc = (
                discovery.get("description")
                or discovery.get("content")
                or str(discovery)
            )
            discovery_type = discovery.get("type") or discovery.get("category") or "logic"
            target_func = discovery.get("target_function") or discovery.get("function") or "unknown"

            evidence = discovery.get("evidence", [])
            if isinstance(evidence, str):
                evidence = [evidence]
            evidence = list(evidence) + [
                f"[DEDUP SEED] Historical confidence: {historical_confidence:.2f}",
                f"[DEDUP SEED] Source: {original_contract}",
                f"[DEDUP SEED] Similarity: {match.similarity:.0%} ({match.match_type})",
            ]

            seeds.append({
                "hypothesis_id": f"dedup_seed_{original_contract}_{target_contract}_{idx}",
                "attack_type": str(discovery_type),
                "description": discovery_desc,
                "target_function": target_func,
                "preconditions": discovery.get("preconditions", []),
                "steps": discovery.get("steps", []),
                "expected_impact": discovery.get("impact", discovery_desc),
                "confidence": base_confidence,
                "requires_research": [],
                "evidence": evidence,
                "from_kb": True,
                "requires_verification": True,
                "_dedup_source": original_contract,
                "_dedup_similarity": match.similarity,
            })

        return seeds

    def _extract_pattern_hints(
        self,
        discoveries: List[Dict[str, Any]],
        match: DuplicateMatch
    ) -> List[Dict[str, Any]]:
        """extract pattern hints for moa specialists."""
        hints = []
        seen_patterns = set()

        for discovery in discoveries:
            pattern_type = discovery.get("type") or discovery.get("category")
            if not pattern_type or pattern_type in seen_patterns:
                continue
            seen_patterns.add(pattern_type)

            hints.append({
                "pattern_type": pattern_type,
                "hint_confidence": match.similarity * 0.8,  # Reduce for transfer
                "description": f"Similar contract had {pattern_type} vulnerability",
                "focus_functions": [
                    f.get("name") for f in discovery.get("functions", [])
                    if f.get("name")
                ] or [discovery.get("target_function")],
                "preconditions_hint": discovery.get("preconditions", []),
            })

        return hints

    def get_seed_hypotheses_for_contract(
        self,
        contract_source: str,
        contract_info: Dict[str, Any],
        contract_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """kb additive philosophy: one-stop method to get seed hypotheses from dedup."""
        match = self.check_duplicate(contract_source, contract_info, contract_name)

        if not match.is_duplicate or not match.original_contract:
            return []

        transfer_result = self.transfer_findings(
            original_contract=match.original_contract,
            target_contract=contract_info,
            match=match
        )

        return transfer_result.get("seed_hypotheses", [])

    def register_contract(
        self,
        contract_name: str,
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> None:
        """
        Register newly audited contract so future runs can deduplicate quickly.
        """
        normalized = self._normalize_source(contract_source)
        source_hash = self._compute_source_hash(normalized)
        self.source_hash_index[source_hash] = {
            "contract_name": contract_name,
            "path": contract_info.get("path"),
            "byte_length": len(contract_source),
        }
        self._persist_source_index()

    def _compute_source_hash(self, source: str) -> str:
        """Compute hash of source code"""
        return hashlib.sha256(source.encode('utf-8')).hexdigest()

    def _extract_function_signatures(
        self,
        source: str,
        info: Dict[str, Any]
    ) -> set:
        """Extract function signatures from contract"""
        # Get from info if available
        functions = info.get("functions", [])
        if functions:
            return set(f.get("name", "") for f in functions if f.get("name"))

        matches = _REGEX_FUNCTION_SIGNATURE.findall(source)
        return set(matches)

    def _normalize_source(self, source: str) -> str:
        """normalize source code for comparison"""
        source = _REGEX_SINGLE_LINE_COMMENT.sub('', source)

        source = _REGEX_MULTI_LINE_COMMENT.sub('', source)

        source = _REGEX_WHITESPACE.sub(' ', source)

        source = _REGEX_STRING_LITERALS.sub('""', source)

        return source.strip()

    def _calculate_source_similarity(
        self,
        source1: str,
        source2: str
    ) -> float:
        """calculate similarity between normalized sources"""
        tokens1 = set(_REGEX_WORD_TOKENS.findall(source1))
        tokens2 = set(_REGEX_WORD_TOKENS.findall(source2))

        if not tokens1 or not tokens2:
            return 0.0

        # Jaccard similarity
        intersection = len(tokens1.intersection(tokens2))
        union = len(tokens1.union(tokens2))

        if union == 0:
            return 0.0

        return intersection / union

    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics"""
        return {
            "cached_contracts": len(self.contract_cache),
            "bytecode_threshold": self.bytecode_threshold,
            "ast_threshold": self.ast_threshold,
            "source_threshold": self.source_threshold,
            "enabled": True
        }
