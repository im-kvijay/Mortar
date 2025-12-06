"""sniper pre-filter layer"""

import re
from typing import Dict, Any, Tuple, List, Optional
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from src.utils.metrics_logger import log_metric

_REGEX_SOLIDITY_VERSION = re.compile(r'pragma\s+solidity\s+[^0-9]*([0-9]+)\.([0-9]+)')

# Test pattern regexes (compiled dynamically from list in _detect_test_contract)
_TEST_PATTERN_REGEXES = [
    re.compile(r'function\s+test\w+\s*\('),  # testFunctionName()
    re.compile(r'function\s+setUp\s*\('),     # setUp()
    re.compile(r'assertEq\('),                 # Foundry assertions
    re.compile(r'expect\('),                   # Hardhat assertions
]

class FilterDecision(Enum):
    """Decision from Sniper filter"""
    SKIP = "skip"
    ANALYZE = "analyze"
    PRIORITY = "priority"

@dataclass
class SniperScore:
    """sniper filter score"""
    score: float
    decision: FilterDecision
    reasoning: str
    factors: Dict[str, float]
    bypass_filters: List[str]

class SniperFilter:
    """pre-filter contracts to avoid expensive analysis on low-value targets"""

    def __init__(
        self,
        skip_threshold: float = 0.3,
        priority_threshold: float = 0.7,
        min_value_usd: float = 100000,
        enable_value_check: bool = False
    ):
        """initialize sniper filter"""
        self.skip_threshold = skip_threshold
        self.priority_threshold = priority_threshold
        self.min_value_usd = min_value_usd
        self.enable_value_check = enable_value_check

        # Known-safe patterns (standard implementations, unmodified)
        self.safe_patterns = [
            "OpenZeppelin/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol",
            "OpenZeppelin/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol",
            "OpenZeppelin/openzeppelin-contracts/contracts/token/ERC1155/ERC1155.sol",
        ]

        # Test/mock indicators
        self.test_indicators = [
            "test", "mock", "fake", "example", "sample", "demo", "dummy"
        ]

        self.high_value_functions = [
            "flashLoan", "borrow", "liquidate", "swap", "withdraw",
            "deposit", "mint", "burn", "transfer", "approve",
            "execute", "call", "delegatecall", "selfdestruct"
        ]

        self.defi_indicators = [
            "pool", "vault", "lending", "borrowing", "liquidity",
            "oracle", "price", "collateral", "debt", "interest"
        ]

    def score_contract(
        self,
        contract_source: str,
        contract_info: Dict[str, Any],
        contract_path: Optional[Path] = None
    ) -> SniperScore:
        """score contract to determine if it needs analysis"""
        factors = {}
        bypass_filters = []

        is_test, test_confidence = self._detect_test_contract(contract_source, contract_info, contract_path)
        if is_test:
            factors["test_detection"] = 0.0
            bypass_filters.append("test_contract")
        else:
            factors["test_detection"] = 1.0 - test_confidence

        is_safe, safe_confidence = self._detect_safe_pattern(contract_source, contract_path)
        if is_safe:
            factors["safe_pattern"] = 0.0
            bypass_filters.append("known_safe_pattern")
        else:
            factors["safe_pattern"] = 1.0 - safe_confidence

        complexity = self._calculate_complexity(contract_source, contract_info)
        factors["complexity"] = complexity
        if complexity < 0.2:
            bypass_filters.append("too_simple")

        has_critical = self._detect_critical_functions(contract_source, contract_info)
        factors["critical_functions"] = has_critical

        is_defi = self._detect_defi_protocol(contract_source, contract_info)
        factors["defi_protocol"] = is_defi

        version_score = self._score_solidity_version(contract_source)
        factors["solidity_version"] = version_score

        has_external = self._detect_external_dependencies(contract_source, contract_info)
        factors["external_deps"] = has_external

        weights = {
            "test_detection": 0.25,  # Highest weight (skip tests immediately)
            "safe_pattern": 0.20,  # Second highest (skip known-safe)
            "complexity": 0.15,
            "critical_functions": 0.15,
            "defi_protocol": 0.10,
            "solidity_version": 0.05,
            "external_deps": 0.10
        }

        score = sum(factors[k] * weights[k] for k in weights.keys())

        if score < self.skip_threshold:
            decision = FilterDecision.SKIP
            reasoning = self._build_skip_reasoning(factors, bypass_filters)
        elif score >= self.priority_threshold:
            decision = FilterDecision.PRIORITY
            reasoning = self._build_priority_reasoning(factors)
        else:
            decision = FilterDecision.ANALYZE
            reasoning = f"Uncertain (score={score:.2f}), running full analysis"

        result = SniperScore(
            score=score,
            decision=decision,
            reasoning=reasoning,
            factors=factors,
            bypass_filters=bypass_filters
        )
        self._log_metrics(result, contract_info)
        return result

    def _log_metrics(self, result: SniperScore, contract_info: Dict[str, Any]) -> None:
        try:
            total_functions = contract_info.get("total_functions") or len(contract_info.get("functions", []))
            log_metric(
                component="sniper",
                event="score",
                payload={
                    "score": round(result.score, 4),
                    "decision": result.decision.value,
                    "total_functions": total_functions,
                    "factors": result.factors,
                    "bypass_filters": result.bypass_filters,
                },
            )
        except Exception:
            pass

    def _detect_test_contract(
        self,
        source: str,
        info: Dict[str, Any],
        path: Optional[Path]
    ) -> Tuple[bool, float]:
        """detect if contract is a test/mock"""
        confidence = 0.0

        if path:
            path_str = str(path).lower()
            if any(indicator in path_str for indicator in ["test", "mock", "t.sol"]):
                confidence = max(confidence, 0.9)

        name = info.get("name", "").lower()
        if any(indicator in name for indicator in self.test_indicators):
            confidence = max(confidence, 0.8)

        if "import \"forge-std/Test.sol\"" in source or "is Test" in source:
            confidence = max(confidence, 0.95)

        if "import \"@nomiclabs/hardhat" in source:
            confidence = max(confidence, 0.85)

        for pattern_regex in _TEST_PATTERN_REGEXES:
            if pattern_regex.search(source):
                confidence = max(confidence, 0.7)
                break

        return confidence > 0.5, confidence

    def _detect_safe_pattern(
        self,
        source: str,
        path: Optional[Path]
    ) -> Tuple[bool, float]:
        """detect if contract matches known-safe patterns"""
        confidence = 0.0

        if path:
            path_str = str(path)
            for safe_path in self.safe_patterns:
                if safe_path in path_str:

                    if "// SPDX-License-Identifier: MIT" in source and "OpenZeppelin" in source:
                        confidence = 0.95
                        break

        if "interface IERC20" in source and source.count("function") < 10:
            confidence = max(confidence, 0.6)

        return confidence > 0.7, confidence

    def _calculate_complexity(
        self,
        source: str,
        info: Dict[str, Any]
    ) -> float:
        """calculate contract complexity score"""
        score = 0.0

        # Factor: Number of functions
        func_count = len(info.get("functions", []))
        if func_count >= 20:
            score += 0.3
        elif func_count >= 10:
            score += 0.2
        elif func_count >= 5:
            score += 0.1

        # Factor: Lines of code
        lines = source.count('\n')
        if lines >= 500:
            score += 0.3
        elif lines >= 200:
            score += 0.2
        elif lines >= 100:
            score += 0.1

        # Factor: State variables
        state_var_count = source.count('private ') + source.count('public ') + source.count('internal ')
        if state_var_count >= 15:
            score += 0.2
        elif state_var_count >= 8:
            score += 0.1

        # Factor: Modifiers (usually indicate access control complexity)
        modifier_count = source.count('modifier ')
        if modifier_count >= 5:
            score += 0.2
        elif modifier_count >= 2:
            score += 0.1

        return min(score, 1.0)

    def _detect_critical_functions(
        self,
        source: str,
        info: Dict[str, Any]
    ) -> float:
        """detect presence of high-value functions"""
        functions = [f.get("name", "").lower() for f in info.get("functions", [])]

        critical_present = sum(
            1 for hv_func in self.high_value_functions
            if any(hv_func.lower() in func for func in functions)
        )

        if critical_present == 0:
            return 0.0

        return min(critical_present / 3.0, 1.0)

    def _detect_defi_protocol(
        self,
        source: str,
        info: Dict[str, Any]
    ) -> float:
        """detect if contract is likely a defi protocol"""
        score = 0.0
        source_lower = source.lower()

        defi_count = sum(
            1 for indicator in self.defi_indicators
            if indicator in source_lower
        )

        if defi_count >= 5:
            score = 1.0
        elif defi_count >= 3:
            score = 0.7
        elif defi_count >= 1:
            score = 0.4

        return score

    def _score_solidity_version(self, source: str) -> float:
        """score solidity version (older = lower score)"""

        match = _REGEX_SOLIDITY_VERSION.search(source)

        if not match:
            return 0.5  # Unknown version

        major = int(match.group(1))
        minor = int(match.group(2))

        # Score based on version
        if major == 0:
            if minor >= 8:
                return 1.0  # Modern (0.8.x)
            elif minor >= 7:
                return 0.8  # Recent (0.7.x)
            elif minor >= 6:
                return 0.6  # Acceptable (0.6.x)
            else:
                return 0.2  # Deprecated (<0.6.0)

        return 0.5  # Unknown major version

    def _detect_external_dependencies(
        self,
        source: str,
        info: Dict[str, Any]
    ) -> float:
        """detect external dependencies (oracles, external calls)"""
        score = 0.0

        # Oracle patterns
        oracle_patterns = [
            "Chainlink", "oracle", "getPrice", "latestAnswer",
            "IPriceFeed", "IOracle"
        ]

        if any(pattern in source for pattern in oracle_patterns):
            score += 0.5

        # External calls
        if ".call(" in source or "delegatecall" in source:
            score += 0.3

        interface_count = source.count("interface I")
        if interface_count >= 5:
            score += 0.2

        return min(score, 1.0)

    def _build_skip_reasoning(
        self,
        factors: Dict[str, float],
        bypass_filters: List[str]
    ) -> str:
        """Build reasoning for SKIP decision"""
        reasons = []

        if "test_contract" in bypass_filters:
            reasons.append("Test/mock contract detected")

        if "known_safe_pattern" in bypass_filters:
            reasons.append("Known-safe pattern (unmodified OZ)")

        if "too_simple" in bypass_filters:
            reasons.append(f"Too simple (complexity={factors['complexity']:.2f})")

        if factors.get("critical_functions", 0) < 0.2:
            reasons.append("No critical functions detected")

        if not reasons:
            reasons.append("Low overall score (multiple weak signals)")

        return "SKIP: " + "; ".join(reasons)

    def _build_priority_reasoning(self, factors: Dict[str, float]) -> str:
        """Build reasoning for PRIORITY decision"""
        reasons = []

        if factors.get("defi_protocol", 0) >= 0.7:
            reasons.append("DeFi protocol detected")

        if factors.get("critical_functions", 0) >= 0.7:
            reasons.append("Multiple critical functions")

        if factors.get("external_deps", 0) >= 0.5:
            reasons.append("External dependencies (oracle/calls)")

        if factors.get("complexity", 0) >= 0.7:
            reasons.append("High complexity")

        if not reasons:
            reasons.append("High overall score (strong signals)")

        return "PRIORITY: " + "; ".join(reasons)

    def get_stats(self) -> Dict[str, Any]:
        """Get filter statistics (for tracking efficiency)"""
        return {
            "skip_threshold": self.skip_threshold,
            "priority_threshold": self.priority_threshold,
            "enabled": True
        }
