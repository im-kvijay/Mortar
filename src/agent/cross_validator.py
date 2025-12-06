"""module docstring"""

from typing import List, Dict, Any, Optional, Tuple, TYPE_CHECKING
from dataclasses import dataclass
from enum import Enum

from utils.logging import ResearchLogger
from kb.knowledge_base import KnowledgeBase

# deferred import to avoid circular dependency
if TYPE_CHECKING:
    from kb.learning_manager import KBLearningManager


class ContradictionType(Enum):
    """Types of contradictions"""
    VERIFICATION_IMPACT = "verification_impact"           # Verified but no impact
    IMPACT_SEVERITY = "impact_severity"                   # Impact doesn't match severity
    VERIFICATION_CHAIN = "verification_chain"             # Verification disagrees with chain validation
    CONFIDENCE_POC = "confidence_poc"                     # Confidence doesn't match PoC result
    RESOLUTION_IMPACT = "resolution_impact"               # Fix complexity doesn't match impact
    ECONOMIC_INFEASIBLE = "economic_infeasible"          # Attack costs more than profit
    CRITICAL_BUT_TRIVIAL_FIX = "critical_but_trivial_fix" # Critical vuln but trivial fix (suspicious)


@dataclass
class Contradiction:
    """
    Detected contradiction between layers

    Attributes:
        type: Type of contradiction
        severity: How bad is this (critical/high/medium/low)
        layer1: First layer involved
        layer2: Second layer involved
        description: What's contradictory
        evidence: Supporting evidence
        recommendation: What to do about it
    """
    type: ContradictionType
    severity: str
    layer1: str
    layer2: str
    description: str
    evidence: Dict[str, Any]
    recommendation: str


@dataclass
class CrossValidationResult:
    """
    Result of cross-validation

    Attributes:
        passed: True if no critical contradictions
        contradictions: List of contradictions found
        confidence: Confidence in overall result (0.0-1.0)
        should_proceed: Whether to proceed with next step
        warnings: Non-critical issues
    """
    passed: bool
    contradictions: List[Contradiction]
    confidence: float
    should_proceed: bool
    warnings: List[str]


class CrossValidator:
    """
    Cross-validates outputs between different layers

    Catches contradictions that indicate false positives or errors.
    """

    def __init__(
        self,
        logger: ResearchLogger,
        kb: Optional[KnowledgeBase] = None
    ):
        self.logger = logger

        # initialize learning manager if kb provided
        self.learning_mgr = None
        if kb:
            from kb.learning_manager import KBLearningManager  # Deferred import
            self.learning_mgr = KBLearningManager(kb, logger)
            self.logger.info("[CrossValidator] Automatic KB learning enabled")

    def check_verification_chain_consistency(
        self,
        verification_result: Any,  # VerificationResult
        chain_result: Any,  # ValidationResult from ExploitChainValidator
        hypothesis_id: Optional[str] = None,
        contract_name: Optional[str] = None
    ) -> CrossValidationResult:
        """
        Check consistency between verification and chain validation

        Args:
            verification_result: Result from VerificationLayer
            chain_result: Result from ExploitChainValidator
            hypothesis_id: Optional hypothesis ID

        Returns:
            CrossValidationResult with contradictions
        """
        contradictions = []
        warnings = []

        # check 1: both agree on validity?
        if verification_result.verified and not chain_result.valid:
            contradictions.append(Contradiction(
                type=ContradictionType.VERIFICATION_CHAIN,
                severity="critical",  # Changed from "high" - this is a critical issue
                layer1="VerificationLayer",
                layer2="ChainValidator",
                description="Verification passed but chain validation failed",
                evidence={
                    'verification_confidence': verification_result.confidence,
                    'chain_violations': chain_result.violations
                },
                recommendation="Reject hypothesis - chain is not executable"
            ))

        # check 2: confidence alignment
        if verification_result.verified and chain_result.valid:
            confidence_diff = abs(verification_result.confidence - chain_result.confidence)
            if confidence_diff > 0.3:
                warnings.append(
                    f"Large confidence gap: verification={verification_result.confidence:.2f}, "
                    f"chain={chain_result.confidence:.2f}"
                )

        # check 3: gas feasibility
        if chain_result.gas_estimate > 30_000_000:  # Block limit
            contradictions.append(Contradiction(
                type=ContradictionType.VERIFICATION_CHAIN,
                severity="critical",
                layer1="ChainValidator",
                layer2="VerificationLayer",
                description=f"Attack requires {chain_result.gas_estimate:,} gas (exceeds block limit)",
                evidence={'gas_estimate': chain_result.gas_estimate},
                recommendation="Reject hypothesis - gas infeasible"
            ))

        # determine if we should proceed
        critical_contradictions = [c for c in contradictions if c.severity == "critical"]
        should_proceed = len(critical_contradictions) == 0

        # calculate confidence
        if not should_proceed:
            confidence = 0.0
        elif contradictions:
            confidence = 0.5
        else:
            confidence = min(verification_result.confidence, chain_result.confidence)

        result = CrossValidationResult(
            passed=len(contradictions) == 0,
            contradictions=contradictions,
            confidence=confidence,
            should_proceed=should_proceed,
            warnings=warnings
        )

        # log
        if hypothesis_id:
            self.logger.log_cross_validation(
                hypothesis_id=hypothesis_id,
                validation_type="verification_chain",
                passed=result.passed,
                contradictions=[c.description for c in contradictions],
                should_proceed=should_proceed
            )

        self.logger.info(
            f"[CrossValidator] Verification-Chain check: passed={result.passed}, "
            f"contradictions={len(contradictions)}, should_proceed={should_proceed}"
        )

        # learn from contradictions (automatic kb learning)
        if self.learning_mgr and contradictions and contract_name:
            for contradiction in contradictions:
                self.learning_mgr.learn_from_contradiction(
                    contradiction_type=contradiction.type.value,
                    layers=(contradiction.layer1, contradiction.layer2),
                    description=contradiction.description,
                    contract_name=contract_name
                )
            self.logger.info(f"[CrossValidator] Logged {len(contradictions)} contradictions to KB")

        return result

    def check_impact_severity_consistency(
        self,
        impact_report: Any,  # ImpactReport
        verification_result: Any,  # VerificationResult
        hypothesis_id: Optional[str] = None,
        contract_name: Optional[str] = None
    ) -> CrossValidationResult:
        """
        Check consistency between impact and severity

        Args:
            impact_report: Result from ImpactAmplifier
            verification_result: Result from VerificationLayer
            hypothesis_id: Optional hypothesis ID

        Returns:
            CrossValidationResult with contradictions
        """
        contradictions = []
        warnings = []

        # check 1: economic impact matches severity?
        severity_impact_mapping = {
            'critical': (100_000, float('inf')),  # $100k+
            'high': (50_000, 100_000),            # $50k-$100k
            'medium': (10_000, 50_000),           # $10k-$50k
            'low': (1_000, 10_000),               # $1k-$10k
            'none': (0, 1_000)                    # <$1k
        }

        severity = impact_report.severity.value
        impact_usd = impact_report.economic_impact_usd
        expected_range = severity_impact_mapping.get(severity, (0, float('inf')))

        if not (expected_range[0] <= impact_usd <= expected_range[1]):
            contradictions.append(Contradiction(
                type=ContradictionType.IMPACT_SEVERITY,
                severity="high",
                layer1="ImpactAmplifier",
                layer2="ImpactAmplifier",
                description=f"Severity={severity} but impact=${impact_usd:,.0f} (out of range ${expected_range[0]:,.0f}-${expected_range[1]:,.0f})",
                evidence={
                    'severity': severity,
                    'economic_impact': impact_usd,
                    'expected_range': expected_range
                },
                recommendation="Review severity classification or impact calculation"
            ))

        # check 2: verified attack with $0 impact?
        if verification_result.verified and impact_usd < 100:
            contradictions.append(Contradiction(
                type=ContradictionType.VERIFICATION_IMPACT,
                severity="critical",
                layer1="VerificationLayer",
                layer2="ImpactAmplifier",
                description="Attack verified but has negligible economic impact ($0-$100)",
                evidence={
                    'verified': True,
                    'verification_confidence': verification_result.confidence,
                    'economic_impact': impact_usd
                },
                recommendation="Reject as false positive - no real economic impact"
            ))

        # check 3: negative roi (attack costs more than profit)?
        if impact_report.roi_percent < 0:
            contradictions.append(Contradiction(
                type=ContradictionType.ECONOMIC_INFEASIBLE,
                severity="high",
                layer1="ImpactAmplifier",
                layer2="ImpactAmplifier",
                description=f"Attack has negative ROI ({impact_report.roi_percent:.1f}%) - costs more than profit",
                evidence={
                    'economic_impact': impact_usd,
                    'attack_cost': impact_report.attack_cost_usd,
                    'roi': impact_report.roi_percent
                },
                recommendation="Reject - not economically viable for attacker"
            ))

        # check 4: very low roi for high severity?
        if severity in ['critical', 'high'] and impact_report.roi_percent < 100:
            warnings.append(
                f"High severity but low ROI ({impact_report.roi_percent:.0f}%) - "
                "may not be attractive to real attackers"
            )

        # determine if we should proceed
        critical_contradictions = [c for c in contradictions if c.severity == "critical"]
        should_proceed = len(critical_contradictions) == 0

        # calculate confidence
        if not should_proceed:
            confidence = 0.0
        elif contradictions:
            confidence = 0.6
        else:
            confidence = impact_report.confidence

        result = CrossValidationResult(
            passed=len(contradictions) == 0,
            contradictions=contradictions,
            confidence=confidence,
            should_proceed=should_proceed,
            warnings=warnings
        )

        # log
        if hypothesis_id:
            self.logger.log_cross_validation(
                hypothesis_id=hypothesis_id,
                validation_type="impact_severity",
                passed=result.passed,
                contradictions=[c.description for c in contradictions],
                should_proceed=should_proceed
            )

        self.logger.info(
            f"[CrossValidator] Impact-Severity check: passed={result.passed}, "
            f"contradictions={len(contradictions)}, should_proceed={should_proceed}"
        )

        # learn from contradictions (automatic kb learning)
        if self.learning_mgr and contradictions and contract_name:
            for contradiction in contradictions:
                self.learning_mgr.learn_from_contradiction(
                    contradiction_type=contradiction.type.value,
                    layers=(contradiction.layer1, contradiction.layer2),
                    description=contradiction.description,
                    contract_name=contract_name
                )
            self.logger.info(f"[CrossValidator] Logged {len(contradictions)} contradictions to KB")

        return result

    def check_resolution_impact_consistency(
        self,
        resolution_report: Any,  # ResolutionReport
        impact_report: Any,  # ImpactReport
        hypothesis_id: Optional[str] = None
    ) -> CrossValidationResult:
        """
        Check consistency between resolution and impact

        Args:
            resolution_report: Result from ResolutionLayer
            impact_report: Result from ImpactAmplifier
            hypothesis_id: Optional hypothesis ID

        Returns:
            CrossValidationResult with contradictions
        """
        contradictions = []
        warnings = []

        # check 1: critical vuln with trivial fix?
        severity = impact_report.severity.value
        fix_complexity = resolution_report.complexity_assessment.value

        if severity in ['critical', 'high'] and fix_complexity in ['trivial', 'simple']:
            contradictions.append(Contradiction(
                type=ContradictionType.CRITICAL_BUT_TRIVIAL_FIX,
                severity="medium",
                layer1="ImpactAmplifier",
                layer2="ResolutionLayer",
                description=f"Severity={severity} but fix is {fix_complexity} (suspicious - might be false positive)",
                evidence={
                    'severity': severity,
                    'fix_complexity': fix_complexity,
                    'recommended_fix': resolution_report.recommended_fix.strategy_name
                },
                recommendation="Double-check - critical vulns usually need complex fixes"
            ))

        # check 2: low impact with major fix?
        if severity in ['low', 'none'] and fix_complexity in ['complex', 'major']:
            warnings.append(
                f"Low impact ({severity}) but complex fix ({fix_complexity}) - "
                "high effort for low value"
            )

        # check 3: fix effectiveness vs impact
        fix_effectiveness = resolution_report.recommended_fix.effectiveness
        if fix_effectiveness < 0.8 and severity in ['critical', 'high']:
            warnings.append(
                f"High severity but fix only {fix_effectiveness:.0%} effective - "
                "may need better mitigation strategy"
            )

        # determine if we should proceed
        should_proceed = True  # Resolution issues are warnings, not blockers

        # calculate confidence
        if contradictions:
            confidence = 0.7
        else:
            confidence = min(impact_report.confidence, resolution_report.confidence)

        result = CrossValidationResult(
            passed=len(contradictions) == 0,
            contradictions=contradictions,
            confidence=confidence,
            should_proceed=should_proceed,
            warnings=warnings
        )

        # log
        if hypothesis_id:
            self.logger.log_cross_validation(
                hypothesis_id=hypothesis_id,
                validation_type="resolution_impact",
                passed=result.passed,
                contradictions=[c.description for c in contradictions],
                should_proceed=should_proceed
            )

        self.logger.info(
            f"[CrossValidator] Resolution-Impact check: passed={result.passed}, "
            f"contradictions={len(contradictions)}, warnings={len(warnings)}"
        )

        return result

    def generate_contradiction_report(
        self,
        contradictions: List[Contradiction]
    ) -> str:
        """Generate human-readable contradiction report"""
        if not contradictions:
            return "[OK] No contradictions detected"

        report = f"# Cross-Validation Report\n\n"
        report += f"**{len(contradictions)} contradiction(s) detected**\n\n"

        # group by severity
        critical = [c for c in contradictions if c.severity == "critical"]
        high = [c for c in contradictions if c.severity == "high"]
        medium = [c for c in contradictions if c.severity == "medium"]

        if critical:
            report += f"## 🔴 Critical ({len(critical)})\n\n"
            for c in critical:
                report += f"### {c.layer1} vs {c.layer2}\n"
                report += f"**Issue**: {c.description}\n\n"
                report += f"**Recommendation**: {c.recommendation}\n\n"

        if high:
            report += f"## 🟠 High ({len(high)})\n\n"
            for c in high:
                report += f"### {c.layer1} vs {c.layer2}\n"
                report += f"**Issue**: {c.description}\n\n"
                report += f"**Recommendation**: {c.recommendation}\n\n"

        if medium:
            report += f"## 🟡 Medium ({len(medium)})\n\n"
            for c in medium:
                report += f"### {c.layer1} vs {c.layer2}\n"
                report += f"**Issue**: {c.description}\n\n"
                report += f"**Recommendation**: {c.recommendation}\n\n"

        return report
