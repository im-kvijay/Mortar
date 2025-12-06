"""module docstring"""

from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum

from config import config
from utils.llm_backend.base import LLMBackend, LLMResponse
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager
from agent.base_attacker import AttackHypothesis
from agent.impact_amplifier import ImpactReport


class FixComplexity(Enum):
    """Complexity of implementing fix"""
    TRIVIAL = "trivial"        # One-line change
    SIMPLE = "simple"          # Simple modifier/check
    MODERATE = "moderate"      # Logic refactoring
    COMPLEX = "complex"        # Significant redesign
    MAJOR = "major"            # Protocol redesign


@dataclass
class MitigationStrategy:
    """
    Single mitigation strategy

    Attributes:
        strategy_name: Short name
        description: What this strategy does
        code_changes: Solidity code showing changes
        effectiveness: How well this fixes the issue (0.0-1.0)
        complexity: Implementation complexity
        risks: Potential risks of this mitigation
        gas_impact: Estimated gas increase
    """
    strategy_name: str
    description: str
    code_changes: str
    effectiveness: float
    complexity: FixComplexity
    risks: List[str]
    gas_impact: str


@dataclass
class ResolutionReport:
    """
    Complete resolution guidance for vulnerability

    Attributes:
        hypothesis: Original attack hypothesis
        impact_report: Impact assessment
        recommended_fix: Primary recommended fix
        alternative_fixes: Alternative mitigation strategies
        test_cases: Test cases to verify fix
        complexity_assessment: Overall fix complexity
        implementation_notes: Important notes for developers
        confidence: Confidence in fix recommendations
    """
    hypothesis: AttackHypothesis
    impact_report: ImpactReport
    recommended_fix: MitigationStrategy
    alternative_fixes: List[MitigationStrategy]
    test_cases: str
    complexity_assessment: FixComplexity
    implementation_notes: List[str]
    confidence: float

    @property
    def fix_complexity(self) -> FixComplexity:
        return self.complexity_assessment


class ResolutionLayer:
    """
    Resolution layer for fix recommendations
    """

    def __init__(
        self,
        backend: LLMBackend,
        logger: ResearchLogger,
        cost_manager: CostManager
    ):
        self.backend = backend
        self.logger = logger
        self.cost_manager = cost_manager

    def generate_resolution(
        self,
        hypothesis: AttackHypothesis,
        impact_report: ImpactReport,
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> ResolutionReport:
        """
        Generate fix recommendations for validated vulnerability

        Args:
            hypothesis: Original attack hypothesis
            impact_report: Impact assessment
            contract_source: Contract source code
            contract_info: Contract metadata

        Returns:
            ResolutionReport with fix recommendations
        """
        self.logger.info(f"[ResolutionLayer] Generating fix for {hypothesis.attack_type}")

        # build resolution prompt
        prompt = self._build_resolution_prompt(
            hypothesis=hypothesis,
            impact_report=impact_report,
            contract_source=contract_source,
            contract_info=contract_info
        )

        # call backend with extended thinking
        from config import config as _cfg
        thinking_type = _cfg.get_thinking_type(getattr(self.backend, "model", _cfg.DEFAULT_MODEL))
        gen_kwargs = dict(
            prompt=prompt,
            max_tokens=config.MAX_OUTPUT_TOKENS,
            temperature=config.EXTENDED_THINKING_TEMPERATURE,
        )
        if thinking_type == "extended":
            gen_kwargs["thinking_budget"] = config.EXTENDED_THINKING_BUDGET
        response: LLMResponse = self.backend.generate(**gen_kwargs)

        # track cost via unified api
        try:
            self.cost_manager.log_cost(
                agent_name="ResolutionLayer",
                contract_name=contract_info.get("name", "Unknown"),
                round_num=0,
                operation="resolution_generate",
                cost=getattr(response, "cost", 0.0),
                metadata={
                    "model": getattr(response, "model", "unknown"),
                    "prompt_tokens": getattr(response, "prompt_tokens", 0),
                    "output_tokens": getattr(response, "output_tokens", 0),
                    "thinking_tokens": getattr(response, "thinking_tokens", 0),
                }
            )
        except Exception:
            pass

        # parse response
        report = self._parse_resolution_response(
            response.text,
            hypothesis,
            impact_report
        )

        # log resolution
        self.logger.log_resolution(
            hypothesis_id=hypothesis.hypothesis_id,
            recommended_fix=report.recommended_fix.strategy_name,
            complexity=report.complexity_assessment.value,
            alternatives=len(report.alternative_fixes)
        )

        return report

    # backwards compatibility wrapper
    def generate_fix(
        self,
        hypothesis: AttackHypothesis,
        impact_report: ImpactReport,
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> ResolutionReport:
        return self.generate_resolution(
            hypothesis=hypothesis,
            impact_report=impact_report,
            contract_source=contract_source,
            contract_info=contract_info
        )

    def _build_resolution_prompt(
        self,
        hypothesis: AttackHypothesis,
        impact_report: ImpactReport,
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> str:
        """
        Build Extended Thinking prompt for resolution
        """
        attack_type = hypothesis.attack_type
        target_fn = hypothesis.target_function
        seq_lines = "\n".join(f"{i+1}. {s}" for i, s in enumerate(hypothesis.steps or [])) or "(no sequence provided)"
        root_cause = (hypothesis.evidence[0] if hypothesis.evidence else "")

        prompt = f"""You are a smart contract security architect. A vulnerability has been validated. Your job is to provide ACTIONABLE FIX RECOMMENDATIONS for developers.

CONTRACT INFORMATION:
Name: {contract_info.get('name', 'Unknown')}
Target Function: {target_fn}

VALIDATED VULNERABILITY:
Type: {attack_type}
Severity: {impact_report.severity.value.upper()}
Description: {hypothesis.description}
Root Cause (if known): {root_cause}

Attack Sequence:
{seq_lines}

IMPACT:
- Economic Impact: ${impact_report.economic_impact_usd:,.2f}
- Attack Cost: ${impact_report.attack_cost_usd:,.2f}
- ROI: {impact_report.roi_percent:.1f}%
- Cascading Effects: {len(impact_report.cascading_effects)}

FIX RECOMMENDATION FRAMEWORK:

1. PRIMARY FIX
   - What's the BEST way to fix this?
   - Provide exact code changes (diff format)
   - Explain why this fix works
   - Assess effectiveness (0.0-1.0)

2. ALTERNATIVE FIXES (2-3)
   - Other ways to mitigate (if primary is complex)
   - Trade-offs vs primary fix
   - When to use each alternative

3. FIX COMPLEXITY
   - trivial: One-line change (add require, modifier)
   - simple: Simple logic change
   - moderate: Function refactoring
   - complex: Significant redesign
   - major: Protocol-level changes

4. IMPLEMENTATION RISKS
   - Could this fix introduce new bugs?
   - Are there edge cases to watch?
   - Gas impact concerns?

5. TEST CASES
   - Foundry test to verify fix works
   - Should fail before fix, pass after fix

COMMON FIX PATTERNS:

Flash Loan Attacks:
- Add balance check before/after
- Implement reentrancy guard
- Add flash loan fee

Oracle Manipulation:
- Use TWAP instead of spot price
- Require multiple oracle sources
- Add sanity bounds

Reentrancy:
- Checks-Effects-Interactions pattern
- ReentrancyGuard modifier
- State updates before external calls

Access Control:
- Add onlyOwner/onlyRole modifiers
- Implement proper access control
- Validate msg.sender

Logic Bugs:
- Add invariant checks
- Validate preconditions
- Fix calculation errors

INSTRUCTIONS:
Provide clear, actionable fix recommendations.
Include code examples in Solidity.
Be realistic about complexity and risks.

Respond in this exact JSON format:
{{
    "recommended_fix": {{
        "strategy_name": "brief name",
        "description": "what this does",
        "code_changes": "solidity code showing fix",
        "effectiveness": 0.0-1.0,
        "complexity": "trivial"|"simple"|"moderate"|"complex"|"major",
        "risks": ["risk 1", "risk 2"],
        "gas_impact": "negligible|low|moderate|high"
    }},
    "alternative_fixes": [
        {{
            "strategy_name": "...",
            "description": "...",
            "code_changes": "...",
            "effectiveness": 0.0-1.0,
            "complexity": "...",
            "risks": [...],
            "gas_impact": "..."
        }}
    ],
    "test_cases": "foundry test code to verify fix",
    "complexity_assessment": "overall complexity",
    "implementation_notes": ["note 1", "note 2"],
    "confidence": 0.0-1.0
}}

CONTRACT SOURCE (for reference):
```solidity
{contract_source[:3000]}
```

FIX RECOMMENDATIONS:"""

        return prompt

    def _parse_resolution_response(
        self,
        response: str,
        hypothesis: AttackHypothesis,
        impact_report: ImpactReport
    ) -> ResolutionReport:
        """
        Parse resolution response into structured report
        """
        import json

        try:
            # extract json from response
            start = response.find('{')
            end = response.rfind('}') + 1
            json_str = response[start:end]
            data = json.loads(json_str)

            # parse recommended fix
            rec_data = data.get('recommended_fix', {})
            recommended_fix = MitigationStrategy(
                strategy_name=rec_data.get('strategy_name', 'Unknown'),
                description=rec_data.get('description', ''),
                code_changes=rec_data.get('code_changes', ''),
                effectiveness=float(rec_data.get('effectiveness', 0.0)),
                complexity=FixComplexity(rec_data.get('complexity', 'moderate')),
                risks=rec_data.get('risks', []),
                gas_impact=rec_data.get('gas_impact', 'unknown')
            )

            # parse alternative fixes
            alternative_fixes = []
            for alt_data in data.get('alternative_fixes', []):
                alt_fix = MitigationStrategy(
                    strategy_name=alt_data.get('strategy_name', 'Unknown'),
                    description=alt_data.get('description', ''),
                    code_changes=alt_data.get('code_changes', ''),
                    effectiveness=float(alt_data.get('effectiveness', 0.0)),
                    complexity=FixComplexity(alt_data.get('complexity', 'moderate')),
                    risks=alt_data.get('risks', []),
                    gas_impact=alt_data.get('gas_impact', 'unknown')
                )
                alternative_fixes.append(alt_fix)

            # parse complexity
            complexity_str = data.get('complexity_assessment', 'moderate')
            complexity = FixComplexity(complexity_str)

            return ResolutionReport(
                hypothesis=hypothesis,
                impact_report=impact_report,
                recommended_fix=recommended_fix,
                alternative_fixes=alternative_fixes,
                test_cases=data.get('test_cases', ''),
                complexity_assessment=complexity,
                implementation_notes=data.get('implementation_notes', []),
                confidence=float(data.get('confidence', 0.0))
            )

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            # parsing failed - return default report
            self.logger.warning(f"[ResolutionLayer] Failed to parse response: {e}")

            default_fix = MitigationStrategy(
                strategy_name="Manual Review Required",
                description="Failed to generate automated fix recommendation",
                code_changes="// Manual review required",
                effectiveness=0.0,
                complexity=FixComplexity.MAJOR,
                risks=["Unknown"],
                gas_impact="unknown"
            )

            return ResolutionReport(
                hypothesis=hypothesis,
                impact_report=impact_report,
                recommended_fix=default_fix,
                alternative_fixes=[],
                test_cases="// Test cases unavailable",
                complexity_assessment=FixComplexity.MAJOR,
                implementation_notes=["Automated resolution failed", "Manual review required"],
                confidence=0.0
            )

    def generate_pr_description(self, report: ResolutionReport) -> str:
        """
        Generate GitHub PR description for fix

        Returns:
            Markdown-formatted PR description
        """
        pr_md = f"""## Fix for {report.hypothesis.attack_type}

### vulnerability summary
{report.hypothesis.description}

**Severity**: {report.impact_report.severity.value.upper()}
**Economic Impact**: ${report.impact_report.economic_impact_usd:,.2f}

### root cause
{(report.hypothesis.evidence[0] if report.hypothesis.evidence else 'N/A')}

### recommended fix
**Strategy**: {report.recommended_fix.strategy_name}
**Effectiveness**: {report.recommended_fix.effectiveness * 100:.0f}%
**Complexity**: {report.recommended_fix.complexity.value}
**Gas Impact**: {report.recommended_fix.gas_impact}

{report.recommended_fix.description}

### code changes
```solidity
{report.recommended_fix.code_changes}
```

### potential risks
{chr(10).join(f'- {risk}' for risk in report.recommended_fix.risks) if report.recommended_fix.risks else '- None identified'}

### alternative approaches
{chr(10).join(f'{i+1}. **{alt.strategy_name}** (effectiveness: {alt.effectiveness * 100:.0f}%, complexity: {alt.complexity.value})' for i, alt in enumerate(report.alternative_fixes)) if report.alternative_fixes else 'None'}

### test cases
```solidity
{report.test_cases}
```

### implementation notes
{chr(10).join(f'- {note}' for note in report.implementation_notes) if report.implementation_notes else '- None'}

---
*Generated by Mortar-C Resolution Layer*
"""
        return pr_md
