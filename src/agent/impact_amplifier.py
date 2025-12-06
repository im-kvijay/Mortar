"""module docstring"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum

from config import config
from utils.llm_backend.base import LLMBackend, LLMResponse
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager
from agent.base_attacker import AttackHypothesis


class ImmuneFiSeverity(Enum):
    """Immunefi severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class ImpactReport:
    """
    Detailed impact assessment for validated vulnerability

    Attributes:
        hypothesis: Original attack hypothesis
        poc_validated: Whether PoC succeeded
        severity: Immunefi severity level
        economic_impact_usd: Estimated economic impact in USD
        attack_cost_usd: Cost to execute attack
        profit_usd: Net profit (impact - cost)
        roi_percent: Return on investment percentage
        cascading_effects: List of secondary impacts
        affected_functions: Functions directly affected
        affected_protocols: External protocols affected (composability)
        recovery_possible: Whether funds can be recovered
        recovery_cost: Estimated cost to fix/upgrade
        confidence: Confidence in impact assessment (0.0-1.0)
        reasoning: Detailed explanation
        exploit_occurred: True if exploit broke invariants/authorization
        economic_impact_realized: True if measurable economic delta occurred
    """
    hypothesis: AttackHypothesis
    poc_validated: bool
    severity: ImmuneFiSeverity
    economic_impact_usd: float
    attack_cost_usd: float
    profit_usd: float
    roi_percent: float
    cascading_effects: List[str]
    affected_functions: List[str]
    affected_protocols: List[str]
    recovery_possible: bool
    recovery_cost: float
    confidence: float
    reasoning: str
    exploit_occurred: bool
    economic_impact_realized: bool

    # backwards-compatible accessors
    @property
    def economic_impact(self) -> float:
        return self.economic_impact_usd

    @property
    def attack_cost(self) -> float:
        return self.attack_cost_usd

    @property
    def profit(self) -> float:
        return self.profit_usd


class ImpactAmplifier:
    """
    Post-PoC impact amplification layer

    Assesses real-world economic impact of validated vulnerabilities.
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

    def amplify_impact(
        self,
        hypothesis: AttackHypothesis,
        poc_code: str,
        poc_result: Dict[str, Any],
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> ImpactReport:
        """
        Amplify impact of validated vulnerability

        Args:
            hypothesis: Original attack hypothesis
            poc_code: PoC test code that succeeded
            poc_result: Execution result from PoC
            contract_source: Contract source code
            contract_info: Contract metadata

        Returns:
            ImpactReport with detailed assessment
        """
        self.logger.info(f"[ImpactAmplifier] Amplifying impact for {hypothesis.attack_type}")

        # build amplification prompt
        prompt = self._build_amplification_prompt(
            hypothesis=hypothesis,
            poc_code=poc_code,
            poc_result=poc_result,
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
                agent_name="ImpactAmplifier",
                contract_name=contract_info.get("name", "Unknown"),
                round_num=0,
                operation="impact_amplify",
                cost=getattr(response, "cost", 0.0),
                metadata={
                    "model": getattr(response, "model", "unknown"),
                    "prompt_tokens": getattr(response, "prompt_tokens", 0),
                    "output_tokens": getattr(response, "output_tokens", 0),
                    "thinking_tokens": getattr(response, "thinking_tokens", 0),
                }
            )
        except (AttributeError, TypeError, ValueError) as exc:
            # cost logging is optional - don't fail if cost_manager is unavailable or data is invalid
            self.logger.debug(f"[ImpactAmplifier] Cost logging failed: {exc}")

        # parse response
        report = self._parse_amplification_response(
            response.text,
            hypothesis,
            poc_result.get('success', False)
        )

        # log impact assessment
        self.logger.log_impact_assessment(
            hypothesis_id=hypothesis.hypothesis_id,
            severity=report.severity.value,
            economic_impact=report.economic_impact_usd,
            attack_cost=report.attack_cost_usd,
            roi=report.roi_percent,
            reasoning=report.reasoning
        )

        return report

    def _build_amplification_prompt(
        self,
        hypothesis: AttackHypothesis,
        poc_code: str,
        poc_result: Dict[str, Any],
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> str:
        """
        Build Extended Thinking prompt for impact amplification
        """
        # map fields from attackhypothesis (no extra attributes assumed)
        attack_type = hypothesis.attack_type
        target_fn = hypothesis.target_function
        seq_lines = "\n".join(f"{i+1}. {s}" for i, s in enumerate(hypothesis.steps or [])) or "(no sequence provided)"
        root_cause = (hypothesis.evidence[0] if hypothesis.evidence else "")

        prompt = f"""You are a smart contract economics and security expert. A vulnerability has been VALIDATED with a working PoC. Your job is to assess the REAL-WORLD IMPACT for bug bounty submission.

CONTRACT INFORMATION:
Name: {contract_info.get('name', 'Unknown')}
Type: {contract_info.get('type', 'Unknown')}
Flash Loan Capable: {contract_info.get('flash_loan_capable', False)}
Has Oracle: {contract_info.get('has_oracle', False)}

VALIDATED VULNERABILITY:
Type: {attack_type}
Target Function: {target_fn}
Description: {hypothesis.description}
Root Cause (if known): {root_cause}
Attack Sequence:
{seq_lines}

POC VALIDATION RESULT:
Success: {poc_result.get('success', False)}
Output: {poc_result.get('output', 'N/A')[:500]}

IMPACT ASSESSMENT FRAMEWORK:

1. ECONOMIC IMPACT (Direct)
   - How much USD can attacker steal/manipulate?
   - Is there a cap (e.g., pool size, vault balance)?
   - Can attack be repeated (continuous drain vs one-time)?

   Estimation factors:
   - If flash loan attack: Assume pool has $1M TVL (typical)
   - If oracle manipulation: Assume $5M+ TVL (DeFi standard)
   - If governance attack: Assume full protocol TVL at risk
   - If DoS: Calculate revenue loss per day * downtime

2. ATTACK COST
   - Gas cost (estimate in USD)
   - Capital required (flash loan fees, initial investment)
   - Setup cost (contracts, monitoring)
   - Total cost = Gas + Capital + Setup

3. NET PROFIT & ROI
   - Profit = Economic Impact - Attack Cost
   - ROI = (Profit / Attack Cost) * 100%
   - Viable if ROI > 100% (profitable)

4. CASCADING EFFECTS (Indirect)
   - Does this break other parts of the protocol?
   - Does it affect external protocols (DeFi composability)?
   - Can it trigger bank run / mass withdrawals?
   - Reputation damage & confidence loss?

5. RECOVERY ANALYSIS
   - Can stolen funds be recovered (pause, blacklist)?
   - What's required to fix (upgrade, patch)?
   - Estimated recovery cost?
   - Time to recover?

6. IMMUNEFI SEVERITY MAPPING
   Critical ($100k+):
   - Direct theft of any user funds
   - Protocol insolvency
   - Permanent loss of funds

   High ($50k+):
   - Theft under specific conditions
   - Significant DoS (>24 hours)
   - Oracle manipulation with economic impact

   Medium ($10k+):
   - Limited theft (< $100k)
   - Temporary DoS (< 24 hours)
   - Griefing with economic impact

   Low ($1k+):
   - Griefing attacks
   - Minimal economic impact
   - Informational bugs

INSTRUCTIONS:
Think deeply about the real-world impact. Be realistic but thorough.
Consider both direct and cascading effects.

Respond in this exact JSON format:
{{
    "severity": "critical" | "high" | "medium" | "low" | "none",
    "economic_impact_usd": 0.0,
    "attack_cost_usd": 0.0,
    "profit_usd": 0.0,
    "roi_percent": 0.0,
    "cascading_effects": ["effect 1", "effect 2", ...],
    "affected_functions": ["function1", "function2", ...],
    "affected_protocols": ["protocol1", "protocol2", ...],
    "recovery_possible": true/false,
    "recovery_cost": 0.0,
    "confidence": 0.0-1.0,
    "reasoning": "detailed explanation with calculations"
}}

POC CODE (for reference):
```solidity
{poc_code[:2000]}
```

CONTRACT SOURCE (for reference):
```solidity
{contract_source[:2000]}
```

IMPACT ASSESSMENT:"""

        return prompt

    def _parse_amplification_response(
        self,
        response: str,
        hypothesis: AttackHypothesis,
        poc_validated: bool
    ) -> ImpactReport:
        """
        Parse amplification response into structured report
        """
        import json

        try:
            # extract json from response
            start = response.find('{')
            end = response.rfind('}') + 1
            json_str = response[start:end]
            data = json.loads(json_str)

            # parse severity
            severity_str = data.get('severity', 'none').lower()
            severity = ImmuneFiSeverity(severity_str)

            # calculate profit and roi if not provided
            economic_impact = float(data.get('economic_impact_usd', 0.0))
            attack_cost = float(data.get('attack_cost_usd', 0.0))
            profit = float(data.get('profit_usd', economic_impact - attack_cost))
            roi = float(data.get('roi_percent', (profit / attack_cost * 100) if attack_cost > 0 else 0))

            exploit_occurred = bool(
                data.get('exploit_occurred',
                data.get('exploitOccurred', poc_validated))
            )
            economic_flag_raw = data.get('economic_impact_realized',
                                         data.get('economicImpactRealized',
                                                  data.get('economic_impact_confirmed',
                                                           data.get('economicImpactConfirmed', None))))
            if economic_flag_raw is None:
                economic_flag = (economic_impact > 0) or (profit > 0)
            else:
                economic_flag = bool(economic_flag_raw)

            if exploit_occurred and severity in (ImmuneFiSeverity.LOW, ImmuneFiSeverity.NONE):
                self.logger.info(
                    "[ImpactAmplifier] Exploit occurred; elevating severity to at least MEDIUM"
                )
                severity = ImmuneFiSeverity.MEDIUM

            return ImpactReport(
                hypothesis=hypothesis,
                poc_validated=poc_validated,
                severity=severity,
                economic_impact_usd=economic_impact,
                attack_cost_usd=attack_cost,
                profit_usd=profit,
                roi_percent=roi,
                cascading_effects=data.get('cascading_effects', []),
                affected_functions=data.get('affected_functions', []),
                affected_protocols=data.get('affected_protocols', []),
                recovery_possible=data.get('recovery_possible', False),
                recovery_cost=float(data.get('recovery_cost', 0.0)),
                confidence=float(data.get('confidence', 0.0)),
                reasoning=data.get('reasoning', ''),
                exploit_occurred=exploit_occurred,
                economic_impact_realized=economic_flag
            )

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            # parsing failed - return default report
            self.logger.warning(f"[ImpactAmplifier] Failed to parse response: {e}")
            return ImpactReport(
                hypothesis=hypothesis,
                poc_validated=poc_validated,
                severity=ImmuneFiSeverity.NONE,
                economic_impact_usd=0.0,
                attack_cost_usd=0.0,
                profit_usd=0.0,
                roi_percent=0.0,
                cascading_effects=[],
                affected_functions=[],
                affected_protocols=[],
                recovery_possible=False,
                recovery_cost=0.0,
                confidence=0.0,
                reasoning="Failed to parse impact assessment",
                exploit_occurred=poc_validated,
                economic_impact_realized=False
            )

    def generate_bug_bounty_report(self, report: ImpactReport) -> str:
        """
        Generate formatted bug bounty submission report

        Returns:
            Markdown-formatted report ready for Immunefi/Code4rena
        """
        report_md = f"""# Vulnerability Report: {report.hypothesis.attack_type}

## severity
**{report.severity.value.upper()}**

## summary
{report.hypothesis.description}

## vulnerability details

### target function
`{report.hypothesis.target_function}`

### attack sequence
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(report.hypothesis.steps))}

### root cause
{(report.hypothesis.evidence[0] if report.hypothesis.evidence else 'N/A')}

## impact assessment

### economic impact
- **Direct Loss**: ${report.economic_impact_usd:,.2f} USD
- **Attack Cost**: ${report.attack_cost_usd:,.2f} USD
- **Net Profit**: ${report.profit_usd:,.2f} USD
- **ROI**: {report.roi_percent:.1f}%

### exploit flags
- **Exploit Occurred**: {'Yes' if report.exploit_occurred else 'No'}
- **Economic Impact Detected**: {'Yes' if report.economic_impact_realized else 'No'}

### affected components
- **Functions**: {', '.join(report.affected_functions) if report.affected_functions else 'N/A'}
- **External Protocols**: {', '.join(report.affected_protocols) if report.affected_protocols else 'None'}

### cascading effects
{chr(10).join(f'- {effect}' for effect in report.cascading_effects) if report.cascading_effects else '- None identified'}

### recovery
- **Possible**: {'Yes' if report.recovery_possible else 'No'}
- **Estimated Cost**: ${report.recovery_cost:,.2f} USD

## proof of concept
[OK] **PoC Validated**: Working exploit code available

## remediation
*See resolution layer output for detailed fix recommendations*

## assessment confidence
**{report.confidence * 100:.0f}%**

## detailed reasoning
{report.reasoning}

---
*Generated by Mortar-C Autonomous Auditing System*
"""
        return report_md
