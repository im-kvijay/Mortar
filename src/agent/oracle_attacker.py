"""module docstring"""

import re
from typing import Dict, Any, List, Tuple

from agent.base_attacker import (
    BaseAttacker,
    AttackHypothesis
)


class OracleAttacker(BaseAttacker):
    """Oracle manipulation specialist"""

    def __init__(self, **kwargs):
        super().__init__(
            name="Oracle",
            description="Specializes in oracle and price manipulation attacks",
            **kwargs
        )

    def get_system_prompt(self) -> str:
        return """You are an Oracle Manipulation Attack Specialist.

Your expertise:
- Price oracle vulnerabilities
- TWAP manipulation
- Stale price data usage
- Flash loan + oracle combo attacks
- Read-only reentrancy on oracle calls

Focus on:
1. Oracle dependencies (Chainlink, Uniswap, Curve, etc)
2. Price calculation methods (spot, TWAP, weighted average)
3. Staleness checks (updatedAt, timeWindow)
4. Flash-manipulable price sources
5. Oracle return value validation

Output format:
HYPOTHESIS: [attack_type]
Description: [description]
Target: [function]
Preconditions: [list]
Steps: [attack sequence]
Impact: [impact]
Confidence: [0.0-1.0]
Evidence: [code references]
Research Needed: [JIT questions]
---

DECISION: [continue/stop]
REASONING: [reasoning]
CONFIDENCE: [0.0-1.0]
"""

    def get_attack_prompt(
        self,
        contract_source: str,
        contract_info: Dict[str, Any],
        round_num: int,
        kb_knowledge: Dict[str, Any]
    ) -> str:
        kb_section = self._format_kb_knowledge(kb_knowledge)
        context_block = self._format_contract_context(contract_info)

        if round_num == 1:
            return f"""Analyze for oracle manipulation attacks:

```solidity
{contract_source}
```

CONTRACT INFO:
- Name: {contract_info.get('name', 'Unknown')}

{context_block}
{kb_section}

OBJECTIVES:
1. Identify oracle dependencies (Chainlink, Uniswap, etc)
2. Find price calculation logic
3. Check for flash-manipulable price sources
4. Validate staleness checks
5. Look for read-only reentrancy

Generate high-confidence attack hypotheses.
"""
        else:
            return f"""Continue oracle attack analysis (Round {round_num}):

{context_block}
{kb_section}

Refine hypotheses based on JIT research.
Look for compositional attacks (oracle + flash loan, etc).
"""

    def extract_hypotheses(
        self,
        response: str,
        round_num: int
    ) -> List[AttackHypothesis]:
        """Extract oracle attack hypotheses - use base implementation"""
        return self._default_extract_hypotheses(response, round_num)

    def should_continue(
        self,
        round_num: int,
        response: str,
        hypotheses: List[AttackHypothesis]
    ) -> Tuple[bool, str, float]:
        """Decide if should continue - use base implementation"""
        return self._default_should_continue(round_num, response, hypotheses, max_rounds=5)
