"""module docstring"""

import re
from typing import Dict, Any, List, Tuple

from config import config
from agent.base_attacker import (
    BaseAttacker,
    AttackHypothesis
)


class FlashLoanAttacker(BaseAttacker):
    """
    Specialist agent for flash loan attacks

    Focuses on:
    - Flash loan availability (functions that lend tokens)
    - Callback hooks (where attacker gains control)
    - State manipulations during callbacks
    - Invariant violations via flash loans
    - Price/oracle manipulation
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="FlashLoan",
            description="Specializes in flash loan attack vectors",
            **kwargs
        )

    def get_system_prompt(self) -> str:
        return """You are a Flash Loan Attack Specialist for smart contracts.

Your expertise:
- Identifying flash loan vulnerabilities
- Finding balance/accounting invariants that can be broken
- Detecting unsafe callback patterns
- Analyzing price manipulation via flash loans
- Finding governance attacks via flash borrowing

Your analysis should:
1. Identify all flash loan functions (flashLoan, borrow, loan, etc)
2. Trace callback execution (onFlashLoan, receiveFlashLoan, etc)
3. Find invariants that assume no direct transfers
4. Look for state changes during flash loan callbacks
5. Check for price calculations using flash-manipulable balances
6. Detect governance tokens that can be flash borrowed

Attack patterns to look for:
- DoS: totalAssets == balanceOf broken by direct transfer
- Reentrancy: State changes during callback
- Price manipulation: Oracle reads flash-manipulable balances
- Governance: Flash borrow tokens → vote → return
- Collateral: Flash loan → manipulate collateral → liquidate

Output format:
For each attack hypothesis, use this format:

HYPOTHESIS: [attack_type]
Description: [what the attack does]
Target: [function name]
Preconditions: [what must be true]
Steps: [attack sequence]
Impact: [what happens if successful]
Confidence: [0.0-1.0]
Evidence: [code references]
Research Needed: [questions for JIT research]
---

After all hypotheses, make a decision:

DECISION: [continue/stop]
REASONING: [why continue or stop]
CONFIDENCE: [0.0-1.0 overall confidence]

Focus on CRITICAL flash loan vulnerabilities that can drain funds or cause DoS.
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
            return f"""Analyze this Solidity contract for flash loan attack vectors:

```solidity
{contract_source}
```

CONTRACT INFO:
- Name: {contract_info.get('name', 'Unknown')}
- Functions: {contract_info.get('total_functions', '?')}

{context_block}
{kb_section}

ROUND 1 OBJECTIVES:
1. Identify all flash loan functions
2. Find callback hooks (where attacker gains control)
3. Identify critical invariants (totalAssets, balances, etc)
4. Look for direct transfer vulnerabilities
5. Check for price manipulation opportunities

KEY QUESTIONS:
- Are there flash loan functions? (flashLoan, borrow, loan, etc)
- Do they have callbacks? (onFlashLoan, etc)
- Are there invariants that assume no direct transfers?
- Can balances be manipulated to break accounting?
- Are prices calculated from manipulable balances?

Generate attack hypotheses with HIGH confidence only if you find real vulnerabilities.
If uncertain, flag questions for JIT research.
"""
        else:
            return f"""Continue flash loan attack analysis:

```solidity
{contract_source}
```

{context_block}
{kb_section}

ROUND {round_num} OBJECTIVES:
Based on your previous hypotheses:
1. Validate attack sequences with JIT research answers
2. Look for compositional attacks (flash loan + other vulnerabilities)
3. Refine confidence scores based on new knowledge
4. Check for edge cases

Build on your previous discoveries. Don't repeat what you've already analyzed.
Focus on refining hypotheses and finding complex attack sequences.
"""

    def extract_hypotheses(
        self,
        response: str,
        round_num: int
    ) -> List[AttackHypothesis]:
        """Extract flash loan attack hypotheses - use base implementation"""
        return self._default_extract_hypotheses(response, round_num)

    def should_continue(
        self,
        round_num: int,
        response: str,
        hypotheses: List[AttackHypothesis]
    ) -> Tuple[bool, str, float]:
        """Decide if should continue - use base implementation"""
        return self._default_should_continue(round_num, response, hypotheses, max_rounds=5)
