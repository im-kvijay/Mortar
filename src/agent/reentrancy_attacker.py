"""module docstring"""

import re
from typing import Dict, Any, List, Tuple
from agent.base_attacker import BaseAttacker, AttackHypothesis


class ReentrancyAttacker(BaseAttacker):
    """Reentrancy specialist"""

    def __init__(self, **kwargs):
        super().__init__(
            name="Reentrancy",
            description="Specializes in reentrancy attacks",
            **kwargs
        )

    def get_system_prompt(self) -> str:
        return """You are a Reentrancy Attack Specialist.

Focus on:
- CEI pattern violations (external call before state update)
- Missing reentrancy guards
- Cross-function reentrancy
- Read-only reentrancy
- Token hooks (ERC777, ERC721)

Output format:
HYPOTHESIS: [attack_type]
Description: [description]
Target: [function]
Confidence: [0.0-1.0]
---

DECISION: [continue/stop]
"""

    def get_attack_prompt(self, contract_source: str, contract_info: Dict[str, Any],
                         round_num: int, kb_knowledge: Dict[str, Any]) -> str:
        kb_section = self._format_kb_knowledge(kb_knowledge)
        context_block = self._format_contract_context(contract_info)

        if round_num == 1:
            return f"""Analyze for reentrancy:

```solidity
{contract_source}
```
{context_block}
{kb_section}

OBJECTIVES:
1. Find external calls (call, transfer, etc)
2. Check CEI pattern (Checks-Effects-Interactions)
3. Identify reentrancy guards
4. Look for cross-function reentrancy
5. Check token hooks
"""
        else:
            return f"Continue reentrancy analysis (Round {round_num})\n{context_block}\n{kb_section}"

    def extract_hypotheses(self, response: str, round_num: int) -> List[AttackHypothesis]:
        """Extract reentrancy hypotheses - use base implementation"""
        return self._default_extract_hypotheses(response, round_num)

    def should_continue(self, round_num: int, response: str,
                       hypotheses: List[AttackHypothesis]) -> Tuple[bool, str, float]:
        """Decide if should continue - use base implementation"""
        return self._default_should_continue(round_num, response, hypotheses, max_rounds=5)
