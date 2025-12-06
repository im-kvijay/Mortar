"""module docstring"""

import re
from typing import Dict, Any, List, Tuple
from agent.base_attacker import BaseAttacker, AttackHypothesis


class LogicAttacker(BaseAttacker):
    """Business logic specialist"""

    def __init__(self, **kwargs):
        super().__init__(
            name="Logic",
            description="Specializes in business logic vulnerabilities",
            **kwargs
        )

    def get_system_prompt(self) -> str:
        return """You are a Business Logic Attack Specialist.

Focus on:
- Access control flaws
- Missing validation
- Incorrect logic
- Unsafe operations
- State transition bugs

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
            return f"""Analyze for logic vulnerabilities:

```solidity
{contract_source}
```
{kb_section}
{context_block}

OBJECTIVES:
1. Check access control (onlyOwner, require)
2. Validate function parameters
3. Find incorrect comparisons
4. Check state transition logic
5. Look for missing checks
"""
        else:
            return f"Continue logic analysis (Round {round_num})\n{context_block}\n{kb_section}"

    def extract_hypotheses(self, response: str, round_num: int) -> List[AttackHypothesis]:
        """Extract logic hypotheses - use base implementation"""
        return self._default_extract_hypotheses(response, round_num)

    def should_continue(self, round_num: int, response: str,
                       hypotheses: List[AttackHypothesis]) -> Tuple[bool, str, float]:
        """Decide if should continue - use base implementation"""
        return self._default_should_continue(round_num, response, hypotheses, max_rounds=5)
