"""
Attacker Prompt Templates

Prompt templates used by specialized attack agents (FlashLoanAttacker, OracleAttacker, etc.).

NOTE: BaseAttacker defines abstract methods get_system_prompt() and get_attack_prompt()
that each specialized attacker implements. This module provides common prompt building
blocks and utilities that attackers can use.

Future: If attack-specific prompts become large, extract them here from individual
attacker files (flash_loan_attacker.py, oracle_attacker.py, etc.).
"""

# Common prompt components that all attackers can use

ATTACKER_OUTPUT_FORMAT = """
# OUTPUT FORMAT

Your response MUST follow this exact format:

HYPOTHESIS:
[Attack Type]
Description: [One sentence description]
Target: [Function name or contract area]
Preconditions:
- [Required condition 1]
- [Required condition 2]
Steps:
- [Attack step 1]
- [Attack step 2]
- [Attack step 3]
Impact: [Expected outcome]
Confidence: [0.0-1.0]
Evidence:
- [Evidence 1]
- [Evidence 2]
Research Needed:
- [Optional question for JIT research]
---

[Repeat HYPOTHESIS blocks for each finding]

DECISION: [continue or stop]
REASONING: [Why continuing or stopping]
CONFIDENCE: [0.0-1.0]
"""

ATTACKER_JIT_GUIDANCE = """
# JIT RESEARCH

If you need more information to validate a hypothesis, you can request Just-In-Time research:
- Format: "NEED TO KNOW: [specific question]"
- Example: "NEED TO KNOW: Does flashLoan() check msg.sender before calling callback?"
- Example: "UNCERTAIN: Is withdraw() protected against reentrancy?"

JIT requests will be handled by specialized research agents and their answers will be
provided in the next round.
"""

ATTACKER_KB_GUIDANCE = """
# KNOWLEDGE BASE DISCOVERIES

The following vulnerabilities and patterns were discovered during Phase 2 research.
These are HINTS to guide your analysis - convert them into concrete attack hypotheses:

{kb_discoveries}

IMPORTANT: These are research discoveries, not confirmed exploits. You must:
1. Validate each discovery applies to this specific contract
2. Generate concrete attack hypotheses with steps
3. Assess confidence based on code evidence
"""

ATTACKER_STOPPING_RULES = """
# WHEN TO STOP

Decide to stop (DECISION: stop) when:
1. You've found 2+ high-confidence attack vectors (confidence >= 0.8)
2. You've exhausted all attack surfaces for your specialization
3. You've tried 3+ rounds without finding new vectors
4. The contract appears secure against your attack type

Decide to continue (DECISION: continue) when:
1. You have promising leads that need more investigation
2. You have JIT research questions that might reveal vulnerabilities
3. You've only done 1 round and want to explore more
"""

# Common validation rules for attackers
ATTACKER_VALIDATION_RULES = """
# VALIDATION RULES

Before generating a hypothesis:
1. Verify the target function EXISTS in the contract
2. Check function signatures match metadata (parameter types, return types)
3. Ensure preconditions are realistic (not impossible states)
4. Make attack steps concrete and executable (not vague like "manipulate state")
5. Base confidence on actual code evidence, not assumptions
"""
