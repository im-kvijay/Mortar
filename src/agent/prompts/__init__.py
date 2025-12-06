"""
Prompt Templates Module

Centralized location for all prompt templates used by attack agents and PoC generator.

Exports:
    From poc_prompts:
        - POC_SYSTEM_PROMPT: System prompt for PoC generation
        - POC_FLASH_LOAN_GUIDANCE: Flash loan specific guidance
        - POC_REENTRANCY_GUIDANCE: Reentrancy specific guidance
        - POC_ORACLE_GUIDANCE: Oracle manipulation guidance
        - POC_ACCESS_CONTROL_GUIDANCE: Access control bypass guidance
        - POC_INTEGRATION_MODE_GUIDANCE: Integration testing guidance

    From attacker_prompts:
        - (Attacker-specific system prompts defined by subclasses)
"""

from .poc_prompts import (
    POC_SYSTEM_PROMPT,
    POC_FLASH_LOAN_GUIDANCE,
    POC_REENTRANCY_GUIDANCE,
    POC_ORACLE_GUIDANCE,
    POC_ACCESS_CONTROL_GUIDANCE,
    POC_INTEGRATION_MODE_GUIDANCE,
)

__all__ = [
    "POC_SYSTEM_PROMPT",
    "POC_FLASH_LOAN_GUIDANCE",
    "POC_REENTRANCY_GUIDANCE",
    "POC_ORACLE_GUIDANCE",
    "POC_ACCESS_CONTROL_GUIDANCE",
    "POC_INTEGRATION_MODE_GUIDANCE",
]
