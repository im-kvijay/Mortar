"""
Access Control Analyst (V3)

Agentic specialist for authorization and privilege escalation analysis.
"""

from typing import Dict, Any
from src.research.base_specialist import EnhancedAgenticSpecialist


class EnhancedAccessControlAnalyst(EnhancedAgenticSpecialist):
    """Access Control Specialist - finds missing authorization checks."""

    def __init__(self, **kwargs):
        super().__init__(
            name="AccessControlAnalyst_V3",
            description="Finds missing authorization and privilege escalation",
            **kwargs
        )

    def get_system_prompt(self) -> str:
        return """You are an access control specialist. Find missing authorization checks.

YOUR DOMAIN:
- Missing modifiers (onlyOwner, onlyRole, etc.)
- Unprotected privileged functions (initialize, upgrade, mint, burn)
- Privilege escalation paths
- Authorization bypass vectors

NOT YOUR DOMAIN:
- Business logic -> BusinessLogic specialist
- Math invariants -> Invariant specialist

APPROACH:
1. run_static_analysis() to identify privileged functions
2. trace_state_variable() on role/permission vars (owner, admin, roles)
3. analyze_function_symbolically() on privileged functions
4. check_invariant() for access control rules
5. reflect_on_finding() before recording
6. compare_with_pattern() for known bypasses

BE EFFICIENT:
- Focus on HIGH-PRIVILEGE functions (initialize, upgrade, mint, withdraw, pause)
- Target 5-8 tool calls, 1-3 findings
- Record discoveries as you find them"""

    def get_analysis_prompt(
        self,
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> str:
        contract_name = contract_info.get("name", "Unknown")
        functions = contract_info.get("functions", [])
        state_vars = contract_info.get("state_vars", [])

        return f"""Analyze this contract's access control for vulnerabilities.

CONTRACT: {contract_name}

SOURCE:
```solidity
{contract_source}
```

METADATA:
- Functions: {', '.join(functions[:10])}
- State Variables: {', '.join(state_vars[:10])}

TASK: Find privilege escalation and authorization bypass vulnerabilities.

WORKFLOW:
1. run_static_analysis() - find access control mechanisms
2. Identify modifiers, role management, permission checks
3. trace_state_variable() on role/permission vars
4. analyze_function_symbolically() on privileged functions
5. check_invariant() for access control rules
6. reflect_on_finding() before recording
7. record_discovery() for each finding
8. analysis_complete() when done

Think between tool calls. Record findings immediately."""

# backwards compat
AccessControlAnalyst = EnhancedAccessControlAnalyst
