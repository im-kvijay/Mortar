"""
Invariant Analyst (V3)

Agentic specialist for mathematical invariant discovery.
"""

from typing import Dict, Any
from src.research.base_specialist import EnhancedAgenticSpecialist


class EnhancedInvariantAnalyst(EnhancedAgenticSpecialist):
    """Invariant Specialist - finds broken mathematical properties."""

    def __init__(self, **kwargs):
        super().__init__(
            name="InvariantAnalyst_V3",
            description="Finds broken mathematical invariants",
            **kwargs
        )

    def get_system_prompt(self) -> str:
        return """You are an invariant specialist. Find broken mathematical properties.

YOUR DOMAIN:
- Balance equations (totalSupply == sum(balances))
- Monotonic properties (timestamps, nonces only increase)
- Mathematical constraints (x + y = z, fees <= principal)
- State consistency (if paused -> no withdrawals)

NOT YOUR DOMAIN:
- Business workflows -> BusinessLogic specialist
- Authorization -> AccessControl specialist

APPROACH:
1. run_static_analysis() to identify key state variables
2. check_invariant() for 3-5 mathematical invariants
3. analyze_function_symbolically() on functions modifying critical vars
4. reflect_on_finding() before recording
5. compare_with_pattern() for flash_loan_dos, reentrancy

BE EFFICIENT:
- Focus on MATH-related invariants only
- Record discoveries as you find them
- Target 5-8 tool calls, 1-3 findings"""

    def get_analysis_prompt(
        self,
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> str:
        contract_name = contract_info.get("name", "Unknown")
        functions = contract_info.get("functions", [])
        state_vars = contract_info.get("state_vars", [])

        return f"""Analyze this contract for mathematical invariant violations.

CONTRACT: {contract_name}

SOURCE:
```solidity
{contract_source}
```

METADATA:
- Functions: {', '.join(functions[:10])}
- State Variables: {', '.join(state_vars[:10])}

TASK: Find broken invariants - balance equations, monotonic properties, constraints.

WORKFLOW:
1. run_static_analysis() - identify state variables
2. check_invariant() for key mathematical properties
3. analyze_function_symbolically() if invariant might be broken
4. reflect_on_finding() before recording
5. record_discovery() for each finding
6. analysis_complete() when done

Focus on math. Record findings immediately."""

# backwards compat
InvariantAnalyst = EnhancedInvariantAnalyst
