"""
Economic Analyst (V3)

Agentic specialist for economic incentive and profitability analysis.
"""

from typing import Dict, Any
from src.research.base_specialist import EnhancedAgenticSpecialist


class EnhancedEconomicAnalyst(EnhancedAgenticSpecialist):
    """Economic Specialist - finds profitable attack vectors."""

    def __init__(self, **kwargs):
        super().__init__(
            name="EconomicAnalyst_V3",
            description="Finds economically rational attacks (profit > cost)",
            **kwargs
        )

    def get_system_prompt(self) -> str:
        return """You are an economic analyst. Find attacks where profit > cost.

YOUR DOMAIN:
1. Economic Actors: Users and their incentives
2. Value Flows: Where money moves (fees, rewards, transfers)
3. Incentive Misalignment: Misaligned incentives = exploitable
4. Profitable Attacks: Calculate profit vs cost
5. Game Theory: Dominant strategies, Nash equilibria

NOT YOUR DOMAIN:
- Pure math invariants -> Invariant specialist
- Access control -> AccessControl specialist

APPROACH:
1. run_static_analysis() for economic parameters
2. trace_state_variable() on value-tracking vars (balances, fees, rewards)
3. analyze_function_symbolically() on value-moving funcs (transfer, swap, claim)
4. check_invariant() for economic rules
5. Calculate ACTUAL profit/cost numbers
6. reflect_on_finding() before recording
7. compare_with_pattern() for flash_loan_dos, oracle_manipulation

KEY REQUIREMENT:
- Calculate concrete profit/cost, not vague "might be profitable"
- Example: "Borrow 1M (fee 1k), claim 100k rewards, profit 99k" """

    def get_analysis_prompt(
        self,
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> str:
        contract_name = contract_info.get("name", "Unknown")
        functions = contract_info.get("functions", [])
        state_vars = contract_info.get("state_vars", [])

        system_context = contract_info.get("system_context")
        taint_hints = contract_info.get("taint_traces") or []
        context_block = ""
        if system_context:
            context_block += f"\nSYSTEM CONTEXT:\n{system_context}"
        if taint_hints:
            context_block += "\nTAINT PATHS:\n" + "\n".join(taint_hints[:5])

        return f"""Analyze this contract's economic incentives for profitable attacks.

CONTRACT: {contract_name}

SOURCE:
```solidity
{contract_source}
```

METADATA:
- Functions: {', '.join(functions[:10])}
- State Variables: {', '.join(state_vars[:10])}
{context_block}

TASK: Find attacks where profit > cost. Calculate concrete numbers.

WORKFLOW:
1. run_static_analysis() - find economic parameters
2. Identify actors and incentives (depositors, LPs, validators)
3. trace_state_variable() on value-tracking vars
4. analyze_function_symbolically() on value-moving funcs
5. Calculate profit/cost for each attack scenario
6. check_invariant() for economic rules
7. reflect_on_finding() before recording
8. record_discovery() with profit calculation
9. analysis_complete() when done

Think between tool calls. Include concrete profit/cost in findings."""

# backwards compat
EconomicAnalyst = EnhancedEconomicAnalyst
