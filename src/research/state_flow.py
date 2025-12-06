"""state flow analyst - state mutation analysis."""

from typing import Dict, Any
from src.research.base_specialist import EnhancedAgenticSpecialist


class EnhancedStateFlowAnalyst(EnhancedAgenticSpecialist):
    """tracks state mutations and finds manipulation vulnerabilities."""

    def __init__(self, **kwargs):
        super().__init__(
            name="StateFlowAnalyst_V3",
            description="Traces state mutations and finds manipulation vulnerabilities",
            **kwargs
        )

    def get_system_prompt(self) -> str:
        return """you are a state flow specialist. track state mutations and find manipulation vulnerabilities.

your domain:
1. state variable mapping (which functions read/write each var)
2. state transitions (how state changes)
3. critical state vars
4. unprotected modifications
5. state manipulation paths

not your domain:
- business workflows -> businesslogic specialist
- access control -> accesscontrol specialist

approach:
1. run_static_analysis() to find all state variables
2. trace_state_variable() on each state variable
3. analyze_function_symbolically() on state-modifying functions
4. check_invariant() for state consistency rules
5. reflect_on_finding() before recording high-confidence finds
6. compare_with_pattern() for reentrancy, flash_loan_dos

completeness:
- trace all state variables
- analyze all state-modifying functions
- verify state consistency rules
- record findings immediately"""

    def get_analysis_prompt(
        self,
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> str:
        contract_name = contract_info.get("name", "Unknown")
        functions = contract_info.get("functions", [])
        state_vars = contract_info.get("state_vars", [])

        return f"""analyze state flow for this contract.

contract: {contract_name}

source:
```solidity
{contract_source}
```

metadata:
- functions: {', '.join(functions[:10])}
- state variables: {', '.join(state_vars[:10])}

task: trace state mutations, find manipulation vulnerabilities.

workflow:
1. run_static_analysis() - identify state variables
2. trace_state_variable() on each variable
3. analyze_function_symbolically() on state-modifying functions
4. check_invariant() for consistency rules
5. reflect_on_finding() before recording
6. record_discovery() for each finding
7. analysis_complete() when done

think between tool calls. record findings immediately."""

# backwards compatibility
StateFlowAnalyst = EnhancedStateFlowAnalyst
