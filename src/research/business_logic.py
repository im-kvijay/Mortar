"""
Business Logic Analyst (V3)

Agentic specialist for business logic vulnerability discovery.
Uses tool-based analysis with self-reflection.
"""

from typing import Dict, Any
from src.research.base_specialist import EnhancedAgenticSpecialist


class EnhancedBusinessLogicAnalyst(EnhancedAgenticSpecialist):
    """
    Business Logic Specialist - analyzes workflows and business rules.

    Focuses on: deposit/withdraw flows, fee calculations, flash loan vectors,
    unintended behavior paths.
    """

    def __init__(self, **kwargs):
        super().__init__(
            name="BusinessLogicAnalyst_V3",
            description="Analyzes contract workflows and business rule violations",
            **kwargs
        )

    def _should_run_web_scan(self, contract_info: Dict[str, Any]) -> bool:
        name = (contract_info or {}).get("name", "") or ""
        name = name.strip()
        if not name or name.lower() in {"unknown", "contract"}:
            return False

        # Trigger web search for well-known protocols or oracle-driven contracts
        keywords = {"oracle", "price", "vault", "amm", "dex", "lending", "pool", "bridge"}
        text_blob = " ".join([
            name,
            *(contract_info.get("tags") or []),
            *(function for function in contract_info.get("functions", [])[:10])
        ]).lower()

        return any(keyword in text_blob for keyword in keywords)

    def get_system_prompt(self) -> str:
        return """You are a business logic specialist. Find workflow vulnerabilities and business rule violations.

YOUR DOMAIN:
1. Deposit/Withdraw/Swap Workflows:
   - Trace all deposit paths (normal, direct transfer, flash loan)
   - Trace all withdrawal paths (normal, emergency, force)
   - Check round-trip inconsistencies (deposit X -> withdraw Y, X != Y?)

2. Fee Calculations:
   - Analyze fee logic (deposit, withdrawal, performance, management fees)
   - Check for fee bypass paths
   - Look for rounding/precision errors

3. Flash Loan & DoS Vectors:
   - External calls where flash loans can inject funds
   - Resource exhaustion (unbounded loops, gas griefing)
   - Sandwich attack surfaces in AMM/DEX

4. Unintended Behavior:
   - Workflow shortcuts bypassing intended processes
   - State corruption via edge cases (zero, MAX_UINT)
   - "Free money" logic (profit without risk)

NOT YOUR DOMAIN (other specialists handle):
- Mathematical invariants -> Invariant specialist
- Access control -> AccessControl specialist

APPROACH:
1. run_static_analysis() for structure
2. List all state-modifying public/external functions
3. analyze_function_symbolically() on each workflow
4. trace_state_variable() for business-critical vars
5. check_invariant() for business rules
6. compare_with_pattern() for known flaws

COMPLETENESS:
- Analyze all deposit/withdraw variations
- Check all fee calculation paths
- Explore flash loan vectors
- Record 5+ findings or confirm none exist"""

    def get_analysis_prompt(
        self,
        contract_source: str,
        contract_info: Dict[str, Any]
    ) -> str:
        contract_name = contract_info.get("name", "Unknown")
        functions = contract_info.get("functions", [])
        state_vars = contract_info.get("state_vars", [])

        return f"""Analyze this contract's business logic for vulnerabilities.

CONTRACT: {contract_name}

SOURCE:
```solidity
{contract_source}
```

METADATA:
- Functions: {', '.join(functions[:10])}
- State Variables: {', '.join(state_vars[:10])}

TASK: Find business logic flaws - workflow bugs, fee manipulation, flash loan vectors.

WORKFLOW:
1. run_static_analysis() - get structure
2. Identify contract type (vault, DEX, lending, etc.) and main operations
3. analyze_function_symbolically() on each workflow function
4. trace_state_variable() for business-critical vars
5. check_invariant() for business rules
6. reflect_on_finding() before recording high-confidence findings
7. compare_with_pattern() for known flaws
8. record_discovery() for each finding
9. analysis_complete() when done

Think between tool calls. Record findings immediately."""

# backwards compat
BusinessLogicAnalyst = EnhancedBusinessLogicAnalyst
