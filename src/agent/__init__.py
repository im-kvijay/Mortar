"""module docstring"""

from .base_attacker import (
    BaseAttacker,
    AttackHypothesis,
    JITResearchRequest,
    AttackRoundResult
)
from .orchestrator import AttackOrchestrator, AttackSession
from .economic_simulator import EconomicSimulator
from .research_gateway import ResearchGateway, JITResponse
from .research_cache import ResearchCache
from .poc_generator import PoCGenerator, GeneratedPoC, PoCGenerationError
from .poc_executor import PoCExecutor, ExecutionResult

# specialized attackers
from .flash_loan_attacker import FlashLoanAttacker
from .oracle_attacker import OracleAttacker
from .reentrancy_attacker import ReentrancyAttacker
from .logic_attacker import LogicAttacker

__all__ = [
    "BaseAttacker", "AttackHypothesis", "JITResearchRequest", "AttackRoundResult",
    "AttackOrchestrator", "AttackSession", "EconomicSimulator",
    "ResearchGateway", "JITResponse", "ResearchCache",
    "PoCGenerator", "GeneratedPoC", "PoCGenerationError", "PoCExecutor", "ExecutionResult",
    "FlashLoanAttacker", "OracleAttacker", "ReentrancyAttacker", "LogicAttacker"
]
