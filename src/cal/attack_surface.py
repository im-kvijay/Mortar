"""attack surface extractor (layer 1.3)"""
from typing import List, Dict, Optional
import logging

from src.models.findings import (
    AttackSurface,
    FunctionSignature,
    TokenFlow,
    OracleDependency,
    UpgradePattern,
    ContractInfo,
    ProjectStructure
)

logger = logging.getLogger(__name__)

def _compute_function_selector(signature: str) -> str:
    """compute ethereum function selector (first 4 bytes of keccak-256 hash)"""
    # Try pycryptodome first (preferred)
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(signature.encode('utf-8'))
        hash_bytes = k.digest()
        return "0x" + hash_bytes[:4].hex()
    except ImportError:
        pass

    # Try web3.py as fallback
    try:
        from web3 import Web3
        hash_bytes = Web3.keccak(text=signature)
        return "0x" + hash_bytes[:4].hex()
    except ImportError:
        pass

    # CRITICAL: No fallback to hashlib.sha3_256 - it produces WRONG selectors!
    # Log critical warning and return invalid selector
    logger.critical(
        "CRITICAL: Neither pycryptodome nor web3.py available for Keccak-256 hashing! "
        "Function selectors will be INCORRECT. Install with: pip install pycryptodome"
    )

    return "0xDEADBEEF"

# flash loan function patterns
FLASH_LOAN_PATTERNS = [
    "flashLoan",
    "flash",
    "onFlashLoan",
    "executeOperation",  # Aave
    "uniswapV2Call",     # Uniswap V2
    "uniswapV3FlashCallback",  # Uniswap V3
    "pancakeCall",       # PancakeSwap
    "balancerFlashLoan", # Balancer
]

### oracle/price feed patterns
ORACLE_PATTERNS = [
    "getPrice",
    "latestAnswer",
    "latestRoundData",  # Chainlink
    "getReserves",      # Uniswap reserves
    "slot0",            # Uniswap V3 slot
    "observe",          # Uniswap V3 TWAP
    "consult",          # TWAP oracle
    "update",           # Oracle update
]

# privileged modifier patterns
PRIVILEGED_MODIFIERS = [
    "onlyOwner",
    "onlyAdmin",
    "onlyGovernance",
    "onlyRole",
    "requiresAuth",
    "authorized",
]

# erc20 token transfer functions
TOKEN_TRANSFER_FUNCTIONS = [
    "transfer",
    "transferFrom",
    "mint",
    "burn",
    "approve",
    "safeTransfer",
    "safeTransferFrom",
]

# external call patterns (in bytecode)
EXTERNAL_CALL_OPCODES = [
    "CALL",
    "DELEGATECALL",
    "STATICCALL",
    "CALLCODE",
]

class AttackSurfaceExtractor:
    """extracts attack surface from compiled smart contracts"""

    def __init__(self):
        """Initialize attack surface extractor"""

    def extract(self, contract: ContractInfo) -> AttackSurface:
        """extract attack surface from a contract"""
        print(f"\n[AttackSurface] Analyzing {contract.name}")

        attack_surface = AttackSurface(
            contract_name=contract.name,
            contract_address=None  # Not deployed yet
        )

        # 1. Extract function signatures from ABI
        if contract.abi:
            attack_surface.external_functions = self._extract_functions(contract.abi)
            attack_surface.privileged_functions = self._find_privileged_functions(attack_surface.external_functions)

            # 2. Detect flash loan functions
            attack_surface.flashloan_functions = self._detect_flash_loans(attack_surface.external_functions)
            attack_surface.has_flashloan = len(attack_surface.flashloan_functions) > 0

            # 3. Detect oracle dependencies
            attack_surface.oracle_dependencies = self._detect_oracles(attack_surface.external_functions, contract)

            # 4. Detect token flows
            attack_surface.token_flows = self._detect_token_flows(attack_surface.external_functions, contract)

        # 5. Detect reentrancy guards (from AST or bytecode)
        attack_surface.has_reentrancy_guard = self._has_reentrancy_guard(contract)

        # 6. Detect upgrade patterns
        attack_surface.upgrade_mechanism = self._detect_upgrade_pattern(contract)

        # Print summary
        print(f"  - External functions: {len(attack_surface.external_functions)}")
        print(f"  - Privileged functions: {len(attack_surface.privileged_functions)}")
        print(f"  - Flash loan capable: {attack_surface.has_flashloan}")
        print(f"  - Oracle dependencies: {len(attack_surface.oracle_dependencies)}")
        print(f"  - Token flows: {len(attack_surface.token_flows)}")
        print(f"  - Reentrancy guard: {attack_surface.has_reentrancy_guard}")

        return attack_surface

    def _extract_functions(self, abi: List[Dict]) -> List[FunctionSignature]:
        """extract function signatures from abi"""
        functions = []

        for item in abi:
            if item.get("type") != "function":
                continue

            # Only include external/public (ABI only exposes external interface)
            name = item.get("name", "")
            state_mutability = item.get("stateMutability", "nonpayable")

            inputs = []
            for param in item.get("inputs", []):
                inputs.append({
                    "type": param.get("type", ""),
                    "name": param.get("name", "")
                })

            outputs = []
            for param in item.get("outputs", []):
                outputs.append({
                    "type": param.get("type", ""),
                    "name": param.get("name", "")
                })

            # Generate function selector using keccak256
            param_types = [inp["type"] for inp in inputs]
            selector_string = f"{name}({','.join(param_types)})"

            # CRITICAL: Solidity uses Keccak-256 (pre-FIPS), NOT SHA3-256 (final FIPS)
            # These produce DIFFERENT outputs! Must use proper Keccak-256.
            # Example: transfer(address,uint256)
            #   - SHA3-256:   0x4b40e901 (WRONG)
            #   - Keccak-256: 0xa9059cbb (CORRECT)
            selector = _compute_function_selector(selector_string)

            is_payable = state_mutability == "payable"

            func_sig = FunctionSignature(
                name=name,
                selector=selector,
                visibility="external",  # ABI only shows external
                state_mutability=state_mutability,
                inputs=inputs,
                outputs=outputs,
                is_payable=is_payable,
                has_modifiers=False,  # Will detect below
                modifiers=[]
            )

            functions.append(func_sig)

        return functions

    def _find_privileged_functions(self, functions: List[FunctionSignature]) -> List[FunctionSignature]:
        """identify functions that likely have access control modifiers"""
        privileged = []

        # Heuristic: function names containing admin/owner/governance keywords
        privileged_keywords = ["owner", "admin", "governance", "authorized", "pause", "upgrade", "initialize"]

        for func in functions:
            func_lower = func.name.lower()

            if any(keyword in func_lower for keyword in privileged_keywords):
                privileged.append(func)

        return privileged

    def _detect_flash_loans(self, functions: List[FunctionSignature]) -> List[str]:
        """detect flash loan capability"""
        flash_loan_funcs = []

        for func in functions:

            for pattern in FLASH_LOAN_PATTERNS:
                if pattern.lower() in func.name.lower():
                    flash_loan_funcs.append(func.name)
                    break

        return flash_loan_funcs

    def _detect_oracles(self, functions: List[FunctionSignature], contract: ContractInfo) -> List[OracleDependency]:
        """detect oracle/price feed dependencies"""
        oracles = []

        for func in functions:

            for pattern in ORACLE_PATTERNS:
                if pattern.lower() in func.name.lower():

                    oracle_type = "custom"
                    is_twap = False

                    if "chainlink" in contract.name.lower() or "latestRoundData" in func.name:
                        oracle_type = "chainlink"
                    elif "uniswap" in contract.name.lower() or "getReserves" in func.name:
                        if "v3" in contract.name.lower() or "observe" in func.name:
                            oracle_type = "uniswap_v3"
                            is_twap = "observe" in func.name
                        else:
                            oracle_type = "uniswap_v2"
                    elif "twap" in func.name.lower() or "observe" in func.name.lower():
                        is_twap = True

                    oracle = OracleDependency(
                        function_name=func.name,
                        oracle_address="unknown",  # Would need runtime analysis
                        oracle_type=oracle_type,
                        is_twap=is_twap,
                        twap_window=None
                    )
                    oracles.append(oracle)
                    break

        return oracles

    def _detect_token_flows(self, functions: List[FunctionSignature], contract: ContractInfo) -> List[TokenFlow]:
        """detect token transfer/flow patterns"""
        flows = []

        for func in functions:

            for transfer_func in TOKEN_TRANSFER_FUNCTIONS:
                if transfer_func.lower() in func.name.lower():

                    flow_type = "transfer"
                    if "mint" in func.name.lower():
                        flow_type = "mint"
                    elif "burn" in func.name.lower():
                        flow_type = "burn"
                    elif "deposit" in func.name.lower():
                        flow_type = "deposit"
                    elif "withdraw" in func.name.lower():
                        flow_type = "withdrawal"

                    flow = TokenFlow(
                        function_name=func.name,
                        token="unknown",  # Would need deeper analysis
                        flow_type=flow_type,
                        amount_expression="unknown",
                        has_balance_check=False,  # Would need AST/bytecode analysis
                        has_allowance_check=False,
                        updates_before_transfer=True  # Assume CEI by default
                    )
                    flows.append(flow)
                    break

        return flows

    def _has_reentrancy_guard(self, contract: ContractInfo) -> bool:
        """detect if contract has reentrancy guard"""
        # Heuristic checks:
        # 1. Contract inherits from ReentrancyGuard
        if any("ReentrancyGuard" in base for base in contract.inherits):
            return True

        # 2. Check imports for OpenZeppelin ReentrancyGuard
        if any("ReentrancyGuard" in imp for imp in contract.imports):
            return True

        # (e.g., detecting lock variables being set/unset around external calls)

        return False

    def _detect_upgrade_pattern(self, contract: ContractInfo) -> Optional[UpgradePattern]:
        """detect upgrade/proxy patterns"""

        for base in contract.inherits:
            base_lower = base.lower()

            if "uups" in base_lower:
                return UpgradePattern(
                    pattern_type="UUPS",
                    admin_address=None,
                    implementation_slot=None
                )
            elif "transparentupgradeableproxy" in base_lower:
                return UpgradePattern(
                    pattern_type="Transparent Proxy",
                    admin_address=None,
                    implementation_slot=None
                )
            elif "beacon" in base_lower and "proxy" in base_lower:
                return UpgradePattern(
                    pattern_type="Beacon",
                    admin_address=None,
                    implementation_slot=None
                )
            elif "diamond" in base_lower:
                return UpgradePattern(
                    pattern_type="Diamond",
                    admin_address=None,
                    implementation_slot=None
                )

        for imp in contract.imports:
            imp_lower = imp.lower()
            if "upgradeable" in imp_lower or "proxy" in imp_lower:
                return UpgradePattern(
                    pattern_type="Unknown Proxy",
                    admin_address=None,
                    implementation_slot=None
                )

        return None

def extract_attack_surface(contract: ContractInfo) -> AttackSurface:
    """convenience function to extract attack surface"""
    extractor = AttackSurfaceExtractor()
    return extractor.extract(contract)

def extract_all_attack_surfaces(project: ProjectStructure) -> Dict[str, AttackSurface]:
    """extract attack surfaces for all contracts in project"""
    extractor = AttackSurfaceExtractor()
    surfaces = {}

    print(f"\n[AttackSurface] Extracting attack surfaces for {len(project.contracts)} contracts")

    for contract in project.contracts:
        surface = extractor.extract(contract)
        surfaces[contract.name] = surface

    return surfaces
