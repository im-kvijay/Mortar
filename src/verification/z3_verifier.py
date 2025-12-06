"""z3 verifier - formal verification using smt solving"""

from typing import Dict, Any, List, Optional, Tuple, TYPE_CHECKING
from decimal import Decimal
from dataclasses import dataclass
from enum import Enum
import re
import ast
import operator
import threading

import z3
from z3 import (
    Solver, Bool, Int, BitVec, BitVecSort, Array, IntSort, Select,
    sat, unsat, unknown, And, Or, Not, Implies,
    ULT, ULE, UGT, UGE, BV2Int, BitVecVal
)

from config import config
from utils.logging import ResearchLogger
from verification.formal_spec_extractor import FormalSpec, StateVariable, Action

if TYPE_CHECKING:
    from verification.mcts_engine import MCTSEngine, MCTSResult


class VerificationResult(Enum):
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"


@dataclass
class Z3VerificationResult:
    """Z3 verification result with SAT/UNSAT/UNKNOWN"""
    result: VerificationResult
    confidence: float
    model: Optional[z3.ModelRef]
    attack_parameters: Dict[str, Any]
    reasoning: str
    solver_time: float
    constraints_added: int


class Z3Verifier:
    """Formal verification using Z3 SMT solver"""

    def __init__(self, logger: ResearchLogger, timeout_ms: int = 30000, enable_mcts_fallback: bool = True, mcts_engine: Optional['MCTSEngine'] = None):
        self.logger = logger
        self.timeout_ms = timeout_ms
        self.z3_vars: Dict[str, Any] = {}
        self._safe_var_names: Dict[str, str] = {}
        self._var_types: Dict[str, str] = {}
        self.enable_mcts_fallback = enable_mcts_fallback
        self.mcts_engine = mcts_engine
        self.total_verifications = 0
        self.sat_count = 0
        self.unsat_count = 0
        self.unknown_count = 0
        self.mcts_fallback_count = 0
        self.mcts_success_count = 0
        self._warned_mcts_placeholder = False

    def _is_main_thread(self) -> bool:
        try:
            return threading.current_thread() is threading.main_thread()
        except Exception:
            return True

    def verify(self, formal_spec: FormalSpec) -> Z3VerificationResult:
        self.logger.info(f"[Z3Verifier] Verifying {formal_spec.hypothesis_id}")
        self.total_verifications += 1
        solver = Solver()
        timer = None

        if self._is_main_thread():
            try:
                solver.set("timeout", self.timeout_ms)
            except ValueError as e:
                self.logger.warning(f"[Z3Verifier] Could not set Z3 timeout: {e}")
        else:
            self.logger.info("[Z3Verifier] Running in worker thread - using Timer-based timeout fallback")
            def timeout_handler():
                self.logger.warning("[Z3Verifier] Timer timeout triggered in worker thread")
                try:
                    solver.interrupt()
                except Exception as e:
                    self.logger.warning(f"[Z3Verifier] Failed to interrupt solver: {e}")
            timer = threading.Timer(self.timeout_ms / 1000.0, timeout_handler)
            timer.start()

        self.z3_vars = {}
        self._safe_var_names = {}
        self._var_types = {}
        constraints_count = 0

        try:
            self._create_z3_variables(formal_spec.state_variables, solver)
            total_constraints = (len(formal_spec.preconditions) + sum(len(a.constraints) + len(a.state_changes) for a in formal_spec.actions) + len(formal_spec.postconditions) + len(formal_spec.economic_constraints))
            failed_constraints = 0

            for precond in formal_spec.preconditions:
                constraint = self._translate_constraint(precond)
                if constraint is not None:
                    solver.add(constraint)
                    constraints_count += 1
                else:
                    failed_constraints += 1

            for action in formal_spec.actions:
                for constraint in action.constraints:
                    z3_constraint = self._translate_constraint(constraint)
                    if z3_constraint is not None:
                        solver.add(z3_constraint)
                        constraints_count += 1
                    else:
                        failed_constraints += 1
                for change in action.state_changes:
                    z3_constraint = self._translate_state_change(change)
                    if z3_constraint is not None:
                        solver.add(z3_constraint)
                        constraints_count += 1
                    else:
                        failed_constraints += 1

            for postcond in formal_spec.postconditions:
                constraint = self._translate_constraint(postcond)
                if constraint is not None:
                    solver.add(constraint)
                    constraints_count += 1
                else:
                    failed_constraints += 1

            for econ_constraint in formal_spec.economic_constraints:
                constraint = self._translate_constraint(econ_constraint)
                if constraint is not None:
                    solver.add(constraint)
                    constraints_count += 1
                else:
                    failed_constraints += 1

            self.logger.info(f"[Z3Verifier] Added {constraints_count} constraints to solver")
            if failed_constraints > 0:
                self.logger.warning(f"[Z3Verifier] Failed to translate {failed_constraints}/{total_constraints} constraints ({failed_constraints/total_constraints*100:.1f}%)")

            failure_ratio = (failed_constraints / total_constraints) if total_constraints else 0.0
            max_failure_ratio = getattr(config, "Z3_MAX_FAILED_CONSTRAINT_RATIO", 0.0)
            if total_constraints > 0 and failure_ratio > max_failure_ratio:
                self.logger.error(f"[Z3Verifier] {failure_ratio:.0%} of constraints failed translation - formal spec is unreliable, returning UNKNOWN")
                return Z3VerificationResult(result=VerificationResult.UNKNOWN, confidence=0.0, model=None, attack_parameters={}, reasoning=f"[ERROR] Formal specification has malformed constraints ({failed_constraints}/{total_constraints} failed; ratio {failure_ratio:.2f}). Cannot reliably verify. Passing to adversarial critic.", solver_time=0.0, constraints_added=constraints_count)
            elif failed_constraints > 0:
                self.logger.info(f"[Z3Verifier] Continuing with degraded spec (failure ratio {failure_ratio:.2f} ≤ {max_failure_ratio:.2f})")

            import time
            start_time = time.time()
            result = solver.check()
            solve_time = time.time() - start_time

            if timer is not None:
                timer.cancel()

            self.logger.info(f"[Z3Verifier] Result: {result} (solved in {solve_time:.2f}s)")
            return self._process_result(result=result, solver=solver, formal_spec=formal_spec, solve_time=solve_time, constraints_count=constraints_count)

        except Exception as e:
            if timer is not None:
                timer.cancel()
            self.logger.error(f"[Z3Verifier] Verification failed: {e}")
            return Z3VerificationResult(result=VerificationResult.UNKNOWN, confidence=0.5, model=None, attack_parameters={}, reasoning=f"Z3 verification failed: {str(e)}", solver_time=0.0, constraints_added=constraints_count)

    def _create_z3_variables(self, state_vars: List[StateVariable], solver: Solver) -> None:
        for var in state_vars:
            z3_var, safe_name = self._create_z3_var(var.name, var.type)
            if z3_var is not None:
                self.z3_vars[var.name] = z3_var
                self._safe_var_names[var.name] = safe_name
                self._var_types[var.name] = var.type
                if var.initial_value and var.initial_value not in ['?', 'unknown', 'any']:
                    init_constraint = self._translate_constraint(f"{var.name} == {var.initial_value}")
                    if init_constraint is not None:
                        solver.add(init_constraint)
                if var.type.startswith('uint'):
                    solver.add(z3_var >= 0)

    def _create_z3_var(self, name: str, var_type: str) -> Tuple[Optional[Any], str]:
        safe_name = re.sub(r'[^\w]', '_', name)

        if var_type.startswith('uint') or var_type.startswith('int'):
            return z3.Int(safe_name), safe_name
        elif var_type == 'address':
            return BitVec(safe_name, 160), safe_name
        elif var_type == 'bool':
            return Bool(safe_name), safe_name
        elif var_type.startswith('mapping'):
            match = re.match(r'mapping\s*\(\s*(\w+)\s*=>\s*(\w+)\s*\)', var_type)
            if match:
                key_type, value_type = match.group(1), match.group(2)
                def _get_sort(t):
                    if t == 'address': return BitVecSort(160)
                    elif t == 'bytes32': return BitVecSort(256)
                    elif t.startswith('uint') or t.startswith('int'): return IntSort()
                    elif t == 'bool': return BitVecSort(8) if t == key_type else IntSort()
                    else: return BitVecSort(256)
                return Array(safe_name, _get_sort(key_type), _get_sort(value_type)), safe_name
            else:
                return Array(safe_name, BitVecSort(256), BitVecSort(256)), safe_name
        elif '[]' in var_type:
            elem_type = var_type.replace('[]', '').strip()
            if elem_type == 'address' or 'address' in elem_type: elem_sort = BitVecSort(160)
            elif elem_type.startswith('uint') or elem_type.startswith('int'): elem_sort = IntSort()
            elif elem_type.startswith('bytes'): elem_sort = BitVecSort(256)
            else: elem_sort = IntSort()
            return Array(safe_name, IntSort(), elem_sort), safe_name
        elif var_type.startswith('bytes'):
            bit_size = 256
            match = re.match(r"bytes(\d+)", var_type)
            if match:
                bit_size = max(8, min(int(match.group(1)) * 8, 256))
            return BitVec(safe_name, bit_size), safe_name
        else:
            self.logger.warning(f"[Z3Verifier] Unsupported type: {var_type} for {name}")
            return None, safe_name

    def _infer_variable_type(self, var_name: str) -> str:
        lower = var_name.lower()
        address_keywords = {"attacker", "attacker_address", "owner", "owner_address", "vault", "vault_address", "contract", "contract_address", "asset", "token", "token_address", "receiver", "receiver_address", "beneficiary", "beneficiary_address", "spender", "spender_address", "target", "target_address", "recipient", "recipient_address", "this", "erc20", "underlying_token", "underlying_asset", "pool_address", "caller"}
        if lower.endswith("_address") or lower in address_keywords or "address" in lower or lower.endswith("_token") or "contract" in lower:
            return "address"
        bool_prefixes = ("is_", "has_", "can_", "should_", "allow_", "enable_")
        bool_suffixes = ("_flag", "_guard", "_enabled", "_paused", "_allowed")
        bool_keywords = ("feasible", "feasibility", "valid", "validity", "possible", "success", "status", "achieved", "succeed", "succeeds")
        if lower.startswith(bool_prefixes) or lower.endswith(bool_suffixes) or any(keyword in lower for keyword in bool_keywords):
            return "bool"
        numeric_keywords = ("balance", "amount", "supply", "total", "fee", "deposit", "withdraw", "profit", "loss", "cost", "capital", "liquidity", "price", "value", "reserve", "shares", "tokens", "flashloan", "loan", "allowance", "funds", "assets", "shares", "reward", "debt", "stake", "limit", "threshold", "rate", "ratio", "gas")
        if any(keyword in lower for keyword in numeric_keywords):
            return "uint256"
        return "uint256"

    def _auto_declare_variable(self, var_name: str) -> bool:
        if var_name in self.z3_vars or var_name in self._safe_var_names.values():
            return True
        inferred_type = self._infer_variable_type(var_name)
        z3_var, safe_name = self._create_z3_var(var_name, inferred_type)
        if z3_var is None:
            return False
        self.z3_vars[var_name] = z3_var
        self._safe_var_names[var_name] = safe_name
        self._var_types[var_name] = inferred_type
        if hasattr(self.logger, "info"):
            self.logger.info(f"[Z3Verifier] Auto-declared variable '{var_name}' as {inferred_type}")
        return True

    def _normalize_constraint_text(self, constraint: str) -> str:
        if not isinstance(constraint, str):
            return constraint
        cleaned = constraint.strip()
        replacements = [(r"==\s*>=", ">="), (r"==\s*<=", "<="), (r"==\s*>", ">"), (r"==\s*<", "<"), (r"==\s*==", "=="), (r"==\s*!=", "!="), (r"!=\s*==", "!="), (r"!=\s*!=", "!="), (r"<=\s*==", "<="), (r">=\s*==", ">="), (r"<\s*=", "<="), (r">\s*=", ">="), (r"==\s*none\b", "== None"), (r"!=\s*none\b", "!= None"), (r"\bTrue\b", "True"), (r"\bFalse\b", "False")]
        for pattern, replacement in replacements:
            cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"([A-Za-z0-9_]+)'s\s+([A-Za-z0-9_]+)", r"\1_\2", cleaned)
        cleaned = cleaned.replace("'", "_")
        text_replacements = [(r"address\s*\(\s*this\s*\)", "contract_address"), (r"address\s*\(\s*0\s*\)", "zero_address"), (r"\btotalAssets\s*\(\s*\)", "total_assets"), (r"\btotalSupply\s*\(\s*\)", "total_supply"), (r"\bERC20\s+token\s+address\b", "token_address"), (r"\bERC20\b", "token"), (r"\bvalid\s+token\b", "token"), (r"\basset\s+address\b", "asset_address"), (r"\bcontract\s+address\b", "contract_address"), (r"\bcontract\s+owner\b", "contract_owner"), (r"\bunderlying\s+token\b", "underlying_token"), (r"\btoken\s+of\s+vault\b", "token"), (r"\bat\s+that\s+point\b", ""), (r"\bsome\s+fixed\s+address\b", "fixed_address"), (r"\b([A-Za-z0-9_]+)\s+contract_address\b", r"\1_contract_address"), (r"\bunderlying\s+token_address\b", "underlying_token_address"), (r"\b([A-Za-z0-9_]+)\s+address\b", r"\1_address"), (r"\b[A-Za-z0-9_]+\s*==\s*And\(", "And("), (r"\btoken\s+hooks\b", "token_hooks"), (r"\((?P<tag>[A-Za-z0-9_]+)\)", lambda m: "_" + m.group("tag")), (r"\b([A-Za-z0-9_]+)_s\s+([A-Za-z0-9_]+)\b", r"\1_\2"), (r"([A-Za-z_])\.(?=[A-Za-z0-9_])", r"\1_"), (r"\b([A-Za-z0-9_]*(?:address|token|asset))\s*!=\s*0\b", r"\1 != zero_address"), (r"\b0\s*!=\s*([A-Za-z0-9_]*(?:address|token|asset))\b", r"zero_address != \1"), (r"\b([A-Za-z0-9_]*(?:address|token|asset))\s*==\s*0\b", r"\1 == zero_address"), (r"\b0\s*==\s*([A-Za-z0-9_]*(?:address|token|asset))\b", r"zero_address == \1"), (r"==\s*distinct\s+from", "!="), (r"\bdistinct\s+from\b", "!="), (r"\btoken\s+with\s+fee-on-transfer\b", "token"), (r"\bwith\s+fee-on-transfer\b", ""), (r"\b([A-Za-z0-9_]+)\s+returns\s+([A-Za-z0-9_().]+)\b", lambda m: f"{m.group(1)} == {m.group(2)}")]
        for pattern, replacement in text_replacements:
            cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"(?<=\w)-(?=\w)", "_", cleaned)
        prev = None
        while prev != cleaned:
            prev = cleaned
            cleaned = re.sub(r"address\s*\(\s*([A-Za-z0-9_\.]+)\s*\)", r"\1", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s+for\s+[A-Za-z0-9_]+$", "", cleaned)
        if "->" in cleaned and cleaned.count("->") == 1:
            lhs, rhs = cleaned.split("->", 1)
            cleaned = f"Implies(({lhs.strip()}), ({rhs.strip()}))"
        cleaned = re.sub(r"(\b[A-Za-z0-9_]+\b)\s*(>|>=|<|<=)\s*(\b[A-Za-z0-9_]+\b)\s*(==|!=|>|>=|<|<=)\s*([^&|]+)", lambda m: f"And({m.group(1)} {m.group(2)} {m.group(3)}, {m.group(3)} {m.group(4)} {m.group(5)})", cleaned)
        cleaned = re.sub(r"(\d+(?:\.\d+)?)\s*ether", lambda m: str(int((Decimal(m.group(1)) * (10 ** 18)).to_integral_value())), cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"(\d+(?:\.\d+)?)e(\d+)", lambda m: str(int((Decimal(m.group(1)) * (10 ** int(m.group(2)))).to_integral_value())), cleaned, flags=re.IGNORECASE)
        bracket_pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([^\[\]]+)\s*\]")
        prev = None
        while prev != cleaned:
            prev = cleaned
            cleaned = bracket_pattern.sub(r"Select(\1, \2)", cleaned)
        call_select_pattern = re.compile(r"([A-Za-z_][A-Za-z0-9_]*\([^()\[\]]*\))\s*\[\s*([^\[\]]+)\s*\]")
        prev = None
        while prev != cleaned:
            prev = cleaned
            cleaned = call_select_pattern.sub(r"Select(\1, \2)", cleaned)
        if "=>" in cleaned:
            parts = re.split(r"\s*=>\s*", cleaned)
            if len(parts) >= 2:
                implied_expr = parts[-1].strip()
                for antecedent in reversed(parts[:-1]):
                    antecedent = antecedent.strip()
                    if not antecedent:
                        continue
                    implied_expr = f"Implies({antecedent}, {implied_expr})"
                cleaned = implied_expr
        cleaned = re.sub(r"new\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:\([^)]*\))?", "new_instance", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned

    def _validate_constraint_syntax(self, constraint: str) -> Tuple[bool, str]:
        if not constraint or not constraint.strip():
            return False, "Empty constraint"
        stripped = constraint.strip()
        operator_pattern = r'^[\+\-\*/\%<>=!&\|\^]+|[\+\-\*/\%<>=!&\|\^]+$'
        if re.match(operator_pattern, stripped):
            return False, f"Constraint starts with operator (partial expression)"
        if re.search(r'[\+\-\*/\%]$', stripped):
            return False, f"Constraint ends with operator (partial expression)"
        if stripped.startswith('/') and not stripped.startswith('//'):
            return False, "Constraint starts with division operator"
        assignment_ops = ['+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<=', '>>=']
        for op in assignment_ops:
            if op in constraint:
                return False, f"Assignment operator '{op}' not allowed in constraints"
        if '==' in constraint and '>' in constraint:
            if '== >' in constraint or '== <' in constraint:
                return False, f"Malformed comparison operator (spaces in '== >')"
        var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
        used_vars = set(re.findall(var_pattern, constraint))
        keywords = {'and', 'or', 'not', 'True', 'False', 'None', 'And', 'Or', 'Not', 'If', 'Select', 'Store', 'ULE', 'ULT', 'UGT', 'UGE', 'Concat', 'Extract', 'ZeroExt', 'SignExt', 'BVAdd', 'BVSub', 'BVMul', 'UDiv', 'URem'}
        used_vars -= keywords
        defined_vars = {re.sub(r'[^\w]', '_', orig) for orig in self._safe_var_names.keys()}
        undefined_vars = used_vars - defined_vars
        undefined_vars = {v for v in undefined_vars if not v.isdigit()}
        auto_declared: List[str] = []
        for var in list(undefined_vars):
            if self._auto_declare_variable(var):
                defined_vars.add(re.sub(r'[^\w]', '_', var))
                auto_declared.append(var)
                undefined_vars.remove(var)
        if undefined_vars:
            return False, f"Undefined variables: {', '.join(sorted(undefined_vars))}"
        return True, ""

    def _translate_constraint(self, constraint: str) -> Optional[Any]:
        expr = constraint
        try:
            constraint = self._normalize_constraint_text(constraint)
            is_valid, error_msg = self._validate_constraint_syntax(constraint)
            if not is_valid:
                self.logger.warning(f"[Z3Verifier] Invalid constraint syntax '{constraint}': {error_msg}")
                return None
            expr = constraint
            for original_name, safe_name in self._safe_var_names.items():
                expr = re.sub(r'\b' + re.escape(original_name) + r'\b', safe_name, expr)
            expr = expr.replace('&&', ' and ')
            expr = expr.replace('||', ' or ')
            expr = expr.replace('//', '/')
            expr = re.sub(r'!\s*(?!=)', ' not ', expr)
            if any(isinstance(v, z3.BitVecRef) for v in self.z3_vars.values()):
                pass
            expr = self._coerce_bitvec_numeric_literals(expr)
            local_vars = {safe_name: self.z3_vars[orig] for orig, safe_name in self._safe_var_names.items()}
            local_vars.update({'and': And, 'or': Or, 'not': Not, 'And': And, 'Or': Or, 'Not': Not, 'Implies': z3.Implies, 'If': z3.If, 'UGE': z3.UGE, 'UGT': z3.UGT, 'ULE': z3.ULE, 'ULT': z3.ULT, 'Select': z3.Select, 'Store': z3.Store, 'BitVecVal': BitVecVal, 'zero_address': z3.BitVecVal(0, 160)})
            z3_expr = self._safe_eval_expr(expr, local_vars)
            if not z3.is_expr(z3_expr):
                self.logger.warning(f"[Z3Verifier] Ignoring non-Z3 expression for '{constraint}'")
                return None
            if not z3.is_bool(z3_expr):
                self.logger.warning(f"[Z3Verifier] Ignoring non-boolean constraint '{constraint}' → {z3_expr}")
                return None
            return z3_expr
        except Exception as e:
            self.logger.warning(f"[Z3Verifier] Failed to translate constraint '{constraint}': {e}; expr='{expr}'")
            return None

    def _translate_state_change(self, state_change: str) -> Optional[Any]:
        return self._translate_constraint(state_change)

    def _bitvec_width_for_type(self, var_type: Optional[str]) -> Optional[int]:
        if not var_type:
            return None
        var_type = var_type.lower()
        if var_type == 'address':
            return 160
        if var_type.startswith('bytes'):
            match = re.match(r"bytes(\d+)", var_type)
            if match:
                return max(8, min(int(match.group(1)) * 8, 256))
            return 256
        return None

    def _safe_eval_expr(self, expr: str, local_vars: Dict[str, Any]) -> Any:
        try:
            tree = ast.parse(expr, mode='eval')
        except SyntaxError as e:
            raise ValueError(f"Invalid expression syntax: {e}")
        return self._eval_ast_node(tree.body, local_vars)

    def _eval_ast_node(self, node: ast.AST, local_vars: Dict[str, Any]) -> Any:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (int, float, bool, str)):
                return node.value
            raise ValueError(f"Disallowed constant type: {type(node.value)}")
        if isinstance(node, ast.Name):
            if node.id in local_vars:
                return local_vars[node.id]
            raise ValueError(f"Unknown variable: {node.id}")
        if isinstance(node, ast.BinOp):
            left = self._eval_ast_node(node.left, local_vars)
            right = self._eval_ast_node(node.right, local_vars)
            ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow, ast.BitOr: operator.or_, ast.BitAnd: operator.and_, ast.BitXor: operator.xor, ast.LShift: operator.lshift, ast.RShift: operator.rshift}
            op_type = type(node.op)
            if op_type not in ops:
                raise ValueError(f"Disallowed binary operator: {op_type.__name__}")
            return ops[op_type](left, right)
        if isinstance(node, ast.UnaryOp):
            operand = self._eval_ast_node(node.operand, local_vars)
            ops = {ast.UAdd: operator.pos, ast.USub: operator.neg, ast.Not: operator.not_, ast.Invert: operator.inv}
            op_type = type(node.op)
            if op_type not in ops:
                raise ValueError(f"Disallowed unary operator: {op_type.__name__}")
            return ops[op_type](operand)
        if isinstance(node, ast.Compare):
            left = self._eval_ast_node(node.left, local_vars)
            result = None
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval_ast_node(comparator, local_vars)
                ops = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge}
                op_type = type(op)
                if op_type not in ops:
                    raise ValueError(f"Disallowed comparison: {op_type.__name__}")
                comp_result = ops[op_type](left, right)
                if result is None:
                    result = comp_result
                else:
                    result = And(result, comp_result) if z3.is_expr(result) else result and comp_result
                left = right
            return result
        if isinstance(node, ast.BoolOp):
            values = [self._eval_ast_node(v, local_vars) for v in node.values]
            if isinstance(node.op, ast.And):
                if any(z3.is_expr(v) for v in values):
                    return And(*values)
                return all(values)
            elif isinstance(node.op, ast.Or):
                if any(z3.is_expr(v) for v in values):
                    return Or(*values)
                return any(values)
            raise ValueError(f"Disallowed boolean operator: {type(node.op).__name__}")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
                if func_name not in local_vars:
                    raise ValueError(f"Unknown function: {func_name}")
                func = local_vars[func_name]
            elif isinstance(node.func, ast.Attribute):
                obj = self._eval_ast_node(node.func.value, local_vars)
                attr = node.func.attr
                if not hasattr(obj, attr):
                    raise ValueError(f"Unknown attribute: {attr}")
                func = getattr(obj, attr)
            else:
                raise ValueError(f"Disallowed function call type: {type(node.func)}")
            args = [self._eval_ast_node(arg, local_vars) for arg in node.args]
            kwargs = {kw.arg: self._eval_ast_node(kw.value, local_vars) for kw in node.keywords}
            return func(*args, **kwargs)
        if isinstance(node, ast.Attribute):
            obj = self._eval_ast_node(node.value, local_vars)
            attr = node.attr
            if not hasattr(obj, attr):
                raise ValueError(f"Unknown attribute: {attr}")
            return getattr(obj, attr)
        if isinstance(node, ast.Subscript):
            obj = self._eval_ast_node(node.value, local_vars)
            if isinstance(node.slice, ast.Index):
                idx = self._eval_ast_node(node.slice.value, local_vars)
            else:
                idx = self._eval_ast_node(node.slice, local_vars)
            if z3.is_array(obj):
                return z3.Select(obj, idx)
            return obj[idx]
        if isinstance(node, ast.Tuple):
            return tuple(self._eval_ast_node(elt, local_vars) for elt in node.elts)
        if isinstance(node, ast.List):
            return [self._eval_ast_node(elt, local_vars) for elt in node.elts]
        if isinstance(node, ast.IfExp):
            test = self._eval_ast_node(node.test, local_vars)
            body = self._eval_ast_node(node.body, local_vars)
            orelse = self._eval_ast_node(node.orelse, local_vars)
            if z3.is_expr(test) or z3.is_expr(body) or z3.is_expr(orelse):
                return z3.If(test, body, orelse)
            return body if test else orelse
        raise ValueError(f"Disallowed AST node type: {type(node).__name__}")

    def _coerce_bitvec_numeric_literals(self, expr: str) -> str:
        if not expr or not self._safe_var_names:
            return expr
        bitvec_widths: Dict[str, int] = {}
        for original_name, safe_name in self._safe_var_names.items():
            var_type = self._var_types.get(original_name)
            bit_width = self._bitvec_width_for_type(var_type)
            if bit_width:
                bitvec_widths[safe_name] = bit_width
        if not bitvec_widths:
            return expr
        numeric_pattern = r"-?(?:0x[0-9a-fA-F]+|\d+)"
        def replace_var_literal(match: re.Match) -> str:
            var_name = match.group('var')
            width = bitvec_widths.get(var_name)
            if not width:
                return match.group(0)
            literal = match.group('value')
            if 'BitVecVal' in literal:
                return match.group(0)
            return f"{var_name} {match.group('op')} BitVecVal({literal}, {width})"
        def replace_literal_var(match: re.Match) -> str:
            var_name = match.group('var')
            width = bitvec_widths.get(var_name)
            if not width:
                return match.group(0)
            literal = match.group('value')
            if 'BitVecVal' in literal:
                return match.group(0)
            return f"BitVecVal({literal}, {width}) {match.group('op')} {var_name}"
        var_literal_pattern = re.compile(rf"(?P<var>\b\w+\b)\s*(?P<op>==|!=|>=|<=|>|<)\s*(?P<value>{numeric_pattern})")
        literal_var_pattern = re.compile(rf"(?P<value>{numeric_pattern})\s*(?P<op>==|!=|>=|<=|>|<)\s*(?P<var>\b\w+\b)")
        expr = var_literal_pattern.sub(replace_var_literal, expr)
        expr = literal_var_pattern.sub(replace_literal_var, expr)
        return expr

    def _process_result(self, result: z3.CheckSatResult, solver: Solver, formal_spec: FormalSpec, solve_time: float, constraints_count: int) -> Z3VerificationResult:
        if result == sat:
            self.sat_count += 1
            model = solver.model()
            attack_params = self._extract_attack_parameters(model)
            return Z3VerificationResult(result=VerificationResult.SAT, confidence=0.99, model=model, attack_parameters=attack_params, reasoning=f"[OK] Attack is FORMALLY PROVABLE. Z3 found a satisfying model with {len(attack_params)} concrete attack parameters. This attack is logically sound and should be exploitable.", solver_time=solve_time, constraints_added=constraints_count)
        elif result == unsat:
            self.unsat_count += 1
            return Z3VerificationResult(result=VerificationResult.UNSAT, confidence=0.05, model=None, attack_parameters={}, reasoning=f"[ERROR] Attack is IMPOSSIBLE. Z3 proved that no satisfying assignment exists. The attack hypothesis contains logical contradictions or impossible preconditions. This should be REJECTED.", solver_time=solve_time, constraints_added=constraints_count)
        else:
            self.unknown_count += 1
            if self.enable_mcts_fallback:
                self.logger.info("[Z3Verifier] Z3 returned UNKNOWN, trying MCTS fallback...")
                self.mcts_fallback_count += 1
                mcts_result = self._try_mcts_fallback(formal_spec)
                if mcts_result is not None:
                    return mcts_result
            return Z3VerificationResult(result=VerificationResult.UNKNOWN, confidence=0.5, model=None, attack_parameters={}, reasoning=f"[WARNING] Z3 solver returned UNKNOWN (timeout or undecidable). Solver ran for {solve_time:.2f}s with {constraints_count} constraints. {'MCTS fallback also failed. ' if self.enable_mcts_fallback else ''}Passing to adversarial critic for manual verification.", solver_time=solve_time, constraints_added=constraints_count)

    def _extract_attack_parameters(self, model: z3.ModelRef) -> Dict[str, Any]:
        params = {}
        for decl in model.decls():
            var_name = decl.name()
            var_value = model[decl]
            try:
                if z3.is_int_value(var_value):
                    params[var_name] = var_value.as_long()
                elif z3.is_bv_value(var_value):
                    params[var_name] = var_value.as_long()
                elif z3.is_bool(var_value):
                    params[var_name] = z3.is_true(var_value)
                else:
                    params[var_name] = str(var_value)
            except Exception as e:
                self.logger.warning(f"[Z3Verifier] Failed to extract {var_name}: {e}")
                params[var_name] = str(var_value)
        return params

    def _try_mcts_fallback(self, formal_spec: FormalSpec) -> Optional[Z3VerificationResult]:
        if not self._warned_mcts_placeholder:
            self.logger.warning("[Z3Verifier] MCTS fallback is not implemented (requires contract ABI, project root, and MCTS engine components). Passing to adversarial critic.")
            self._warned_mcts_placeholder = True
        return None

    def get_statistics(self) -> Dict[str, Any]:
        total = self.total_verifications
        return {'total_verifications': total, 'sat_count': self.sat_count, 'unsat_count': self.unsat_count, 'unknown_count': self.unknown_count, 'mcts_fallback_count': self.mcts_fallback_count, 'mcts_success_count': self.mcts_success_count, 'sat_rate': self.sat_count / total if total > 0 else 0.0, 'unsat_rate': self.unsat_count / total if total > 0 else 0.0, 'unknown_rate': self.unknown_count / total if total > 0 else 0.0, 'mcts_success_rate': self.mcts_success_count / self.mcts_fallback_count if self.mcts_fallback_count > 0 else 0.0}
