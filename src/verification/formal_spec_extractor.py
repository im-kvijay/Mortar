"""formal spec extractor - convert attack hypotheses into formal specifications"""

from typing import List, Dict, Any, Optional, Tuple
from decimal import Decimal
from dataclasses import dataclass
import json
from json import JSONDecoder
import re

from config import config
from utils.llm_backend.base import LLMBackend
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager
from agent.base_attacker import AttackHypothesis
from utils.source_snippets import gather_relevant_snippets
from pydantic import BaseModel, Field


@dataclass
class StateVariable:
    """State variable with name, type, initial_value, description"""
    name: str
    type: str
    initial_value: str
    description: str


@dataclass
class Action:
    """Transaction step with function, caller, parameters, state_changes, constraints"""
    step_num: int
    function_name: str
    caller: str
    parameters: Dict[str, str]
    state_changes: List[str]
    constraints: List[str]


@dataclass
class FormalSpec:
    """Formal spec output for Z3 verifier"""
    hypothesis_id: str
    state_variables: List[StateVariable]
    preconditions: List[str]
    actions: List[Action]
    postconditions: List[str]
    invariants_to_check: List[str]
    economic_constraints: List[str]
    extraction_confidence: float
    notes: str


class _StateVariableModel(BaseModel):
    name: str = Field(..., description="State variable identifier (snake_case only)")
    type: str
    initial_value: str
    description: str


class _ActionModel(BaseModel):
    step_num: int
    function_name: str
    caller: str
    parameters: Dict[str, str]
    state_changes: List[str]
    constraints: List[str]


class _FormalSpecResponse(BaseModel):
    state_variables: List[_StateVariableModel]
    preconditions: List[str]
    actions: List[_ActionModel]
    postconditions: List[str]
    invariants_to_check: List[str]
    economic_constraints: List[str]
    extraction_confidence: float = Field(ge=0.0, le=1.0)
    notes: str


class FormalSpecExtractor:
    """Extracts formal specs from attack hypotheses using LLM"""

    def __init__(
        self,
        backend: LLMBackend,
        logger: ResearchLogger,
        cost_manager: CostManager
    ):
        self.backend = backend
        self.logger = logger
        self.cost_manager = cost_manager
        self._system_prompt = self._build_system_prompt()

    @staticmethod
    def _normalize_expression(value: Any) -> Any:
        """Clean up formatting in constraint strings"""
        if not isinstance(value, str):
            return value

        cleaned = value.strip()

        replacements = [
            (r"==\s*>=", ">="),
            (r"==\s*<=", "<="),
            (r"==\s*>", ">"),
            (r"==\s*<", "<"),
            (r"==\s*==", "=="),
            (r"==\s*!=", "!="),
            (r"!=\s*==", "!="),
            (r"!=\s*!=", "!="),
            (r"<=\s*==", "<="),
            (r">=\s*==", ">="),
            (r"==\s*none\b", "== None"),
            (r"!=\s*none\b", "!= None"),
        ]

        for pattern, replacement in replacements:
            cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)

        cleaned = re.sub(r"([A-Za-z0-9_]+)'s\s+([A-Za-z0-9_]+)", r"\1_\2", cleaned).replace("'", "_")

        address_replacements = [
            (r"address\s*\(\s*this\s*\)", "contract_address"),
            (r"address\s*\(\s*0\s*\)", "zero_address"),
            (r"\btotalAssets\s*\(\s*\)", "total_assets"),
            (r"\btotalSupply\s*\(\s*\)", "total_supply"),
            (r"\bERC20\s+token\s+address\b", "token_address"),
            (r"\bERC20\b", "token"),
            (r"\bvalid\s+token\b", "token"),
            (r"\basset\s+address\b", "asset_address"),
            (r"\bcontract\s+address\b", "contract_address"),
            (r"\bcontract\s+owner\b", "contract_owner"),
            (r"\bunderlying\s+token\b", "underlying_token"),
            (r"\btoken\s+of\s+vault\b", "token"),
            (r"\bat\s+that\s+point\b", ""),
            (r"\bsome\s+fixed\s+address\b", "fixed_address"),
            (r"\b([A-Za-z0-9_]+)\s+contract_address\b", r"\1_contract_address"),
            (r"\bunderlying\s+token_address\b", "underlying_token_address"),
            (r"\b([A-Za-z0-9_]+)\s+address\b", r"\1_address"),
        ]
        for pattern, replacement in address_replacements:
            cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)
        def _bool_rewrite(match: re.Match) -> str:
            lhs = match.group(1).strip()
            op = match.group(2).lower()
            rhs = match.group(3).strip()
            fn = "Or" if op == "or" else "And"
            return f"{fn}({lhs}, {rhs})"

        cleaned = re.sub(
            r"\b([A-Za-z0-9_]+)\s+(or|and)\s+([A-Za-z0-9_]+)\b",
            _bool_rewrite,
            cleaned,
            flags=re.IGNORECASE,
        )
        cleaned = re.sub(r"\bnot\s+([A-Za-z0-9_]+)\b", r"Not(\1)", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\b[A-Za-z0-9_]+\s*==\s*And\(", "And(", cleaned)
        cleaned = re.sub(r"\btoken\s+hooks\b", "token_hooks", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\((?P<tag>[A-Za-z0-9_]+)\)", lambda m: "_" + m.group("tag"), cleaned)
        more_replacements = [
            (r"\b([A-Za-z0-9_]+)_s\s+([A-Za-z0-9_]+)\b", r"\1_\2"),
            (r"([A-Za-z_])\.(?=[A-Za-z0-9_])", r"\1_"),
            (r"\b([A-Za-z0-9_]*(?:address|token|asset))\s*!=\s*0\b", r"\1 != zero_address"),
            (r"\b0\s*!=\s*([A-Za-z0-9_]*(?:address|token|asset))\b", r"zero_address != \1"),
            (r"\b([A-Za-z0-9_]*(?:address|token|asset))\s*==\s*0\b", r"\1 == zero_address"),
            (r"\b0\s*==\s*([A-Za-z0-9_]*(?:address|token|asset))\b", r"zero_address == \1"),
            (r"==\s*distinct\s+from", "!="),
            (r"\bdistinct\s+from\b", "!="),
            (r"\btoken\s+with\s+fee-on-transfer\b", "token"),
            (r"\bwith\s+fee-on-transfer\b", ""),
        ]
        for pattern, replacement in more_replacements:
            cleaned = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(
            r"\b([A-Za-z0-9_]+)\s+returns\s+([A-Za-z0-9_().]+)\b",
            lambda m: f"{m.group(1)} == {m.group(2)}",
            cleaned,
            flags=re.IGNORECASE
        )

        def _rewrite_chain(match: re.Match) -> str:
            left, op1, middle, op2, right = match.groups()
            return f"And({left} {op1} {middle}, {middle} {op2} {right})"

        cleaned = re.sub(
            r"(\b[A-Za-z0-9_]+\b)\s*(>|>=|<|<=)\s*(\b[A-Za-z0-9_]+\b)\s*(==|!=|>|>=|<|<=)\s*([^&|]+)",
            _rewrite_chain,
            cleaned
        )

        cleaned = re.sub(
            r"(\d+(?:\.\d+)?)\s*ether",
            lambda m: str(int((Decimal(m.group(1)) * (10 ** 18)).to_integral_value())),
            cleaned,
            flags=re.IGNORECASE
        )
        cleaned = re.sub(
            r"(\d+(?:\.\d+)?)e(\d+)",
            lambda m: str(int((Decimal(m.group(1)) * (10 ** int(m.group(2)))).to_integral_value())),
            cleaned,
            flags=re.IGNORECASE
        )

        cleaned = re.sub(r"\s+", " ", cleaned)
        cleaned = re.sub(r"\s+[Oo][Rr]\s+", " Or ", cleaned)
        cleaned = re.sub(r"\s+[Aa][Nn][Dd]\s+", " And ", cleaned)
        cleaned = re.sub(r"\s+[Nn][Oo][Tt]\s+", " Not ", cleaned)
        cleaned = re.sub(r"\s*\((?:[^()]*[A-Za-z][^()]*?)\)\s*", " ", cleaned)

        is_valid = (re.search(r"(==|!=|>=|<=|>|<|[+\-*/])", cleaned) or
                    any(tok in cleaned for tok in ("And(", "Or(", "Not(")) or
                    re.search(r"[A-Za-z_][A-Za-z0-9_]*\s*\(", cleaned))
        if not is_valid and cleaned.lower() not in {"true", "false"}:
            return ""

        return cleaned.strip()

    @staticmethod
    def _contains_disallowed_tokens(expr: str) -> Optional[str]:
        """Scan for unsupported Z3 constructs or prose"""
        lowered = expr.lower()
        if "keccak256" in lowered or "sha256" in lowered:
            return "Hash functions not supported; use concrete equality."
        if " bytes32[" in lowered or " bytes[" in lowered or "bytes32[]" in lowered or "bytes[]" in lowered:
            return "bytes/bytes32 arrays not supported; use scalars or explicit indices."
        if "no economic impact" in lowered or "fake sender" in lowered or "placeholder" in lowered:
            return "Inline prose detected; use only boolean/arithmetic relations."
        if re.search(r"\b(or|and|not)\b(?!\s*\()", lowered):
            return "Use Or()/And()/Not() instead of textual 'or/and/not'."
        return None

    def extract(self, hypothesis: AttackHypothesis, contract_source: str, contract_info: Dict[str, Any]) -> FormalSpec:
        """Extract formal spec from attack hypothesis for Z3 verification"""
        self.logger.info(f"[FormalSpecExtractor] Extracting formal spec for {hypothesis.hypothesis_id}")

        if not self.backend.supports_structured_outputs():
            self.logger.info("[FormalSpecExtractor] Using JSON fallback extraction")
            return self._extract_with_json_fallback(hypothesis, contract_source, contract_info)

        retry_feedback: Optional[str] = None
        last_spec: Optional[FormalSpec] = None
        issues: List[str] = []

        for attempt in range(1, 4):
            prompt = self._build_extraction_prompt(
                hypothesis=hypothesis,
                contract_source=contract_source,
                contract_info=contract_info,
                retry_feedback=retry_feedback,
            )

            response, parsed_obj = self.backend.generate_structured(
                prompt=prompt,
                response_model=_FormalSpecResponse,
                system_prompt=self._system_prompt,
                max_tokens=config.MAX_OUTPUT_TOKENS,
                temperature=min(config.NORMAL_TEMPERATURE, 0.35),
                force_reset=True,
            )

            self.cost_manager.log_cost(
                agent_name="FormalSpecExtractor",
                contract_name=contract_info.get("name", "Unknown"),
                round_num=0,
                operation="formal_spec_extraction",
                cost=response.cost
            )

            try:
                formal_spec = self._model_to_spec(parsed_obj, hypothesis)
            except Exception as exc:
                issues = [f"Failed to parse structured response: {exc}"]
                retry_feedback = self._format_feedback(issues)
                continue

            issues = self._lint_formal_spec(formal_spec)
            if not issues:
                self.logger.info(
                    f"[FormalSpecExtractor] Extracted: {len(formal_spec.state_variables)} vars, "
                    f"{len(formal_spec.actions)} actions, confidence {formal_spec.extraction_confidence:.2f}"
                )
                return formal_spec

            last_spec = formal_spec
            retry_feedback = self._format_feedback(issues)
            self.logger.warning(
                f"[FormalSpecExtractor] Spec attempt {attempt} contained {len(issues)} syntax issues; retrying."
            )

        if last_spec is None:
            self.logger.warning("[FormalSpecExtractor] All extraction attempts failed - using fallback")
            return self._create_fallback_spec(hypothesis, contract_info)

        self.logger.warning(f"[FormalSpecExtractor] Final retry with simplified prompt after {len(issues)} issues")
        simplified_spec = self._extract_with_simplified_prompt(hypothesis, contract_source, contract_info)
        simplified_issues = self._lint_formal_spec(simplified_spec)

        if not simplified_issues:
            self.logger.info("[FormalSpecExtractor] Simplified extraction succeeded")
            return simplified_spec

        self.logger.warning(f"[FormalSpecExtractor] Simplified retry failed - using fallback")
        return self._create_fallback_spec(hypothesis, contract_info)

    def _extract_with_json_fallback(self, hypothesis: AttackHypothesis, contract_source: str, contract_info: Dict[str, Any]) -> FormalSpec:
        """Fallback extraction using plain text + JSON parsing for backends without structured output"""
        retry_feedback: Optional[str] = None
        last_spec: Optional[FormalSpec] = None
        issues: List[str] = []

        for attempt in range(1, 4):
            prompt = self._build_extraction_prompt(
                hypothesis=hypothesis,
                contract_source=contract_source,
                contract_info=contract_info,
                retry_feedback=retry_feedback,
            )

            response = self.backend.generate(
                prompt=prompt,
                system_prompt=self._system_prompt,
                max_tokens=config.MAX_OUTPUT_TOKENS,
                temperature=min(config.NORMAL_TEMPERATURE, 0.35),
            )

            self.cost_manager.log_cost(
                agent_name="FormalSpecExtractor",
                contract_name=contract_info.get("name", "Unknown"),
                round_num=0,
                operation="formal_spec_extraction_fallback",
                cost=response.cost
            )

            try:
                formal_spec = self._parse_extraction_response(response.text, hypothesis)
            except Exception as exc:
                issues = [f"Failed to parse JSON response: {exc}"]
                retry_feedback = self._format_feedback(issues)
                continue

            issues = self._lint_formal_spec(formal_spec)
            if not issues:
                self.logger.info(
                    f"[FormalSpecExtractor] Extracted (fallback): {len(formal_spec.state_variables)} vars, "
                    f"{len(formal_spec.actions)} actions, confidence {formal_spec.extraction_confidence:.2f}"
                )
                return formal_spec

            last_spec = formal_spec
            retry_feedback = self._format_feedback(issues)
            self.logger.warning(
                f"[FormalSpecExtractor] Fallback spec attempt {attempt} contained {len(issues)} syntax issues; retrying."
            )

        if last_spec is None:
            raise ValueError("FormalSpecExtractor (fallback) failed to produce usable spec.")

        self.logger.warning(f"[FormalSpecExtractor] Fallback spec has lint issues: {'; '.join(issues[:5])}")
        raise ValueError("FormalSpecExtractor (fallback) could not produce clean spec after retries.")

    _FORBIDDEN_EXPR_PATTERNS = [
        (re.compile(r"\bempty\s+array\b", re.IGNORECASE), "Use length == 0 not 'empty array'."),
        (re.compile(r"\bfor\s+all\b", re.IGNORECASE), "No quantifiers; enumerate concrete indices."),
        (re.compile(r"\bno\s+validation\b", re.IGNORECASE), "No prose; use boolean variables."),
        (re.compile(r"\barbitrary\b", re.IGNORECASE), "No 'arbitrary'; declare concrete variable."),
        (re.compile(r"\bnew_instance\b", re.IGNORECASE), "No placeholder names; declare real variable."),
        (re.compile(r"\bexpected_price\b", re.IGNORECASE), "No vague placeholders; declare concrete variables."),
        (re.compile(r"\b(or|and|not)\s+(?![A-Z]|\()", re.IGNORECASE), "Use Or()/And()/Not() not textual 'or/and/not'."),
        (re.compile(r"\([A-Za-z\s,]+\)\s*(?![=!<>])", re.IGNORECASE), "No inline prose; remove comments like '(fake sender)'."),
        (re.compile(r"\bkeccak256\s*\(", re.IGNORECASE), "keccak256 not supported; use equality to declared constant."),
        (re.compile(r"\bbytes32\[\s*\]|\bbytes\[\s*\]", re.IGNORECASE), "bytes/bytes32 arrays not supported; use scalars."),
        (re.compile(r"\bSelect\s*\(", re.IGNORECASE), "Select() not supported; declare separate variables per key."),
        (re.compile(r"\bStore\s*\(", re.IGNORECASE), "Store() not supported; declare separate variables per key."),
        (re.compile(r"\b(caller|success|owner|user)\s+(?=\w)", re.IGNORECASE), "Bare word suggests prose; use snake_case."),
    ]

    def _extract_with_simplified_prompt(self, hypothesis: AttackHypothesis, contract_source: str, contract_info: Dict[str, Any]) -> FormalSpec:
        """Simplified extraction - last attempt before fallback"""
        minimal_prompt = {
            "schema_version": "2025-02-FormalSpec-Minimal",
            "command": "extract_minimal_spec",
            "hypothesis": {
                "id": hypothesis.hypothesis_id,
                "type": hypothesis.attack_type,
                "target": hypothesis.target_function,
                "steps": hypothesis.steps[:3] if hypothesis.steps else [],
            },
            "instructions": "Extract: 2+ state vars, 1+ actions, 1+ postcondition. Simple expressions only."
        }

        response = self.backend.generate(
            prompt=json.dumps(minimal_prompt, indent=2),
            system_prompt="Extract minimal spec. snake_case only, simple expressions (==, >, <, +, -).",
            max_tokens=2000,
            temperature=0.1,
        )

        self.cost_manager.log_cost(
            agent_name="FormalSpecExtractor",
            contract_name=contract_info.get("name", "Unknown"),
            round_num=0,
            operation="formal_spec_simplified",
            cost=response.cost
        )

        try:
            return self._parse_extraction_response(response.text, hypothesis)
        except Exception as e:
            self.logger.warning(f"[FormalSpecExtractor] Simplified extraction failed: {e}")
            return self._create_fallback_spec(hypothesis, contract_info)

    def _create_fallback_spec(self, hypothesis: AttackHypothesis, contract_info: Dict[str, Any]) -> FormalSpec:
        """Create minimal fallback spec when extraction fails"""
        self.logger.info("[FormalSpecExtractor] Creating fallback template spec")

        target_fn = hypothesis.target_function or "unknown"
        if '(' in target_fn:
            target_fn = target_fn.split('(')[0]

        state_vars = [
            StateVariable(
                name="attacker_address",
                type="address",
                initial_value="attacker_address != zero_address",
                description="Attacker address"
            ),
            StateVariable(
                name="profit",
                type="uint256",
                initial_value="0",
                description="Attacker profit"
            ),
        ]

        if "balance" in hypothesis.description.lower() or "funds" in hypothesis.description.lower():
            state_vars.append(StateVariable(
                name="balance_before",
                type="uint256",
                initial_value="balance_before > 0",
                description="Balance before attack"
            ))
            state_vars.append(StateVariable(
                name="balance_after",
                type="uint256",
                initial_value="0",
                description="Balance after attack"
            ))

        actions = []
        if hypothesis.steps:
            actions.append(Action(
                step_num=1,
                function_name=target_fn,
                caller="attacker_address",
                parameters={"amount": "amount_param"},
                state_changes=["balance_after == balance_before"],
                constraints=["amount_param > 0"]
            ))
        else:
            actions.append(Action(
                step_num=1,
                function_name=target_fn,
                caller="attacker_address",
                parameters={},
                state_changes=[],
                constraints=[]
            ))

        return FormalSpec(
            hypothesis_id=hypothesis.hypothesis_id,
            state_variables=state_vars,
            preconditions=["attacker_address != zero_address"],
            actions=actions,
            postconditions=["profit > 0"],
            invariants_to_check=[],
            economic_constraints=["profit > 0"],
            extraction_confidence=0.3,
            notes="Fallback template - LLM extraction failed"
        )

    def _build_extraction_prompt(self, hypothesis: AttackHypothesis, contract_source: str, contract_info: Dict[str, Any], retry_feedback: Optional[str] = None) -> str:
        """Build JSON extraction request payload"""
        extra_candidates = [
            (sig or "").split("(", 1)[0]
            for sig in (contract_info.get("external_functions") or [])[:5]
        ]
        snippets = gather_relevant_snippets(
            contract_source=contract_source,
            target_function=hypothesis.target_function or "",
            steps=hypothesis.steps or [],
            extra_candidates=extra_candidates,
        )

        payload = {
            "schema_version": "2025-02-FormalSpec",
            "command": "extract_formal_spec",
            "contract": {
                "name": contract_info.get("name", "Unknown"),
                "key_functions": contract_info.get("external_functions", [])[:25],
                "path": contract_info.get("path"),
                "total_functions": contract_info.get("total_functions"),
            },
            "hypothesis": {
                "id": hypothesis.hypothesis_id,
                "type": hypothesis.attack_type,
                "target": hypothesis.target_function,
                "description": hypothesis.description,
                "steps": hypothesis.steps,
                "preconditions": hypothesis.preconditions,
                "expected_impact": hypothesis.expected_impact,
            },
            "source_snippets": [
                {"label": label, "code": snippet}
                for label, snippet in snippets
            ],
            "contract_source_excerpt": contract_source[:4000],
        }
        if retry_feedback:
            payload["retry_feedback"] = retry_feedback

        return json.dumps(payload, ensure_ascii=False, indent=2)

    def _build_system_prompt(self) -> str:
        return """Convert attack hypothesis to Z3-compatible formal spec. Return ONLY valid JSON.

SCHEMA:
{"state_variables": [{"name": "var", "type": "uint256|address|bool", "initial_value": "expr", "description": "text"}],
 "preconditions": ["expr"], "actions": [{"step_num": 1, "function_name": "fn", "caller": "attacker", "parameters": {"p": "val"}, "state_changes": ["s_after == s_before + x"], "constraints": ["x > 0"]}],
 "postconditions": ["profit > 0"], "invariants_to_check": ["supply_before == supply_after"], "economic_constraints": ["gas < profit"], "extraction_confidence": 0.95, "notes": "summary"}

Z3 RULES:
- Allowed: ==, !=, <, <=, >, >=, +, -, *, /, %, And(), Or(), Not(), Implies()
- snake_case identifiers only (balance_before, total_supply_after)
- Literals: integers, True, False
- Mappings: separate vars per key (finalized_before_leaf1, finalized_after_leaf1)

FORBIDDEN:
- English: 'or', 'and', 'not', 'all', 'any', 'arbitrary', 'fake', 'some', 'empty'
- Comments: '(fake sender)', '(no validation)'
- Hash functions: keccak256(), sha256()
- Dynamic types: bytes[], bytes32[], string
- Spaces in identifiers
- Select()/Store() for mappings

Min requirements: 3+ state_vars, 1+ action, preconditions, postconditions. ALL constraints must be valid Z3 Python."""

    def _lint_formal_spec(self, spec: FormalSpec) -> List[str]:
        issues: List[str] = []

        if not spec.actions:
            issues.append("Spec has zero actions; need at least one transaction step.")
        if spec.state_variables is not None and len(spec.state_variables) == 0:
            issues.append("Spec has no state variables; need concrete variables.")

        allowed_identifiers = set()
        for var in spec.state_variables:
            allowed_identifiers.add(var.name)
        for action in spec.actions:
            allowed_identifiers.update((action.parameters or {}).keys())
        allowed_identifiers.update({"zero_address", "contract_address", "contract_owner", "underlying_token", "total_assets", "total_supply"})

        for var in spec.state_variables:
            if " " in var.name:
                issues.append(f"State variable '{var.name}' has spaces; use snake_case.")

        def _check(exprs: List[str], ctx: str):
            for expr in exprs or []:
                issues.extend(self._lint_expression(expr, ctx, allowed_identifiers))

        _check(spec.preconditions, "precondition")
        _check(spec.postconditions, "postcondition")
        _check(spec.invariants_to_check, "invariant")
        _check(spec.economic_constraints, "economic_constraint")

        for action in spec.actions:
            _check(action.state_changes, f"action_{action.step_num}_state_change")
            _check(action.constraints, f"action_{action.step_num}_constraint")

        return issues

    def _model_to_spec(self, model: _FormalSpecResponse, hypothesis: AttackHypothesis) -> FormalSpec:
        return FormalSpec(
            hypothesis_id=hypothesis.hypothesis_id,
            state_variables=[
                StateVariable(
                    name=sv.name,
                    type=sv.type,
                    initial_value=sv.initial_value,
                    description=sv.description,
                )
                for sv in model.state_variables
            ],
            preconditions=model.preconditions or [],
            actions=[
                Action(
                    step_num=action.step_num,
                    function_name=action.function_name,
                    caller=action.caller,
                    parameters=action.parameters or {},
                    state_changes=action.state_changes or [],
                    constraints=action.constraints or [],
                )
                for action in model.actions
            ],
            postconditions=model.postconditions or [],
            invariants_to_check=model.invariants_to_check or [],
            economic_constraints=model.economic_constraints or [],
            extraction_confidence=float(model.extraction_confidence or 0.0),
            notes=model.notes or "",
        )

    def _lint_expression(self, expr: Any, context: str, allowed_identifiers: Optional[set] = None) -> List[str]:
        if not isinstance(expr, str) or not expr.strip():
            return []

        stripped = expr.strip()
        problems: List[str] = []

        for pattern, message in self._FORBIDDEN_EXPR_PATTERNS:
            if pattern.search(stripped):
                problems.append(f"{context}: {message} Expression: `{stripped}`")

        if re.search(r"\b[A-Za-z0-9_]+\s+[A-Za-z0-9_]+\b", stripped):
            problems.append(f"{context}: No spaces in identifiers. Expression: `{stripped}`")

        disallowed = self._contains_disallowed_tokens(stripped)
        if disallowed:
            problems.append(f"{context}: {disallowed} Expression: `{stripped}`")

        token_words = re.findall(r"[A-Za-z_][A-Za-z_]*", stripped)
        allowed_fns = {"And", "Or", "Not", "Implies", "Select", "Store", "True", "False", "None"}
        for word in token_words:
            if word in allowed_fns or (allowed_identifiers and word in allowed_identifiers):
                continue
            if word.isalpha() and "_" not in word:
                problems.append(f"{context}: Bare word '{word}' suggests prose; use snake_case. Expression: `{stripped}`")
                break

        return problems

    @staticmethod
    def _format_feedback(issues: List[str]) -> str:
        if not issues:
            return ""
        trimmed = issues[:8]
        body = "\n".join(f"- {issue}" for issue in trimmed)
        if len(issues) > 8:
            body += f"\n- ...and {len(issues) - 8} more."
        return body

    def _parse_extraction_response(self, response: str, hypothesis: AttackHypothesis) -> FormalSpec:
        """Parse JSON response into FormalSpec"""
        try:
            decoder = JSONDecoder()
            data = None
            for idx, ch in enumerate(response):
                if ch != "{":
                    continue
                try:
                    data, end = decoder.raw_decode(response[idx:])
                    break
                except json.JSONDecodeError:
                    continue
            if data is None:
                raise json.JSONDecodeError("No JSON object found", response, 0)

            state_vars = [
                StateVariable(
                    name=var['name'],
                    type=var['type'],
                    initial_value=self._normalize_expression(var['initial_value']),
                    description=var['description']
                )
                for var in data.get('state_variables', [])
            ]

            actions = [
                Action(
                    step_num=act['step_num'],
                    function_name=act['function_name'],
                    caller=act['caller'],
                    parameters={
                        key: self._normalize_expression(value)
                        for key, value in act.get('parameters', {}).items()
                    },
                    state_changes=[
                        self._normalize_expression(change)
                        for change in act.get('state_changes', [])
                    ],
                    constraints=[
                        self._normalize_expression(constraint)
                        for constraint in act.get('constraints', [])
                    ]
                )
                for act in data.get('actions', [])
            ]

            return FormalSpec(
                hypothesis_id=hypothesis.hypothesis_id,
                state_variables=state_vars,
                preconditions=[
                    self._normalize_expression(pre)
                    for pre in data.get('preconditions', [])
                ],
                actions=actions,
                postconditions=[
                    self._normalize_expression(post)
                    for post in data.get('postconditions', [])
                ],
                invariants_to_check=[
                    self._normalize_expression(inv)
                    for inv in data.get('invariants_to_check', [])
                ],
                economic_constraints=[
                    self._normalize_expression(constraint)
                    for constraint in data.get('economic_constraints', [])
                ],
                extraction_confidence=float(data.get('extraction_confidence', 0.5)),
                notes=self._normalize_expression(data.get('notes', ''))
            )

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            self.logger.warning(f"[FormalSpecExtractor] Parse failed: {e}")
            return FormalSpec(
                hypothesis_id=hypothesis.hypothesis_id,
                state_variables=[],
                preconditions=[],
                actions=[],
                postconditions=[],
                invariants_to_check=[],
                economic_constraints=[],
                extraction_confidence=0.0,
                notes=f"Parse failed: {str(e)}"
            )
