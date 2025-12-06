# spdx-license-identifier: mit
"""module docstring"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import config

_SETUP_HEADER_PATTERN = re.compile(
    r"(function\s+setUp\s*\(\s*\)\s+public)(\s+virtual)?(?!\s+override)([^{]*\{)",
    flags=re.MULTILINE,
)


def _ensure_setup_override(code: str) -> Tuple[str, bool]:
    """Inject `override` into `setUp()` if missing."""
    new_code, count = _SETUP_HEADER_PATTERN.subn(r"\1 override\3", code)
    return new_code, bool(count)


def _insert_super_setup(code: str) -> Tuple[str, bool]:
    """
    Ensure `super.setUp();` exists as the first statement inside setUp().

    The insertion is idempotent — if the call already exists within the
    function body we leave the code untouched.
    """
    marker = "function setUp"
    start = 0
    changed = False
    while True:
        idx = code.find(marker, start)
        if idx == -1:
            break
        brace_idx = code.find("{", idx)
        if brace_idx == -1:
            break

        # locate the matching closing brace so we can scope the search.
        depth = 0
        end_idx = None
        for pos in range(brace_idx, len(code)):
            ch = code[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end_idx = pos
                    break
        if end_idx is None:
            # malformed solidity; bail
            break

        body = code[brace_idx + 1 : end_idx]
        if "super.setUp();" not in body:
            line_start = code.rfind("\n", 0, idx)
            if line_start == -1:
                line_start = 0
            indent = code[line_start + 1 : idx]
            indent = re.match(r"\s*", indent).group(0)
            insertion = f"\n{indent}    super.setUp();"
            code = code[: brace_idx + 1] + insertion + code[brace_idx + 1 :]
            changed = True
            # adjust end index to account for insertion
            end_idx += len(insertion)
        start = end_idx if end_idx is not None else idx + len(marker)
    return code, changed


def _resolve_contract_source(contract_info: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(contract_info, dict):
        return None
    path_str = contract_info.get("path") or contract_info.get("file_path")
    if not path_str:
        return None
    path = Path(path_str)
    if not path.is_absolute():
        path = Path(config.PROJECT_ROOT) / path
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _maybe_fix_grant_role(code: str, contract_source: Optional[str], error_blob: str) -> Tuple[str, bool]:
    """
    Solady's OwnableRoles exposes `grantRoles(address,uint256)` instead of the
    OpenZeppelin-style `grantRole(bytes32,address)`. LLM PoCs often call the
    wrong helper, which produces the compiler diagnostic observed in DVD
    exploit suites.

    We only rewrite the call if BOTH of the following are true:
      * the target contract source contains `grantRoles(` but not `grantRole(`
      * the compiler error explicitly mentioned `grantRole`
    """
    if "grantRole" not in error_blob:
        return code, False
    if not contract_source:
        return code, False
    uses_solady_roles = (
        "OwnableRoles" in contract_source
        or "grantRoles(" in contract_source
        or "_grantRoles(" in contract_source
    )
    source_has_singular = "grantRole(" in contract_source
    if not uses_solady_roles or source_has_singular:
        return code, False
    if ".grantRole(" not in code:
        return code, False
    new_code = code.replace(".grantRole(", ".grantRoles(")
    return new_code, new_code != code


def _maybe_swap_grant_roles_args(code: str, error_blob: str) -> Tuple[str, bool]:
    if "grantRoles" not in error_blob:
        return code, False
    if "Invalid type for argument" not in error_blob:
        return code, False

    pattern = re.compile(r"(\.grantRoles\s*\()\s*([^,]+?)\s*,\s*([^,)]+?)(\))")

    def _looks_like_role(expr: str) -> bool:
        token = re.sub(r"[\s()]", "", expr)
        return "ROLE" in token.upper() or token.isupper()

    def _swap(match: re.Match) -> str:
        first = match.group(2).strip()
        second = match.group(3).strip()
        if not _looks_like_role(first):
            return match.group(0)
        return f"{match.group(1)}{second}, {first}{match.group(4)}"

    new_code, count = pattern.subn(_swap, code)
    return new_code, count > 0


def _maybe_fix_constant_getters(code: str, error_blob: str) -> Tuple[str, bool]:
    if "function () view external returns" not in error_blob:
        return code, False

    pattern = re.compile(r"(\b[A-Za-z_][A-Za-z0-9_]*\.[A-Z0-9_]{2,})(?!\s*\()")

    def _append_call(match: re.Match) -> str:
        return match.group(1) + "()"

    new_code, count = pattern.subn(_append_call, code)
    return new_code, count > 0


def _maybe_fix_memory_calldata(code: str, error_blob: str) -> Tuple[str, bool]:
    """
    Fix missing memory/calldata keywords for dynamic types in function parameters.
    LLMs often forget these keywords for string, bytes, arrays.
    """
    if "Data location must be" not in error_blob and "storage" not in error_blob.lower():
        return code, False

    # pattern for function parameters missing memory/calldata
    # e.g., string name -> string memory name
    dynamic_types = r"(string|bytes|bytes32\[\]|uint256\[\]|address\[\]|uint\[\])"
    pattern = re.compile(
        rf"(\(\s*|,\s*){dynamic_types}(\s+)([a-zA-Z_][a-zA-Z0-9_]*)",
        flags=re.MULTILINE
    )

    def _add_memory(match: re.Match) -> str:
        prefix = match.group(1)
        type_name = match.group(2)
        space = match.group(3)
        var_name = match.group(4)
        return f"{prefix}{type_name} memory{space}{var_name}"

    new_code, count = pattern.subn(_add_memory, code)
    return new_code, count > 0


def _maybe_fix_visibility_order(code: str, error_blob: str) -> Tuple[str, bool]:
    """
    Fix visibility keyword ordering. Solidity requires: visibility mutability override.
    LLMs sometimes put these in wrong order.
    """
    if "Expected ';'" not in error_blob and "visibility specifier" not in error_blob.lower():
        return code, False

    # fix: public override -> public override (order is: visibility, mutability, override)
    # common mistake: override public -> public override
    pattern = re.compile(r"\b(override)\s+(public|external|internal|private)\b")
    new_code, count = pattern.subn(r"\2 \1", code)

    # also fix: view public -> public view
    pattern2 = re.compile(r"\b(view|pure)\s+(public|external|internal|private)\b")
    new_code, count2 = pattern2.subn(r"\2 \1", new_code)

    return new_code, count > 0 or count2 > 0


def _maybe_fix_constructor_visibility(code: str, error_blob: str) -> Tuple[str, bool]:
    """
    Remove visibility from constructor (post-Solidity 0.7).
    LLMs trained on old code sometimes add `public` to constructors.
    """
    if "constructor" not in error_blob.lower():
        return code, False

    # fix: constructor() public { -> constructor() {
    pattern = re.compile(r"constructor\s*\([^)]*\)\s+(public|internal)\s*(\{|payable)")
    new_code, count = pattern.subn(r"constructor() \2", code)
    return new_code, count > 0


def _maybe_fix_interface_calls(code: str, error_blob: str, contract_info: Optional[Dict[str, Any]]) -> Tuple[str, bool]:
    """
    Fix incorrect interface method calls by checking against ABI.
    LLMs often use wrong function names or call non-existent methods.
    """
    if not contract_info:
        return code, False

    abi = contract_info.get("abi", [])
    if not abi:
        return code, False

    # extract function names from abi
    abi_functions = set()
    for item in abi:
        if isinstance(item, dict) and item.get("type") == "function":
            abi_functions.add(item.get("name", ""))

    if not abi_functions:
        return code, False

    # check for "not found" or "undeclared identifier" errors mentioning function names
    changed = False
    new_code = code

    # common llm mistakes: withdraw vs withdrawall, transfer vs safetransfer
    common_fixes = {
        "withdrawAll": "withdraw",
        "safeTransfer": "transfer",
        "safeTransferFrom": "transferFrom",
        "transferOwner": "transferOwnership",
        "setOwner": "transferOwnership",
        "removeOwner": "renounceOwnership",
    }

    for wrong, correct in common_fixes.items():
        if wrong in error_blob and correct in abi_functions:
            pattern = re.compile(rf"\.{wrong}\s*\(")
            if pattern.search(new_code):
                new_code = pattern.sub(f".{correct}(", new_code)
                changed = True

    return new_code, changed


def _maybe_fix_import_path(code: str, error_blob: str) -> Tuple[str, bool]:
    """
    Fix common import path issues.
    """
    if "Source" not in error_blob or "not found" not in error_blob:
        return code, False

    changed = False
    new_code = code

    # fix @openzeppelin paths (llms often use npm-style imports)
    if "@openzeppelin" in code:
        # replace npm-style imports with local lib paths
        new_code = re.sub(
            r'import\s+[{]?[^}]*[}]?\s+from\s+"@openzeppelin/contracts/([^"]+)"',
            r'import "lib/openzeppelin-contracts/contracts/\1"',
            new_code
        )
        changed = new_code != code

    return new_code, changed


def _maybe_fix_assert_eq(code: str, error_blob: str) -> Tuple[str, bool]:
    """
    Fix assert_eq -> assertEq (Rust style vs Foundry style).
    """
    if "assert_eq" not in code:
        return code, False

    new_code = code.replace("assert_eq!(", "assertEq(")
    new_code = new_code.replace("assert_eq(", "assertEq(")
    return new_code, new_code != code


def _maybe_fix_emit_syntax(code: str, error_blob: str) -> Tuple[str, bool]:
    """
    Fix emit syntax issues - LLMs sometimes forget `emit` keyword.
    """
    if "Expected ';'" not in error_blob:
        return code, False

    # pattern for event calls without emit keyword
    # this is heuristic - looks for capitalized identifier followed by ( that's not a function call
    event_pattern = re.compile(r"^\s+([A-Z][a-zA-Z0-9_]*)\s*\(", re.MULTILINE)

    # only apply if there's a matching event definition
    if "event " not in code:
        return code, False

    # find event names
    event_names = set(re.findall(r"event\s+([A-Z][a-zA-Z0-9_]*)\s*\(", code))
    if not event_names:
        return code, False

    def _add_emit(match: re.Match) -> str:
        name = match.group(1)
        if name in event_names:
            return f"    emit {name}("
        return match.group(0)

    new_code = event_pattern.sub(_add_emit, code)
    return new_code, new_code != code


def apply_poc_fixers(
    code: str,
    error_blob: str,
    contract_info: Optional[Dict[str, Any]] = None,
) -> Tuple[str, List[str]]:
    """
    Attempt deterministic fixes for known compilation issues.

    Returns the possibly-modified code and a list describing the fixes applied.
    The caller can decide whether to retry compilation based on the list.
    """
    applied: List[str] = []
    updated = code

    updated, changed = _ensure_setup_override(updated)
    if changed:
        applied.append("add_setUp_override")

    updated, changed = _insert_super_setup(updated)
    if changed:
        applied.append("insert_super_setUp")

    contract_source = _resolve_contract_source(contract_info)
    updated, changed = _maybe_fix_grant_role(updated, contract_source, error_blob)
    if changed:
        applied.append("rewrite_grantRoles")

    updated, changed = _maybe_swap_grant_roles_args(updated, error_blob)
    if changed:
        applied.append("swap_grantRoles_args")

    updated, changed = _maybe_fix_constant_getters(updated, error_blob)
    if changed:
        applied.append("call_constant_getter")

    # new fixers for common llm mistakes
    updated, changed = _maybe_fix_memory_calldata(updated, error_blob)
    if changed:
        applied.append("fix_memory_calldata")

    updated, changed = _maybe_fix_visibility_order(updated, error_blob)
    if changed:
        applied.append("fix_visibility_order")

    updated, changed = _maybe_fix_constructor_visibility(updated, error_blob)
    if changed:
        applied.append("fix_constructor_visibility")

    updated, changed = _maybe_fix_interface_calls(updated, error_blob, contract_info)
    if changed:
        applied.append("fix_interface_calls")

    updated, changed = _maybe_fix_import_path(updated, error_blob)
    if changed:
        applied.append("fix_import_path")

    updated, changed = _maybe_fix_assert_eq(updated, error_blob)
    if changed:
        applied.append("fix_assert_eq")

    updated, changed = _maybe_fix_emit_syntax(updated, error_blob)
    if changed:
        applied.append("fix_emit_syntax")

    if "Source file requires different compiler version" in error_blob or "pragma solidity" not in code:
        if "pragma solidity" not in updated:
            updated = "pragma solidity 0.8.25;\n" + updated
            applied.append("add_pragma_0_8_25")

    return updated, applied
