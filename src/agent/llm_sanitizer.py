# spdx-license-identifier: mit
"""module docstring"""
import re
from typing import Optional

ALLOWED_IMPORT_FRAGMENTS = (
    "forge-std/Test.sol",
    "openzeppelin/",
    "@uniswap/v3-core/",
    "@uniswap/v3-periphery/",
    "src/poc/modules/",
    "pocmods/",
    "src/poc/ExploitTestBase.sol",
    "poc/ExploitTestBase.sol",
)

FORBIDDEN_PATTERNS = (
    r"handlers?/",
    r"training/.*/handlers?/",
)

RE_VM_LEGACY = re.compile(r"\bt\.vm\b")
RE_PRANK = re.compile(r"\b(startPrank|stopPrank)\b")
RE_PRAGMA = re.compile(r"^\s*pragma\s+solidity\s+[^;]+;", re.MULTILINE)


def _ensure_pragma(code: str) -> str:
    if RE_PRAGMA.search(code):
        return RE_PRAGMA.sub("pragma solidity >=0.8.15 <0.9.0;", code, count=1)
    return "pragma solidity >=0.8.15 <0.9.0;\n" + code


def _filter_imports(code: str) -> str:
    cleaned: list[str] = []
    for line in code.splitlines():
        stripped = line.strip()
        if stripped.startswith("import"):
            if any(re_pattern in stripped for re_pattern in FORBIDDEN_PATTERNS):
                continue
            if not any(allow in stripped for allow in ALLOWED_IMPORT_FRAGMENTS):
                continue
        cleaned.append(line)
    return "\n".join(cleaned)


def sanitize_poc(code: str) -> str:
    """
    Normalise PoC source prior to compilation.
    """
    code = _ensure_pragma(code)
    code = _filter_imports(code)

    if "forge-std/Test.sol" not in code:
        code = 'import "forge-std/Test.sol";\n' + code

    hevm_import = 'import {Vm, VM} from "src/poc/support/Hevm.sol";'
    if hevm_import not in code:
        code = hevm_import + "\n" + code

    code = RE_VM_LEGACY.sub("VM", code)
    code = RE_PRANK.sub("/* prank sanitized */", code)

    return code
