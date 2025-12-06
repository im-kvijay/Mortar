"""extract solidity function bodies for llm prompts"""

from __future__ import annotations

import re
from typing import Iterable, List, Sequence, Tuple


def _normalize_name(name: str) -> str:
    """bare identifier before parameter list"""
    return (name or "").split("(", 1)[0].strip()


def _extract_block(source: str, start_idx: int) -> str:
    """extract solidity block with brace matching"""
    brace_idx = source.find("{", start_idx)
    if brace_idx == -1:
        return source[start_idx:start_idx + 400]

    depth = 0
    i = brace_idx
    while i < len(source):
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start_idx:i + 1]
        i += 1

    return source[start_idx:min(len(source), start_idx + 800)]


def _find_function_block(source: str, func_name: str) -> str | None:
    """extract full function definition"""
    if not func_name:
        return None

    pattern = re.compile(rf"\bfunction\s+{re.escape(func_name)}\b")
    match = pattern.search(source)
    if not match:
        return None
    return _extract_block(source, match.start())


def _candidate_names_from_steps(steps: Sequence[str]) -> List[str]:
    """extract function names from hypothesis steps"""
    names: List[str] = []
    func_pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for step in steps:
        for match in func_pattern.findall(step or ""):
            names.append(match)
    return names


def gather_relevant_snippets(
    contract_source: str,
    target_function: str,
    steps: Sequence[str],
    extra_candidates: Iterable[str] | None = None,
    max_snippets: int = 5,
    max_chars_per_snippet: int = 1400,
) -> List[Tuple[str, str]]:
    """collect solidity function bodies relevant to attack hypothesis"""
    ordered_names: List[str] = []

    def _append(name: str) -> None:
        name = _normalize_name(name)
        if name and name not in ordered_names:
            ordered_names.append(name)

    _append(target_function)
    for name in _candidate_names_from_steps(steps):
        _append(name)
    if extra_candidates:
        for name in extra_candidates:
            _append(name)

    snippets: List[Tuple[str, str]] = []
    for name in ordered_names:
        if len(snippets) >= max_snippets:
            break
        block = _find_function_block(contract_source, name)
        if not block:
            continue
        snippet = block.strip()
        if len(snippet) > max_chars_per_snippet:
            snippet = snippet[: max_chars_per_snippet - 3].rstrip() + "..."
        snippets.append((name, snippet))

    return snippets
