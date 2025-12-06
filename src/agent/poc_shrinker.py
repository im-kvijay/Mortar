"""module docstring"""

from __future__ import annotations

import re
from typing import Callable, List, Tuple


def _partition_by_steps(code: str) -> Tuple[List[str], List[Tuple[int, int]]]:
    """Return lines and step ranges (start,end inclusive) based on "// Step N" markers."""
    lines = code.splitlines()
    indices = [i for i, ln in enumerate(lines) if re.match(r"^\s*//\s*Step\s+\d+", ln)]
    if not indices:
        return lines, []
    ranges: List[Tuple[int, int]] = []
    for idx, start in enumerate(indices):
        end = indices[idx + 1] - 1 if idx + 1 < len(indices) else len(lines) - 1
        ranges.append((start, end))
    return lines, ranges


def shrink_greedy(test_code: str, probe: Callable[[str], bool]) -> str:
    lines, ranges = _partition_by_steps(test_code)
    if not ranges:
        return test_code  # Nothing to shrink deterministically

    kept = list(ranges)
    changed = True
    while changed:
        changed = False
        for i in range(len(kept)):
            candidate = kept[:i] + kept[i + 1 :]
            # build code without the i-th chunk
            chunks = []
            last = 0
            for (s, e) in candidate:
                chunks.extend(lines[last:s])
                chunks.extend(lines[s : e + 1])
                last = e + 1
            chunks.extend(lines[last:])
            new_code = "\n".join(chunks)
            if probe(new_code):
                kept = candidate
                lines = new_code.splitlines()
                changed = True
                break
    return "\n".join(lines)

