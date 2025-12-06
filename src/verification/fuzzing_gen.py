"""
FuzzingGen: converts invariants into Foundry invariant handlers.

This is a lightweight generator to keep quick iterations safe. Execution
should be guarded by budget/time flags in callers.
"""
from __future__ import annotations

from pathlib import Path
from typing import List
import subprocess
import re


class FuzzingGenerator:
    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)

    def _qualify_invariant(self, invariant: str, contract_var: str = "target") -> str:
        """
        Prefix bare identifiers in an invariant expression with the contract variable.
        Keeps literals/keywords/operators untouched.
        """
        tokens = set()
        for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", invariant):
            tokens.add(match.group(1))

        keywords = {
            "true",
            "false",
            "this",
            "require",
            "assert",
            "if",
            "else",
            "return",
            "for",
            "while",
        }

        qualified = invariant
        for tok in sorted(tokens, key=len, reverse=True):
            low = tok.lower()
            if low in keywords or tok.startswith(contract_var + ".") or tok.startswith(contract_var + "("):
                continue
            # Avoid double-qualifying anything already target.<id>
            qualified = re.sub(rf"\b{tok}\b", f"{contract_var}.{tok}", qualified)
        return qualified

    def _parse_constructor_args(self, import_path: str) -> str:
        """
        Derive default constructor args from source. Best-effort.
        """
        src_file = self.project_root / import_path
        if not src_file.exists():
            try_path = Path(import_path)
            if try_path.exists():
                src_file = try_path
        try:
            content = src_file.read_text(encoding="utf-8")
        except Exception:
            return ""
        match = re.search(r"constructor\s*\(([^)]*)\)", content, re.MULTILINE)
        if not match:
            return ""
        params_raw = match.group(1).strip()
        if not params_raw:
            return ""
        parts = [p.strip() for p in params_raw.split(",") if p.strip()]
        defaults: List[str] = []
        for part in parts:
            tokens = part.split()
            if not tokens:
                continue
            ptype = tokens[0]
            defaults.append(self._default_for_type(ptype))
        return ", ".join(defaults)

    def _default_for_type(self, ptype: str) -> str:
        ptype = ptype.strip()
        if ptype.startswith("address"):
            return "address(0)"
        if ptype.startswith("bool"):
            return "false"
        if ptype.startswith("string") or ptype.startswith("bytes"):
            return "\"\""
        if re.match(r"u?int", ptype):
            return "0"
        if ptype.endswith("[]"):
            base = ptype[:-2]
            return f"new {base}[](0)"
        # Fallback numeric literal
        return "0"

    def generate_handler(
        self,
        contract_name: str,
        invariants: List[str],
        prefix: str = "InvariantFuzz",
        source_import: str | None = None
    ) -> Path:
        """
        Generate a minimal Foundry invariant test file for the given invariants.

        Args:
            contract_name: target contract
            invariants: list of invariant expressions as strings
            prefix: test contract prefix
            source_import: optional import path for the target contract (relative to project root or absolute)

        Returns:
            Path to the generated .sol file
        """
        if not invariants:
            raise ValueError("generate_handler requires at least one invariant")
        if not source_import:
            raise ValueError("generate_handler requires source_import for contract wiring")

        import_path = source_import
        try:
            # Prefer project-relative import if possible
            src_path = Path(source_import)
            if src_path.is_absolute():
                import_path = str(src_path.relative_to(self.project_root))
        except Exception:
            pass

        # Parse constructor args from source for wiring
        ctor_args = self._parse_constructor_args(import_path)

        handler_name = f"{prefix}_{contract_name}"
        out_dir = self.project_root / "out" / "fuzzing"
        out_dir.mkdir(parents=True, exist_ok=True)
        file_path = out_dir / f"{handler_name}.t.sol"
        invariant_blocks = []
        for i, inv in enumerate(invariants):
            qualified = self._qualify_invariant(inv)
            invariant_blocks.append(f"    function invariant_{i}() public {{ assert({qualified}); }}")
        invariant_section = "\n".join(invariant_blocks)

        template = f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;
import "forge-std/Test.sol";
import "{import_path}";

contract {handler_name} is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}({ctor_args});
    }}

{invariant_section}
}}
"""
        file_path.write_text(template, encoding="utf-8")
        return file_path

    def run_fuzz(self, handler_path: Path, timeout: int = 60) -> bool:
        """
        Execute forge test on the generated handler.
        Returns True if tests pass.
        """
        try:
            # Execute from repository root so remappings/foundry.toml apply
            relpath = handler_path.relative_to(self.project_root)
            result = subprocess.run(
                ["forge", "test", "-q", "--match-path", str(relpath)],
                cwd=str(self.project_root),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode == 0
        except Exception:
            return False
