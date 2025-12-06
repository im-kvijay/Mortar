from __future__ import annotations

from pathlib import Path
from datetime import datetime, UTC
from typing import Any, Dict, Tuple
import subprocess


def _tool_versions() -> Tuple[str, str, str]:
    def _run(cmd: list[str]) -> str:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return (p.stdout or p.stderr or "").strip()
        except Exception:
            return "unknown"

    forge_v = _run(["forge", "--version"]).splitlines()[0] if _run(["forge", "--version"]) else "forge unknown"
    solc_v = _run(["solc", "--version"]).splitlines()[0] if _run(["solc", "--version"]) else "solc unknown"
    git_sha = _run(["git", "rev-parse", "--short", "HEAD"]) or "git unknown"
    return forge_v, solc_v, git_sha


def build_bug_report(
    impact_report: Any,
    poc_path: Path,
    execution_stdout: str,
    sandbox_root: Path | None = None,
    test_relpath: str | None = None,
    mode: str = "local",
    artifact_path: Path | None = None,
    determinism: Dict[str, Any] | None = None,
    impact_vectors: Dict[str, bool] | None = None,
    failure_reason: str | None = None,
    plan_path: Path | None = None,
) -> str:
    title = getattr(impact_report, "title", None) or "Vulnerability Report"
    severity = getattr(impact_report, "severity", None)
    severity_str = getattr(severity, "value", None) if severity else str(severity or "")
    summary = getattr(impact_report, "summary", None) or getattr(impact_report, "reasoning", "")
    econ = getattr(impact_report, "economic_impact_usd", 0.0)

    code_lang = "solidity"
    code: str
    try:
        code = Path(poc_path).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            raw = Path(poc_path).read_bytes()
            code = raw.hex()
            if len(code) > 2048:
                code = code[:2048] + "…"
            code_lang = "text"
        except Exception:
            code = f"<unable to read PoC at {poc_path}>"
            code_lang = "text"
    except Exception:
        code = f"<unable to read PoC at {poc_path}>"
        code_lang = "text"

    stdout_head = (execution_stdout or "").strip().splitlines()
    stdout_head = "\n".join(stdout_head[:30])

    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    repro_cmd = "forge test -vvv"
    repro_extra = []
    if sandbox_root:
        repro_extra.append(f"-C {sandbox_root}")
    if test_relpath:
        repro_extra.append(f"--match-path {test_relpath}")
    if repro_extra:
        repro_cmd = f"forge test {' '.join(repro_extra)} -vvv"

    env_note = (
        "PoC executed in a local sandbox (no public testnet/mainnet)."
        if mode != "fork" else "PoC executed against a local fork."
    )
    forge_v, solc_v, git_sha = _tool_versions()

    determinism = determinism or {}
    determ_lines = "\n".join(f"- {k}: {v}" for k, v in determinism.items()) or "- Not recorded"

    vectors = impact_vectors or {}
    vector_lines = "\n".join(f"- {k}: {'YES' if state else 'no'}" for k, state in vectors.items() if state) or "- None (profit-only)"

    failure_section = f"\nFailure Reason\n{failure_reason}\n" if failure_reason else ""

    autoplan_section = ""
    plan_path = plan_path or (poc_path if poc_path.suffix.lower() == ".bin" else None)
    if plan_path and plan_path.exists():
        try:
            raw = plan_path.read_bytes()
            preview = raw[:256].hex()
            autoplan_section = f"\nAutoPoC Plan ({plan_path.name})\n```text\n{preview}{'…' if len(raw) > 256 else ''}\n```\n"
        except Exception:
            autoplan_section = f"\nAutoPoC Plan\nUnable to read plan bytes at {plan_path}\n"

    md = f"""# {title}
Severity: {severity_str}

Summary
{summary}

Doppins
Reproduction (Foundry)
{repro_cmd}

PoC ({poc_path.name})
```{code_lang}
{code}
```

Execution Snippet
```text
{stdout_head}
```

Impact

Estimated Economic Impact: ${econ:,.2f} USD

Impact Vectors
{vector_lines}

Determinism
{determ_lines}

Environment

{env_note}

Tools

- {forge_v}
- {solc_v}
- Git: {git_sha}
{f'\nArtifact\n\nSandbox tarball: {artifact_path}\n' if artifact_path else ''}
{failure_section}{autoplan_section}

Generated: {now}
""".rstrip()
    return md


def write_report(md: str, out_dir: Path, base_name: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{base_name}.md"
    path.write_text(md, encoding="utf-8")
    return path
