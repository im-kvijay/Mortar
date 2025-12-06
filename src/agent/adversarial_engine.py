"""module docstring"""
from __future__ import annotations

import os
import re
import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional


@dataclass
class HarnessResult:
    name: str
    command: str
    status: str  # passed|failed|skipped
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    reason: str = ""


class AdversarialEngine:
    # allowed characters for path validation (alphanumeric, dash, underscore, slash, dot)
    _SAFE_PATH_PATTERN = re.compile(r'^[a-zA-Z0-9_\-./]+$')

    def __init__(self, project_root: str, forge_timeout: int = 600):
        self.project_root = project_root
        self.forge_timeout = forge_timeout
        self.forge_bin = shutil.which("forge")

    def _validate_path(self, path: str) -> bool:
        """Validate that path contains only safe characters and doesn't escape project root."""
        if not path or not self._SAFE_PATH_PATTERN.match(path):
            return False
        # prevent path traversal
        if '..' in path:
            return False
        # ensure path resolves within project_root
        try:
            resolved = (Path(self.project_root) / path).resolve()
            project_resolved = Path(self.project_root).resolve()
            return str(resolved).startswith(str(project_resolved))
        except (ValueError, OSError):
            return False

    def run_harnesses(self, harnesses: List[Dict[str, str]]) -> List[HarnessResult]:
        """
        Run a list of harness specifications.

        harness: {"name": str, "path": str, "match": Optional[str]}
        """
        results: List[HarnessResult] = []
        for harness in harnesses:
            name = harness.get("name") or harness.get("path") or "harness"
            path = harness.get("path")
            match = harness.get("match")
            if not path:
                results.append(
                    HarnessResult(
                        name=name,
                        command="",
                        status="skipped",
                        reason="missing path",
                    )
                )
                continue

            # security: validate path to prevent command injection
            if not self._validate_path(path):
                results.append(
                    HarnessResult(
                        name=name,
                        command="",
                        status="skipped",
                        reason="invalid path: contains disallowed characters or traversal",
                    )
                )
                continue

            # security: validate match pattern if provided
            if match and not self._SAFE_PATH_PATTERN.match(match):
                results.append(
                    HarnessResult(
                        name=name,
                        command="",
                        status="skipped",
                        reason="invalid match pattern: contains disallowed characters",
                    )
                )
                continue

            cmd_list = self._build_command(path, match)
            if not cmd_list:
                results.append(
                    HarnessResult(
                        name=name,
                        command="",
                        status="skipped",
                        reason="forge not available",
                    )
                )
                continue

            # convert list to string for display purposes only
            cmd_display = " ".join(cmd_list)

            try:
                # security: use list-based command without shell=true
                proc = subprocess.run(
                    cmd_list,
                    cwd=self.project_root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.forge_timeout,
                    text=True,
                )
                status = "passed" if proc.returncode == 0 else "failed"
                results.append(
                    HarnessResult(
                        name=name,
                        command=cmd_display,
                        status=status,
                        stdout=proc.stdout[-4000:],  # keep tail
                        stderr=proc.stderr[-4000:],
                        returncode=proc.returncode,
                    )
                )
            except subprocess.TimeoutExpired as exc:
                results.append(
                    HarnessResult(
                        name=name,
                        command=cmd_display,
                        status="failed",
                        reason=f"timeout after {self.forge_timeout}s",
                        stdout=exc.stdout or "",
                        stderr=exc.stderr or "",
                        returncode=-1,
                    )
                )
        return results

    def _build_command(self, path: str, match: Optional[str]) -> Optional[List[str]]:
        """Build command as a list (not string) to prevent shell injection."""
        if not self.forge_bin:
            return None
        cmd = [self.forge_bin, "test", "-C", path]
        if match:
            cmd.extend(["--match-path", match])
        return cmd
