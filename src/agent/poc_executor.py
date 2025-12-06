"""PoC execution with auto-fixing and multi-turn LLM fallback."""

import hashlib
import os
import shutil
import subprocess
import time
import re
from typing import Dict, Any, Optional, List, TYPE_CHECKING, Callable, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from utils.logging import ResearchLogger
from agent.poc_generator import GeneratedPoC
from agent.base_attacker import AttackHypothesis
from kb.knowledge_base import KnowledgeBase
from agent.poc_sandbox import make_sandbox, write_test, run_forge, cleanup_sandbox
from agent.llm_sanitizer import sanitize_poc
from agent.poc_fixers import apply_poc_fixers

MAX_FALLBACK_ATTEMPTS = 3
MAX_TOTAL_ATTEMPTS = 10
ERROR_CONTEXT_CHARS = 1500


def _build_rich_error_context(
    current_error: str,
    iteration_history: List[Dict[str, Any]],
    contract_info: Optional[Dict[str, Any]] = None,
) -> str:
    """Build rich error context for multi-turn LLM iteration."""
    sections = ["=== COMPILATION ERROR ===", current_error[:ERROR_CONTEXT_CHARS], ""]

    if iteration_history:
        sections.append("=== PREVIOUS ATTEMPTS ===")
        for i, attempt in enumerate(iteration_history[-3:]):
            applied = attempt.get("applied", [])
            error_summary = attempt.get("error_summary", "")[:150]
            sections.append(f"Attempt {i+1} ({attempt.get('type', 'unknown')}): {', '.join(applied) if applied else 'no fixes'}")
            if error_summary:
                sections.append(f"  Error: {error_summary}")
        sections.append("")

    sections.append("=== FIX SUGGESTIONS ===")
    suggestions = []
    err_lower = current_error.lower()

    if "not found" in err_lower or "undeclared" in err_lower:
        suggestions.append("- Check function name spelling")
        if contract_info and contract_info.get("external_functions"):
            suggestions.append(f"- Available: {', '.join(contract_info['external_functions'][:10])}")
    if "type" in err_lower and "incompatible" in err_lower:
        suggestions.extend(["- Verify param types", "- Check uint256 vs uint, address vs address payable"])
    if "memory" in err_lower or "calldata" in err_lower:
        suggestions.extend(["- Add 'memory' for string/bytes/array", "- Use 'calldata' for external params"])
    if "visibility" in err_lower or "override" in err_lower:
        suggestions.extend(["- Order: visibility, mutability, override", "- setUp() needs 'override'"])
    if not suggestions:
        suggestions.extend(["- Verify imports", "- Ensure ExploitTestBase inheritance", "- Check target instantiation"])

    sections.extend(suggestions)
    sections.extend(["", "=== REQUIREMENTS ===", "- Must compile", "- Preserve attack logic", "- MUST call markImpact()"])
    return "\n".join(sections)

if TYPE_CHECKING:
    from kb.learning_manager import KBLearningManager


@dataclass
class ExecutionResult:
    """PoC execution result."""
    poc_path: Path
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    gas_used: Optional[int]
    profit: Optional[str]
    execution_time: float
    error_message: Optional[str]
    fallback_used: bool = False
    attempts: int = 1
    error_fingerprint: Optional[str] = None
    fallback_fingerprint: Optional[str] = None
    fallback_meta: Optional[Dict[str, Any]] = None
    impact_tags: List[str] = field(default_factory=list)
    sandbox_root: Optional[Path] = None
    sandbox_test_relpath: Optional[str] = None
    determinism: Dict[str, Any] = field(default_factory=dict)
    auto_fixes: List[str] = field(default_factory=list)


class PoCExecutor:
    """Executes Foundry test PoCs and validates exploits."""

    def __init__(
        self,
        logger: ResearchLogger,
        project_root: Path,
        kb: Optional[KnowledgeBase] = None,
        mode: str = "local",
        timeout: int = 180
    ):
        self.logger = logger
        self.project_root = Path(project_root)
        self.mode = mode
        self._forge_available = shutil.which("forge") is not None
        self.timeout = timeout
        self.repo_root = Path(__file__).resolve().parents[2]
        self.learning_mgr = None
        if kb:
            from kb.learning_manager import KBLearningManager
            self.learning_mgr = KBLearningManager(kb, logger)
            self.logger.info("[PoCExecutor] KB learning enabled")
        self.logger.info(f"[PoCExecutor] Initialized (mode: {mode})")

    @staticmethod
    def _fingerprint(stderr: str) -> str:
        lines: List[str] = []
        for raw in stderr.splitlines():
            stripped = raw.strip()
            if any(token in stripped for token in ("Error", "Compiler", "Source", "Unable to get")):
                lines.append(stripped)
        payload = "\n".join(lines)
        return hashlib.sha1(payload.encode()).hexdigest() if payload else ""

    @staticmethod
    def _extract_contract_name(code: str) -> Optional[str]:
        match = re.search(r"contract\s+(\w+)\s*(?:is|{)", code)
        if match:
            return match.group(1)
        return None

    def execute(
        self,
        poc: GeneratedPoC,
        hypothesis: Optional[AttackHypothesis] = None,
        contract_name: Optional[str] = None,
        contract_info: Optional[Dict[str, Any]] = None,
        pattern_id: Optional[str] = None,
        fallback_provider: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
    ) -> ExecutionResult:
        """Execute generated PoC and learn from results."""
        self.logger.info(f"[PoCExecutor] Executing: {poc.file_path}")

        if self.mode == "dry-run":
            result = self._dry_run(poc)
        elif not self._forge_available:
            return ExecutionResult(
                poc_path=poc.file_path, success=False, exit_code=-1, stdout="", stderr="forge not found in PATH",
                gas_used=None, profit=None, execution_time=0.0, error_message="forge not found"
            )
        elif self.mode == "fork":
            result = self._execute_fork(poc, fallback_provider=fallback_provider, contract_info=contract_info)
        else:
            result = self._execute_local(poc, fallback_provider=fallback_provider, contract_info=contract_info)
        def _maybe_tag_impact(exec_result: ExecutionResult, hyp: Optional[AttackHypothesis]) -> ExecutionResult:
            try:
                if not exec_result.success or exec_result.profit or exec_result.impact_tags:
                    return exec_result
                htype = (getattr(hyp, 'attack_type', '') or '').lower() if hyp else ''
                tag = (
                    'MARKET_CORRUPTION' if 'oracle' in htype or 'price' in htype else
                    'AUTHZ_BYPASS' if 'auth' in htype or 'access' in htype or 'role' in htype else
                    'CONFIG_CAPTURE' if 'config' in htype else
                    'INVARIANT_BREAK' if 'reentrancy' in htype else None
                )
                if tag:
                    exec_result.impact_tags.append(tag)
            except Exception as e:
                self.logger.warning(f"Failed to tag impact: {e}")
            return exec_result

        if self.learning_mgr and hypothesis and contract_name:
            self.logger.info("[PoCExecutor] KB learning")
            result = _maybe_tag_impact(result, hypothesis)
            self.learning_mgr.learn_from_poc_result(hypothesis=hypothesis, poc_result=result,
                                                      contract_name=contract_name, pattern_id=pattern_id)
        return result

    def _dry_run(self, poc: GeneratedPoC) -> ExecutionResult:
        """Dry run - syntax check only."""
        self.logger.info("[PoCExecutor] Dry-run mode")
        if not self._forge_available:
            return ExecutionResult(
                poc_path=poc.file_path, success=True, exit_code=0, stdout="Dry-run: forge unavailable",
                stderr="", gas_used=None, profit=None, execution_time=0.0, error_message=None
            )
        result = self._run_command(["forge", "build", "--force"], cwd=self.project_root)
        return ExecutionResult(
            poc_path=poc.file_path, success=result["exit_code"] == 0, exit_code=result["exit_code"],
            stdout=result["stdout"], stderr=result["stderr"], gas_used=None, profit=None,
            execution_time=result["execution_time"], error_message=result["stderr"] if result["exit_code"] != 0 else None
        )

    def _run_sandbox(
        self,
        solidity_code: str,
        filename: str,
        match_contract: Optional[str],
        fallback_provider: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
        extra_args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        contract_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        _ = match_contract  # kept for interface compatibility
        sandbox_root, test_dir = make_sandbox(self.repo_root)
        attempts = 0
        fallback_used = False
        fingerprint: Optional[str] = None
        fallback_fp: Optional[str] = None
        fallback_meta: Optional[Dict[str, Any]] = None
        reason: Optional[str] = None
        final_stdout = ""
        final_stderr = ""
        final_exit = -1
        start_time = time.perf_counter()
        should_cleanup = True
        auto_fixes: List[str] = []

        def _short_reason(stdout: str, stderr: str) -> str:
            diagnostics: List[str] = []
            for raw in (stderr or "").splitlines():
                line = raw.strip()
                if not line and diagnostics:
                    break
                if not line:
                    continue
                if line.startswith("Error") or "ParserError" in line or "TypeError" in line or "Compiler" in line or line.startswith("-->") or diagnostics:
                    diagnostics.append(line)
                if len(diagnostics) >= 6:
                    break
            if diagnostics:
                return " | ".join(diagnostics)[:600]
            stderr_msg = (stderr or "").strip()
            if stderr_msg and stderr_msg not in {"Error: Compilation failed"}:
                return stderr_msg[:400]
            tail = "\n".join((stdout or "").splitlines()[-20:])
            return (tail or stderr_msg or "COMPILE_FAIL")[:400]

        def _execute(code: str, name: str) -> subprocess.CompletedProcess:
            test_name = name if name.endswith(".sol") else f"{name}.sol"
            write_test(sandbox_root, test_name, code)
            args = list(extra_args) if extra_args else []
            args.extend(["--match-path", str(Path("test/.generated") / test_name)])
            self.logger.info(f"[PoCExecutor] forge test -C {sandbox_root} -vvv --match-path test/.generated/{test_name}")
            return run_forge(sandbox_root, timeout_sec=self.timeout, args=args, env=env)

        try:
            current_code = solidity_code
            iteration_history: List[Dict[str, Any]] = []

            while attempts < MAX_TOTAL_ATTEMPTS:
                attempts += 1
                res = _execute(current_code, filename)
                final_stdout = res.stdout or ""
                final_stderr = res.stderr or ""
                final_exit = res.returncode

                if res.returncode == 0:
                    should_cleanup = False
                    return {
                        "success": True, "exit_code": res.returncode, "stdout": final_stdout, "stderr": final_stderr,
                        "attempts": attempts, "fallback_used": False, "fingerprint": None, "fallback_fingerprint": None,
                        "fallback_meta": None, "reason": None, "execution_time": time.perf_counter() - start_time,
                        "sandbox_root": str(sandbox_root), "auto_fixes": auto_fixes,
                        "test_relpath": str(Path("test/.generated") / (filename if filename.endswith(".sol") else f"{filename}.sol")),
                    }

                fingerprint = self._fingerprint(final_stderr)
                main_reason = _short_reason(final_stdout, final_stderr)
                reason = main_reason
                error_blob = "\n".join(filter(None, [final_stdout, final_stderr, main_reason]))

                patched_code, fixes = apply_poc_fixers(current_code, error_blob, contract_info=contract_info)
                if fixes:
                    self.logger.info(f"[PoCExecutor] Auto-fixed ({', '.join(fixes)})")
                    auto_fixes.extend(fixes)
                    iteration_history.append({"type": "auto_fixer", "applied": fixes, "error_summary": main_reason[:200], "fingerprint": fingerprint})
                    current_code = patched_code
                    continue
                if fallback_provider:
                    fallback_attempts = 0
                    rich_error_context = error_blob

                    while fallback_attempts < MAX_FALLBACK_ATTEMPTS:
                        fallback_attempts += 1
                        self.logger.info(f"[PoCExecutor] LLM fallback {fallback_attempts}/{MAX_FALLBACK_ATTEMPTS}")

                        if fallback_attempts > 1:
                            rich_error_context = _build_rich_error_context(error_blob, iteration_history, contract_info)

                        fallback_meta = fallback_provider(rich_error_context)
                        if not fallback_meta or not isinstance(fallback_meta, dict) or not fallback_meta.get("code"):
                            self.logger.warning(f"[PoCExecutor] Fallback no code (attempt {fallback_attempts})")
                            break

                        safe_code = sanitize_poc(fallback_meta["code"])
                        fallback_meta["sanitized_code"] = safe_code
                        fallback_name = fallback_meta.get("filename") or f"llm_{filename}_v{fallback_attempts}"
                        fallback_used = True
                        attempts += 1

                        res_fb = _execute(safe_code, fallback_name)
                        final_stdout = res_fb.stdout or ""
                        final_stderr = res_fb.stderr or ""
                        final_exit = res_fb.returncode
                        fallback_fp = self._fingerprint(final_stderr)

                        iteration_history.append({"type": f"llm_fallback_v{fallback_attempts}", "applied": [],
                                                   "error_summary": _short_reason(final_stdout, final_stderr)[:200], "fingerprint": fallback_fp})

                        if res_fb.returncode == 0:
                            should_cleanup = False
                            return {
                                "success": True, "exit_code": res_fb.returncode, "stdout": final_stdout, "stderr": final_stderr,
                                "attempts": attempts, "fallback_used": True, "fingerprint": fingerprint, "fallback_fingerprint": fallback_fp,
                                "fallback_meta": fallback_meta, "reason": None, "execution_time": time.perf_counter() - start_time,
                                "sandbox_root": str(sandbox_root), "auto_fixes": auto_fixes,
                                "test_relpath": str(Path("test/.generated") / (fallback_name if fallback_name.endswith(".sol") else f"{fallback_name}.sol")),
                            }

                        error_blob = "\n".join(filter(None, [final_stdout, final_stderr]))
                        fallback_reason = _short_reason(final_stdout, final_stderr)

                        if fallback_fp == fingerprint:
                            self.logger.warning("[PoCExecutor] Fallback same error")
                            reason = f"Main: {main_reason[:200]} | Fallback: SAME ERROR"
                            break

                        reason = f"Main: {main_reason[:200]} | Fallback v{fallback_attempts}: {fallback_reason[:200]}"

                    if not fallback_meta or not fallback_meta.get("code"):
                        if fallback_meta and fallback_meta.get("error"):
                            reason = f"Main: {main_reason[:200]} | Fallback: {fallback_meta['error']}"
                        else:
                            reason = f"Main: {main_reason[:200]} | Fallback: no code after {fallback_attempts} attempts"

                if not fallback_provider:
                    reason = f"Main: {main_reason[:200]} | No fallback"
                return {
                    "success": False, "exit_code": final_exit, "stdout": final_stdout, "stderr": final_stderr,
                    "attempts": attempts, "fallback_used": fallback_used, "fingerprint": fingerprint,
                    "fallback_fingerprint": fallback_fp, "fallback_meta": fallback_meta, "reason": reason,
                    "execution_time": time.perf_counter() - start_time, "sandbox_root": str(sandbox_root),
                    "test_relpath": str(Path("test/.generated") / (filename if filename.endswith(".sol") else f"{filename}.sol")),
                    "auto_fixes": auto_fixes, "iteration_history": iteration_history,
                }

            return {
                "success": False, "exit_code": -1, "stdout": "", "stderr": f"Exceeded MAX_TOTAL_ATTEMPTS ({MAX_TOTAL_ATTEMPTS})",
                "attempts": attempts, "fallback_used": fallback_used, "fingerprint": fingerprint,
                "fallback_fingerprint": fallback_fp, "fallback_meta": fallback_meta,
                "reason": f"Max iterations ({MAX_TOTAL_ATTEMPTS})", "execution_time": time.perf_counter() - start_time,
                "sandbox_root": str(sandbox_root), "auto_fixes": auto_fixes, "iteration_history": iteration_history,
                "test_relpath": str(Path("test/.generated") / (filename if filename.endswith(".sol") else f"{filename}.sol")),
            }
        finally:
            if should_cleanup:
                try:
                    cleanup_sandbox(sandbox_root)
                except Exception as e:
                    self.logger.warning(f"[PoCExecutor] Cleanup failed {sandbox_root}: {e}")

    def _execute_local(
        self,
        poc: GeneratedPoC,
        fallback_provider: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
        contract_info: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        """Execute on local testnet."""
        self.logger.info("[PoCExecutor] Local testnet")

        code = poc.test_code or Path(poc.file_path).read_text(encoding="utf-8")
        if poc.generation_method == "autoplan" and code.startswith("AUTOPOC_PLAN_BIN:"):
            plan_path = code.split(":", 1)[1].strip()
            try:
                data = Path(plan_path).read_bytes()
            except Exception as e:
                return ExecutionResult(
                    poc_path=poc.file_path, success=False, exit_code=-1, stdout="", stderr=f"Failed to read AutoPlan: {e}",
                    gas_used=None, profit=None, execution_time=0.0, error_message=str(e)
                )
            sandbox_root, _ = make_sandbox(self.repo_root)
            args = ["--match-test", "test_RunAutoPlan"]
            env = {"AUTOPOC_PLAN": "0x" + data.hex()}
            start_time = time.perf_counter()
            success = False
            try:
                res = run_forge(sandbox_root, timeout_sec=self.timeout, args=args, env=env)
                stdout = res.stdout or ""
                stderr = res.stderr or ""
                success = (res.returncode == 0)
                return ExecutionResult(
                    poc_path=poc.file_path, success=success, exit_code=res.returncode, stdout=stdout, stderr=stderr,
                    gas_used=self._extract_gas_used(stdout), profit=self._extract_profit(stdout),
                    execution_time=time.perf_counter() - start_time, error_message=self._extract_error(stderr, stdout),
                    impact_tags=self._extract_impact_tags(stdout), sandbox_root=Path(sandbox_root),
                    sandbox_test_relpath="test/AutoPoCRunner.t.sol", determinism=self._extract_determinism(stdout),
                )
            finally:
                if not success:
                    try:
                        cleanup_sandbox(sandbox_root)
                    except Exception as e:
                        self.logger.warning(f"[PoCExecutor] AutoPlan cleanup failed {sandbox_root}: {e}")
        sandbox_result = self._run_sandbox(
            solidity_code=code, filename=Path(poc.file_path).name, match_contract=self._extract_contract_name(code),
            fallback_provider=fallback_provider, extra_args=None, env=None, contract_info=contract_info,
        )
        return self._build_execution_result(poc.file_path, sandbox_result)

    def _execute_fork(
        self,
        poc: GeneratedPoC,
        fallback_provider: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
        contract_info: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        """Execute on mainnet fork."""
        self.logger.info("[PoCExecutor] Mainnet fork")

        fork_url = os.getenv("ETH_RPC_URL")
        if not fork_url:
            self.logger.info("[PoCExecutor] ETH_RPC_URL not set; dry-run mode")
            return self._dry_run(poc)
        try:
            from urllib.parse import urlparse
            host = (urlparse(fork_url).hostname or "").lower()
            if host not in {"127.0.0.1", "localhost", "0.0.0.0"}:
                self.logger.warning("[PoCExecutor] Non-local RPC blocked")
                return ExecutionResult(
                    poc_path=poc.file_path, success=False, exit_code=-1, stdout="", stderr="Non-local RPC prohibited",
                    gas_used=None, profit=None, execution_time=0.0, error_message="Non-local RPC blocked"
                )
        except Exception as e:
            self.logger.warning(f"Fork URL validation failed: {e}")

        code = poc.test_code or Path(poc.file_path).read_text(encoding="utf-8")
        sandbox_result = self._run_sandbox(
            solidity_code=code, filename=Path(poc.file_path).name, match_contract=self._extract_contract_name(code),
            fallback_provider=fallback_provider, extra_args=["--fork-url", fork_url], env=None, contract_info=contract_info,
        )
        return self._build_execution_result(poc.file_path, sandbox_result)

    def _build_execution_result(self, poc_path: Path, sandbox_result: Dict[str, Any]) -> ExecutionResult:
        """Build ExecutionResult from sandbox result."""
        stdout = sandbox_result["stdout"]
        stderr = sandbox_result["stderr"]
        return ExecutionResult(
            poc_path=poc_path, success=sandbox_result["success"], exit_code=sandbox_result["exit_code"],
            stdout=stdout, stderr=stderr, gas_used=self._extract_gas_used(stdout), profit=self._extract_profit(stdout),
            execution_time=sandbox_result["execution_time"], error_message=sandbox_result["reason"] or self._extract_error(stderr, stdout),
            fallback_used=sandbox_result["fallback_used"], attempts=sandbox_result["attempts"],
            error_fingerprint=sandbox_result["fingerprint"], fallback_fingerprint=sandbox_result["fallback_fingerprint"],
            fallback_meta=sandbox_result["fallback_meta"], auto_fixes=sandbox_result.get("auto_fixes", []),
            impact_tags=self._extract_impact_tags(stdout),
            sandbox_root=Path(sandbox_result.get("sandbox_root")) if sandbox_result.get("sandbox_root") else None,
            sandbox_test_relpath=sandbox_result.get("test_relpath"), determinism=self._extract_determinism(stdout),
        )

    def _run_command(self, cmd: List[str], cwd: Path) -> Dict[str, Any]:
        """Run shell command."""
        start_time = time.time()
        try:
            result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=self.timeout)
            return {"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "execution_time": time.time() - start_time}
        except subprocess.TimeoutExpired:
            self.logger.error(f"[PoCExecutor] Timeout after {self.timeout}s")
            return {"exit_code": -1, "stdout": "", "stderr": f"Timeout after {self.timeout}s", "execution_time": time.time() - start_time}
        except Exception as e:
            self.logger.error(f"[PoCExecutor] Command failed: {e}")
            return {"exit_code": -1, "stdout": "", "stderr": str(e), "execution_time": time.time() - start_time}

    def _extract_gas_used(self, stdout: str) -> Optional[int]:
        """Extract gas used from output."""
        match = re.search(r"gas:\s*(\d+)", stdout, re.IGNORECASE)
        return int(match.group(1)) if match else None

    def _extract_profit(self, stdout: str) -> Optional[str]:
        """Extract profit from output."""
        for pattern in [r"profit:\s*(-?[\d.]+\s*\w+)", r"profit:\s*(-?\d+)", r"gained:\s*([\d.]+\s*\w+)", r"balance:\s*([\d.]+\s*\w+)"]:
            match = re.search(pattern, stdout, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _extract_impact_tags(self, stdout: str) -> List[str]:
        """Extract IMPACT:<TAG> markers from output."""
        tags: List[str] = []
        for line in (stdout or "").splitlines():
            m = re.search(r"\bIMPACT:([A-Z0-9_]+)\b", line.strip())
            if m and m.group(1) not in tags:
                tags.append(m.group(1))
        return tags

    def _extract_determinism(self, stdout: str) -> Dict[str, Any]:
        """Parse ENV:KEY value logs from AutoPoCVM."""
        meta: Dict[str, Any] = {}
        for line in (stdout or "").splitlines():
            m = re.search(r"ENV:([A-Z0-9_]+)\s+([^\s]+)", line.strip())
            if not m:
                continue
            key, value = m.group(1).upper(), m.group(2)
            try:
                meta[key] = value if (value.startswith("0x") and len(value) > 2) else int(value)
            except ValueError:
                meta[key] = value
        return meta

    def _extract_error(self, stderr: str, stdout: str) -> Optional[str]:
        """Extract error message."""
        if stderr and stderr.strip():
            return stderr[:500]
        for pattern in [r"Error:.*", r"FAILED:.*", r"Revert:.*"]:
            match = re.search(pattern, stdout, re.IGNORECASE)
            if match:
                return match.group(0)
        return None


def compile_and_run(
    repo_root: str,
    solidity_test: str,
    test_filename: str,
    match_contract: Optional[str],
    llm_fallback: Optional[Callable[[], Optional[str]]] = None,
    timeout: int = 180,
) -> Tuple[bool, str]:
    """Compile and execute PoC with optional LLM fallback."""
    sandbox_root, _ = make_sandbox(repo_root)
    try:
        generated = write_test(sandbox_root, test_filename, solidity_test)
        res = run_forge(sandbox_root, timeout_sec=timeout, args=["--match-path", f"test/.generated/{generated.name}"])
        if res.returncode == 0:
            return True, res.stdout

        fingerprint = PoCExecutor._fingerprint(res.stderr)
        if llm_fallback:
            try:
                fallback_code = llm_fallback()
            except Exception as exc:
                return False, f"COMPILE_FAIL: fallback error ({exc})"

            if fallback_code:
                safe_code = sanitize_poc(fallback_code)
                fallback_name = f"llm_{test_filename}" if not test_filename.startswith("llm_") else test_filename
                written = write_test(sandbox_root, fallback_name, safe_code)
                res_llm = run_forge(sandbox_root, timeout_sec=timeout, args=["--match-path", f"test/.generated/{written.name}"])
                if res_llm.returncode == 0:
                    return True, res_llm.stdout
                if PoCExecutor._fingerprint(res_llm.stderr) == fingerprint:
                    return False, "COMPILE_UNSAT: repeated fingerprint"
                final_report = "\n".join(filter(None, [res_llm.stdout.strip(), res_llm.stderr.strip()]))
                return False, final_report or "COMPILE_FAIL: different error"
            return False, "COMPILE_FAIL: fallback unavailable"

        return False, "\n".join(filter(None, [res.stdout.strip(), res.stderr.strip()])) or "COMPILE_FAIL"
    finally:
        try:
            cleanup_sandbox(sandbox_root)
        except Exception:
            pass
