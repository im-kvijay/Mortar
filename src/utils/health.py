"""health check utilities for mortar-c production readiness. this module provides  heal..."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
import subprocess
import os
import sys
import shutil
import json
import time
from pathlib import Path

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class HealthStatus(Enum):
    """health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"  # some non-critical checks failed
    UNHEALTHY = "unhealthy"  # critical checks failed

@dataclass
class HealthCheckResult:
    """result of a single health check."""
    name: str
    status: HealthStatus
    message: str
    details: Optional[Dict[str, Any]] = None
    is_critical: bool = True  # if false, failure results in degraded not unhealthy

    def to_dict(self) -> Dict[str, Any]:
        """convert to dictionary for json serialization."""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "details": self.details or {},
            "is_critical": self.is_critical
        }

class HealthChecker:
    """ health checker for mortar-c."""

    def __init__(self, config=None):
        """initialize health checker. args: config: optional config object. if none, will try to load from s..."""
        self.config = config
        self.results: List[HealthCheckResult] = []

#        # try to load config if not provided
        if self.config is None:
            try:
                from src.config import Config
                self.config = Config()
            except Exception:
                pass

    def check_python_version(self) -> HealthCheckResult:
        """verify python version is 3.11+."""
        try:
            version_info = sys.version_info
            version_str = f"{version_info.major}.{version_info.minor}.{version_info.micro}"

            if version_info.major == 3 and version_info.minor >= 11:
                return HealthCheckResult(
                    name="python_version",
                    status=HealthStatus.HEALTHY,
                    message=f"Python version {version_str} is supported",
                    details={"version": version_str, "required": "3.11+"},
                    is_critical=True
                )
            else:
                return HealthCheckResult(
                    name="python_version",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Python {version_str} is not supported. Required: 3.11+",
                    details={"version": version_str, "required": "3.11+"},
                    is_critical=True
                )
        except Exception as e:
            return HealthCheckResult(
                name="python_version",
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check Python version: {e}",
                details={"error": str(e)},
                is_critical=True
            )

    def check_llm_connectivity(self) -> HealthCheckResult:
        """test llm api connectivity with 5s timeout."""
        try:
#            # get backend from config or environment
            backend = None
            api_key = None

            if self.config:
                backend = getattr(self.config, 'BACKEND', None)
                if backend == 'xai':
                    api_key = getattr(self.config, 'XAI_API_KEY', None)
                elif backend == 'openrouter':
                    api_key = getattr(self.config, 'OPENROUTER_API_KEY', None)

            if not backend:
                backend = os.getenv('BACKEND', 'openrouter')

            if not api_key:
                if backend == 'xai':
                    api_key = os.getenv('XAI_API_KEY')
                elif backend == 'openrouter':
                    api_key = os.getenv('OPENROUTER_API_KEY')

            if not api_key:
                return HealthCheckResult(
                    name="llm_connectivity",
                    status=HealthStatus.UNHEALTHY,
                    message=f"API key not configured for backend: {backend}",
                    details={"backend": backend, "api_key_set": False},
                    is_critical=True
                )

#            # test api connectivity with timeout
            start_time = time.time()
            try:
                from src.utils.llm_backend import create_llm_backend

                llm = create_llm_backend(backend=backend)

                test_prompt = "Return 'OK'"
                response = llm.complete(
                    prompt=test_prompt,
                    max_tokens=10,
                    temperature=0.0,
                    timeout=5.0
                )

                elapsed = time.time() - start_time

                if response and len(response.strip()) > 0:
                    return HealthCheckResult(
                        name="llm_connectivity",
                        status=HealthStatus.HEALTHY,
                        message=f"LLM API ({backend}) is responding",
                        details={
                            "backend": backend,
                            "response_time_ms": int(elapsed * 1000),
                            "api_key_set": True
                        },
                        is_critical=True
                    )
                else:
                    return HealthCheckResult(
                        name="llm_connectivity",
                        status=HealthStatus.UNHEALTHY,
                        message=f"LLM API ({backend}) returned empty response",
                        details={"backend": backend, "response_time_ms": int(elapsed * 1000)},
                        is_critical=True
                    )

            except Exception as api_err:
                elapsed = time.time() - start_time
                return HealthCheckResult(
                    name="llm_connectivity",
                    status=HealthStatus.UNHEALTHY,
                    message=f"LLM API ({backend}) connection failed: {api_err}",
                    details={
                        "backend": backend,
                        "error": str(api_err),
                        "response_time_ms": int(elapsed * 1000)
                    },
                    is_critical=True
                )

        except Exception as e:
            return HealthCheckResult(
                name="llm_connectivity",
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check LLM connectivity: {e}",
                details={"error": str(e)},
                is_critical=True
            )

    def check_foundry(self) -> HealthCheckResult:
        """verify foundry installation and forge command."""
        try:
#            # check if forge is in path
            forge_path = shutil.which('forge')

            if not forge_path:
                return HealthCheckResult(
                    name="foundry",
                    status=HealthStatus.UNHEALTHY,
                    message="Foundry (forge) not found in PATH",
                    details={"forge_path": None, "install_url": "https://book.getfoundry.sh/getting-started/installation"},
                    is_critical=True
                )

#            # test forge command
            result = subprocess.run(
                ['forge', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                version_output = result.stdout.strip()
                return HealthCheckResult(
                    name="foundry",
                    status=HealthStatus.HEALTHY,
                    message="Foundry is installed and working",
                    details={"forge_path": forge_path, "version": version_output},
                    is_critical=True
                )
            else:
                return HealthCheckResult(
                    name="foundry",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Foundry command failed: {result.stderr}",
                    details={"forge_path": forge_path, "error": result.stderr},
                    is_critical=True
                )

        except subprocess.TimeoutExpired:
            return HealthCheckResult(
                name="foundry",
                status=HealthStatus.UNHEALTHY,
                message="Foundry command timed out",
                details={"error": "timeout"},
                is_critical=True
            )
        except Exception as e:
            return HealthCheckResult(
                name="foundry",
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check Foundry: {e}",
                details={"error": str(e)},
                is_critical=True
            )

    def check_kb_storage(self) -> HealthCheckResult:
        """verify kb storage directories are writable."""
        try:
#            # determine project root
            current_file = Path(__file__).resolve()
            project_root = current_file.parent.parent.parent
            kb_dir = project_root / 'data' / 'kb'

#            # create directory if it doesn't exist
            kb_dir.mkdir(parents=True, exist_ok=True)

#            # test write access
            test_file = kb_dir / '.health_check_test'
            try:
                test_file.write_text('test')
                test_file.unlink()

                return HealthCheckResult(
                    name="kb_storage",
                    status=HealthStatus.HEALTHY,
                    message="KB storage is writable",
                    details={"path": str(kb_dir), "writable": True},
                    is_critical=True
                )
            except Exception as write_err:
                return HealthCheckResult(
                    name="kb_storage",
                    status=HealthStatus.UNHEALTHY,
                    message=f"KB storage is not writable: {write_err}",
                    details={"path": str(kb_dir), "writable": False, "error": str(write_err)},
                    is_critical=True
                )

        except Exception as e:
            return HealthCheckResult(
                name="kb_storage",
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check KB storage: {e}",
                details={"error": str(e)},
                is_critical=True
            )

    def check_disk_space(self, min_gb: float = 1.0) -> HealthCheckResult:
        """check available disk space."""
        if not PSUTIL_AVAILABLE:
            return HealthCheckResult(
                name="disk_space",
                status=HealthStatus.DEGRADED,
                message="psutil not available, cannot check disk space",
                details={"psutil_available": False},
                is_critical=False
            )

        try:
#            # get disk usage for current directory
            current_file = Path(__file__).resolve()
            project_root = current_file.parent.parent.parent

            usage = psutil.disk_usage(str(project_root))
            available_gb = usage.free / (1024 ** 3)
            total_gb = usage.total / (1024 ** 3)
            used_percent = usage.percent

            if available_gb >= min_gb:
                return HealthCheckResult(
                    name="disk_space",
                    status=HealthStatus.HEALTHY,
                    message=f"Sufficient disk space: {available_gb:.2f} GB available",
                    details={
                        "available_gb": round(available_gb, 2),
                        "total_gb": round(total_gb, 2),
                        "used_percent": round(used_percent, 1),
                        "threshold_gb": min_gb
                    },
                    is_critical=False
                )
            else:
                return HealthCheckResult(
                    name="disk_space",
                    status=HealthStatus.DEGRADED,
                    message=f"Low disk space: {available_gb:.2f} GB available (< {min_gb} GB)",
                    details={
                        "available_gb": round(available_gb, 2),
                        "total_gb": round(total_gb, 2),
                        "used_percent": round(used_percent, 1),
                        "threshold_gb": min_gb
                    },
                    is_critical=False
                )

        except Exception as e:
            return HealthCheckResult(
                name="disk_space",
                status=HealthStatus.DEGRADED,
                message=f"Failed to check disk space: {e}",
                details={"error": str(e)},
                is_critical=False
            )

    def check_memory(self, max_percent: float = 80.0) -> HealthCheckResult:
        """check system memory usage."""
        if not PSUTIL_AVAILABLE:
            return HealthCheckResult(
                name="memory",
                status=HealthStatus.DEGRADED,
                message="psutil not available, cannot check memory",
                details={"psutil_available": False},
                is_critical=False
            )

        try:
            memory = psutil.virtual_memory()
            used_percent = memory.percent
            available_gb = memory.available / (1024 ** 3)
            total_gb = memory.total / (1024 ** 3)

            if used_percent <= max_percent:
                return HealthCheckResult(
                    name="memory",
                    status=HealthStatus.HEALTHY,
                    message=f"Memory usage normal: {used_percent:.1f}% used",
                    details={
                        "used_percent": round(used_percent, 1),
                        "available_gb": round(available_gb, 2),
                        "total_gb": round(total_gb, 2),
                        "threshold_percent": max_percent
                    },
                    is_critical=False
                )
            else:
                return HealthCheckResult(
                    name="memory",
                    status=HealthStatus.DEGRADED,
                    message=f"High memory usage: {used_percent:.1f}% used (> {max_percent}%)",
                    details={
                        "used_percent": round(used_percent, 1),
                        "available_gb": round(available_gb, 2),
                        "total_gb": round(total_gb, 2),
                        "threshold_percent": max_percent
                    },
                    is_critical=False
                )

        except Exception as e:
            return HealthCheckResult(
                name="memory",
                status=HealthStatus.DEGRADED,
                message=f"Failed to check memory: {e}",
                details={"error": str(e)},
                is_critical=False
            )

    def check_slither(self) -> HealthCheckResult:
        """check slither installation (optional dependency)."""
        try:
#            # check if slither is in path
            slither_path = shutil.which('slither')

            if not slither_path:
                return HealthCheckResult(
                    name="slither",
                    status=HealthStatus.DEGRADED,
                    message="Slither not found (optional dependency)",
                    details={
                        "slither_path": None,
                        "optional": True,
                        "install_cmd": "pip install slither-analyzer"
                    },
                    is_critical=False
                )

#            # test slither command
            result = subprocess.run(
                ['slither', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                version_output = result.stdout.strip()
                return HealthCheckResult(
                    name="slither",
                    status=HealthStatus.HEALTHY,
                    message="Slither is installed and working",
                    details={"slither_path": slither_path, "version": version_output, "optional": True},
                    is_critical=False
                )
            else:
                return HealthCheckResult(
                    name="slither",
                    status=HealthStatus.DEGRADED,
                    message=f"Slither command failed: {result.stderr}",
                    details={"slither_path": slither_path, "error": result.stderr, "optional": True},
                    is_critical=False
                )

        except subprocess.TimeoutExpired:
            return HealthCheckResult(
                name="slither",
                status=HealthStatus.DEGRADED,
                message="Slither command timed out",
                details={"error": "timeout", "optional": True},
                is_critical=False
            )
        except Exception as e:
            return HealthCheckResult(
                name="slither",
                status=HealthStatus.DEGRADED,
                message=f"Failed to check Slither: {e}",
                details={"error": str(e), "optional": True},
                is_critical=False
            )

    def run_all_checks(self) -> tuple[HealthStatus, List[HealthCheckResult]]:
        """run all health checks and return overall status. returns: tuple of (overall_status, list_of_results)"""
        self.results = []

#        # run all checks
        self.results.append(self.check_python_version())
        self.results.append(self.check_foundry())
        self.results.append(self.check_kb_storage())
        self.results.append(self.check_disk_space())
        self.results.append(self.check_memory())
        self.results.append(self.check_slither())
        self.results.append(self.check_llm_connectivity())

#        # determine overall status
        has_critical_failure = any(
            r.status == HealthStatus.UNHEALTHY and r.is_critical
            for r in self.results
        )

        has_any_failure = any(
            r.status in (HealthStatus.UNHEALTHY, HealthStatus.DEGRADED)
            for r in self.results
        )

        if has_critical_failure:
            overall_status = HealthStatus.UNHEALTHY
        elif has_any_failure:
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY

        return overall_status, self.results

    def to_dict(self) -> Dict[str, Any]:
        """return health status as dictionary (for json api)."""
        overall_status = HealthStatus.HEALTHY

        if self.results:
            has_critical_failure = any(
                r.status == HealthStatus.UNHEALTHY and r.is_critical
                for r in self.results
            )
            has_any_failure = any(
                r.status in (HealthStatus.UNHEALTHY, HealthStatus.DEGRADED)
                for r in self.results
            )

            if has_critical_failure:
                overall_status = HealthStatus.UNHEALTHY
            elif has_any_failure:
                overall_status = HealthStatus.DEGRADED

        return {
            "overall_status": overall_status.value,
            "timestamp": time.time(),
            "checks": [r.to_dict() for r in self.results],
            "summary": {
                "total": len(self.results),
                "healthy": sum(1 for r in self.results if r.status == HealthStatus.HEALTHY),
                "degraded": sum(1 for r in self.results if r.status == HealthStatus.DEGRADED),
                "unhealthy": sum(1 for r in self.results if r.status == HealthStatus.UNHEALTHY),
            }
        }

    def print_report(self, verbose: bool = False):
        """print human-readable health report. args: verbose: if true, include detailed information"""
        overall_status, _ = (
            (self.results[0].status, self.results) if not self.results
            else self.run_all_checks() if not self.results
            else (HealthStatus.HEALTHY, self.results)
        )

#        # recalculate overall status
        has_critical_failure = any(
            r.status == HealthStatus.UNHEALTHY and r.is_critical
            for r in self.results
        )
        has_any_failure = any(
            r.status in (HealthStatus.UNHEALTHY, HealthStatus.DEGRADED)
            for r in self.results
        )

        if has_critical_failure:
            overall_status = HealthStatus.UNHEALTHY
        elif has_any_failure:
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY

#        # print header
        status_symbols = {
            HealthStatus.HEALTHY: "✓",
            HealthStatus.DEGRADED: "⚠",
            HealthStatus.UNHEALTHY: "✗"
        }

        status_colors = {
            HealthStatus.HEALTHY: "\033[92m",  # green
            HealthStatus.DEGRADED: "\033[93m",  # yellow
            HealthStatus.UNHEALTHY: "\033[91m",  # red
        }
        reset_color = "\033[0m"

        print(f"\n{'='*60}")
        print(f"Mortar-C Health Check Report")
        print(f"{'='*60}\n")

#        # overall status
        color = status_colors[overall_status]
        symbol = status_symbols[overall_status]
        print(f"Overall Status: {color}{symbol} {overall_status.value.upper()}{reset_color}\n")

#        # individual checks
        for result in self.results:
            color = status_colors[result.status]
            symbol = status_symbols[result.status]
            critical_marker = " [CRITICAL]" if result.is_critical else ""

            print(f"{color}{symbol}{reset_color} {result.name}{critical_marker}")
            print(f"  {result.message}")

            if verbose and result.details:
                for key, value in result.details.items():
                    print(f"    {key}: {value}")
            print()

#        # summary
        summary = self.to_dict()["summary"]
        print(f"{'='*60}")
        print(f"Summary: {summary['healthy']} healthy, {summary['degraded']} degraded, {summary['unhealthy']} unhealthy")
        print(f"{'='*60}\n")

def quick_health_check(silent: bool = False) -> bool:
    """quick health check for startup - returns true if healthy or degraded. args: silent: if true, supp..."""
    checker = HealthChecker()
    overall_status, results = checker.run_all_checks()

    if not silent:
        if overall_status == HealthStatus.HEALTHY:
            print("✓ System health check passed")
        elif overall_status == HealthStatus.DEGRADED:
            print("⚠ System health check passed with warnings:")
            for result in results:
                if result.status != HealthStatus.HEALTHY:
                    print(f"  - {result.name}: {result.message}")
        else:
            print("✗ System health check failed:")
            for result in results:
                if result.status == HealthStatus.UNHEALTHY and result.is_critical:
                    print(f"  - {result.name}: {result.message}")

    return overall_status != HealthStatus.UNHEALTHY

# cli entry point
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Mortar-C Health Check")
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Include detailed information'
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick check (exit code only)'
    )

    args = parser.parse_args()

    if args.quick:
#        # quick check mode
        success = quick_health_check(silent=True)
        sys.exit(0 if success else 1)

#    # full check mode
    checker = HealthChecker()
    overall_status, results = checker.run_all_checks()

    if args.json:
#        # json output
        print(json.dumps(checker.to_dict(), indent=2))
    else:
#        # human-readable output
        checker.print_report(verbose=args.verbose)

#    # exit with appropriate code
    sys.exit(0 if overall_status != HealthStatus.UNHEALTHY else 1)
