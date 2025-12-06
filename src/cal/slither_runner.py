"""slither runner with caching"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

_slither_cache: Dict[str, Dict[str, Any]] = {}
MIN_SUPPORTED_SOLC = (0, 6, 0)
SYSTEM_SOLC_VERSION: Optional[Tuple[int, int, int]] = None

def find_slither() -> Optional[str]:
    return shutil.which("slither")

def _get_system_solc_version() -> Optional[Tuple[int, int, int]]:
    global SYSTEM_SOLC_VERSION
    if SYSTEM_SOLC_VERSION is not None:
        return SYSTEM_SOLC_VERSION

    try:
        result = subprocess.run(["solc", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            match = re.search(r"Version:\s*(\d+)\.(\d+)\.(\d+)", result.stdout)
            if match:
                SYSTEM_SOLC_VERSION = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
                return SYSTEM_SOLC_VERSION
    except Exception:
        pass
    return None

def _parse_pragma_version(source: str) -> Optional[Tuple[int, int, int]]:
    match = re.search(r'pragma\s+solidity\s+[\^>=<]*\s*(\d+)\.(\d+)\.(\d+)', source)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return None

def _is_version_compatible(contract_version: Tuple[int, int, int], system_version: Tuple[int, int, int]) -> bool:
    contract_major = contract_version[0]
    contract_minor = contract_version[1]
    system_major = system_version[0]
    system_minor = system_version[1]

    if contract_major != system_major:
        return False

    if contract_major == 0:
        if contract_minor != system_minor:
            if contract_minor <= system_minor and (system_minor - contract_minor) <= 2:
                return True
            return False

    return True

def check_slither_compatibility(contract_path: Path) -> Tuple[bool, str]:
    """check if slither can analyze this contract"""
    try:
        source = contract_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return False, f"cannot read source: {e}"

    contract_version = _parse_pragma_version(source)
    if not contract_version:
        return True, "no pragma, assuming modern"

    system_version = _get_system_solc_version()
    if not system_version:
        return False, "system solc not found"

    if not _is_version_compatible(contract_version, system_version):
        return False, f"version mismatch: {contract_version[0]}.{contract_version[1]}.x vs {system_version[0]}.{system_version[1]}.{system_version[2]}"

    if contract_version < MIN_SUPPORTED_SOLC:
        return False, f"version {contract_version[0]}.{contract_version[1]}.{contract_version[2]} too old"

    return True, "compatible"

def _compute_source_hash(contract_path: Path) -> str:
    try:
        content = contract_path.read_bytes()
        return hashlib.sha256(content).hexdigest()[:16]
    except Exception:
        return "unknown"

def run_slither(contract_path: Path, project_root: Path, timeout: int = 120) -> Dict[str, Any]:
    """run slither with caching"""
    slither_bin = find_slither()
    if not slither_bin:
        raise FileNotFoundError("slither not found")

    contract_path = contract_path.resolve()
    project_root = project_root.resolve()

    is_compatible, reason = check_slither_compatibility(contract_path)
    if not is_compatible:
        print(f"[slither] skipping {contract_path.name}: {reason}")
        return {"results": {"detectors": []}, "skipped": True, "reason": reason}

    source_hash = _compute_source_hash(contract_path)
    cache_key = f"{contract_path.stem}_{source_hash}"

    if cache_key in _slither_cache:
        return _slither_cache[cache_key]

    cache_dir = project_root / "data" / "cache" / "slither"
    cache_dir.mkdir(parents=True, exist_ok=True)
    json_path = cache_dir / f"{cache_key}.json"

    if json_path.exists():
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            _slither_cache[cache_key] = data
            return data
        except (json.JSONDecodeError, OSError):
            pass

    cmd = [slither_bin, str(contract_path), "--json", str(json_path)]
    try:
        subprocess.run(cmd, cwd=str(project_root), check=True, timeout=timeout, capture_output=True)
        data = json.loads(json_path.read_text(encoding="utf-8"))
        _slither_cache[cache_key] = data
        return data
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"slither failed: {exc.stderr}") from exc
    except (json.JSONDecodeError, OSError) as exc:
        raise RuntimeError(f"failed to read slither json: {exc}") from exc
