"""static analysis integration via slither with intelligent severity mapping"""
import subprocess
import json
import logging
import os
from pathlib import Path
from typing import List, Dict, Optional

from src.models.findings import (
    StaticAnalysisFinding,
    VulnerabilityType,
    Severity,
    ProjectStructure
)

logger = logging.getLogger(__name__)

# map slither detector ids to our vulnerabilitytype enum
# based on slither's 92 detectors - mapping the most critical ones
SLITHER_TO_VULN_TYPE = {
    # reentrancy detectors
    "reentrancy-eth": VulnerabilityType.REENTRANCY,
    "reentrancy-no-eth": VulnerabilityType.REENTRANCY,
    "reentrancy-benign": VulnerabilityType.REENTRANCY,
    "reentrancy-events": VulnerabilityType.REENTRANCY,

    # access control
    "unprotected-upgrade": VulnerabilityType.ACCESS_CONTROL,
    "function-init-state": VulnerabilityType.INITIALIZATION,
    "missing-inheritance": VulnerabilityType.ACCESS_CONTROL,
    "arbitrary-send-eth": VulnerabilityType.ACCESS_CONTROL,
    "arbitrary-send-erc20": VulnerabilityType.ACCESS_CONTROL,

    # unchecked calls
    "unchecked-lowlevel": VulnerabilityType.UNCHECKED_CALL,
    "unchecked-send": VulnerabilityType.UNCHECKED_CALL,

    # delegatecall
    "controlled-delegatecall": VulnerabilityType.DELEGATE_CALL,
    "delegatecall-loop": VulnerabilityType.DELEGATE_CALL,

    # logic errors
    "incorrect-equality": VulnerabilityType.LOGIC_ERROR,
    "divide-before-multiply": VulnerabilityType.LOGIC_ERROR,
    "weak-prng": VulnerabilityType.LOGIC_ERROR,

    # integer issues (mostly mitigated in solidity 0.8+)
    "integer-overflow": VulnerabilityType.INTEGER_OVERFLOW,

    # timestamp manipulation
    "timestamp": VulnerabilityType.TIME_MANIPULATION,

    # oracle/price issues
    "price-oracle": VulnerabilityType.ORACLE_MANIPULATION,

    # dos
    "reentrancy-unlimited-gas": VulnerabilityType.DOS,
    "costly-loop": VulnerabilityType.DOS,

    # front-running
    "tx-origin": VulnerabilityType.FRONT_RUNNING,
}

# map slither impact levels to our severity enum
SLITHER_IMPACT_TO_SEVERITY = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFORMATIONAL,
}

# map slither confidence to float
SLITHER_CONFIDENCE_TO_FLOAT = {
    "High": 0.9,
    "Medium": 0.6,
    "Low": 0.3,
}

class StaticAnalyzer:
    """runs slither static analysis and normalizes findings"""

    _warned_missing_slither: bool = False
    _session_cache: Dict[str, Dict] = {}

    def __init__(self, project_root: Optional[Path] = None):
        """initialize static analyzer"""
        self.project_root = Path(project_root).resolve() if project_root else None
        self.slither_path = self._find_slither()
        # prepare on-disk cache dir
        from config import config as _cfg
        self._cache_dir = Path(_cfg.DATA_DIR) / "cache" / "slither"
        self._cache_dir.mkdir(parents=True, exist_ok=True)

    def _find_slither(self) -> Optional[str]:
        """find slither executable in path or common locations"""

        common_paths = [
            os.path.expanduser("~/Library/Python/3.9/bin/slither"),
            os.path.expanduser("~/Library/Python/3.10/bin/slither"),
            os.path.expanduser("~/Library/Python/3.11/bin/slither"),
            os.path.expanduser("~/.local/bin/slither"),
            "/usr/local/bin/slither",
            "/usr/bin/slither",
        ]

        for path in common_paths:
            if os.path.exists(path):
                return path

        # try which slither
        try:
            result = subprocess.run(
                ["which", "slither"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            # solc not found or compilation failed - return none to indicate unavailable
            pass

        return None

    def analyze(self, project: ProjectStructure) -> List[StaticAnalysisFinding]:
        """run slither analysis on the project"""
        if not self.slither_path:
            if not StaticAnalyzer._warned_missing_slither:
                logger.warning("Slither not found. Skipping static analysis gracefully.")
                StaticAnalyzer._warned_missing_slither = True
            return []

        # use in-process cache first
        key = str((self.project_root or project.project_root).resolve())
        if key in StaticAnalyzer._session_cache:
            slither_output = StaticAnalyzer._session_cache[key]
        else:
            logger.info(f"Running Slither on {project.project_name}",
                       extra={"project": project.project_name})
            # on-disk cache path (stable per project root)
            import hashlib
            h = hashlib.sha1(key.encode()).hexdigest()[:12]
            disk_cache = self._cache_dir / f"slither_{h}.json"
            if disk_cache.exists():
                try:
                    with open(disk_cache, "r", encoding="utf-8") as f:
                        slither_output = json.load(f)
                    StaticAnalyzer._session_cache[key] = slither_output
                except Exception as e:
                    logger.warning(f"Failed to read cache: {e}")
                    slither_output = self._run_slither(disk_cache)
            else:
                slither_output = self._run_slither(disk_cache)

        if not slither_output:
            logger.error("Slither analysis failed")
            return []

        findings = self._parse_slither_output(slither_output, project)

        logger.info(f"Found {len(findings)} potential issues",
                   extra={"findings_count": len(findings)})

        # log severity breakdown
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                logger.info(f"  - {severity.value.upper()}: {count}",
                          extra={"severity": severity.value, "count": count})

        return findings

    def analyze_file(self, contract_path: Path) -> List[StaticAnalysisFinding]:
        """analyze a single contract file by inferring project root and filtering results"""
        contract_path = Path(contract_path).resolve()
        contract_name = contract_path.stem

        # find project root by walking up from contract
        project_root = self._find_project_root(contract_path)
        if not project_root:
            logger.warning(f"Could not find project root for {contract_path}",
                         extra={"contract_path": str(contract_path)})
            return []

        # update project_root if different
        if project_root != self.project_root:
            self.project_root = project_root

        # discover project structure
        from cal.contract_discovery import ContractDiscoverySystem
        discovery = ContractDiscoverySystem(project_root=project_root)

        # discover project
        project = discovery.discover()

        # run analysis on whole project
        all_findings = self.analyze(project)

        # filter findings for this specific contract
        filtered = []
        for finding in all_findings:

            if finding.affected_contract and finding.affected_contract.name == contract_name:
                filtered.append(finding)
            # also check location string
            elif contract_name in finding.location:
                filtered.append(finding)

        return filtered

    def _find_project_root(self, start_path: Path) -> Optional[Path]:
        """find foundry project root by walking up directory tree"""
        current = start_path if start_path.is_dir() else start_path.parent

        # walk up max 10 levels
        for _ in range(10):

            if (current / "foundry.toml").exists() and (
                (current / "src").exists() or (current / "contracts").exists()
            ):
                return current

            # also check for hardhat
            if (current / "hardhat.config.js").exists() or (current / "hardhat.config.ts").exists():
                return current

            parent = current.parent
            if parent == current:  # reached root
                break
            current = parent

        return None

    def _run_slither(self, output_file: Optional[Path] = None) -> Optional[Dict]:
        """execute slither and return json output"""
        # optional escape hatch or known-incompatible environments
        if os.getenv("SLITHER_DISABLED", "0") == "1":
            logger.info("Slither disabled via SLITHER_DISABLED=1")
            return None

        output_file = output_file or (self.project_root / "slither_output.json")

        # run slither on the entire project (.)

        # with latest foundry build artifacts (keyerror: 'output' in crytic-compile)
        # slither will now compile the project itself, ensuring compatible artifacts
        # align with discovery: prefer out/ else foundry/out
        foundry_out = "out"
        if not (self.project_root / "out").exists() and (self.project_root / "foundry" / "out").exists():
            foundry_out = "foundry/out"

        cmd = [
            self.slither_path,
            ".",
            "--json", str(output_file),
            "--foundry-out-directory", foundry_out,
        ]

        # set up environment with forge in path (use home for portability)
        env = os.environ.copy()
        home = os.path.expanduser("~")
        env["PATH"] = f"{home}/.foundry/bin:{env.get('PATH', '')}"
        # disable hardhat auto-clean when foundry artifacts are present to avoid noisy failures
        env.setdefault("SLITHER_DISABLE_HARDHAT_CLEAN", "1")

        # short-circuit slither when hardhat is present but node version is unsupported (avoids long retries)
        node_version = None
        has_hardhat = (self.project_root / "hardhat.config.js").exists() or (self.project_root / "hardhat.config.ts").exists()
        if has_hardhat:
            try:
                import subprocess as _sub
                version_out = _sub.check_output(["node", "-v"], text=True).strip().lstrip("v")
                node_major = int(version_out.split(".")[0])
                node_version = version_out
                if node_major >= 25:
                    logger.warning(f"Skipping Slither: Hardhat + unsupported Node {node_version}",
                                 extra={"node_version": node_version})
                    return None
            except Exception:
                pass

        try:
            logger.info(f"Running: {' '.join(cmd)}", extra={"cmd": ' '.join(cmd)})

            # import config for timeout
            from config import config as _cfg

            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                env=env,
                capture_output=True,
                text=True,
                timeout=_cfg.SLITHER_TIMEOUT
            )

            # slither exits with non-zero even on success if it finds issues
            # so we check if the json file was created
            if output_file.exists():
                with open(output_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                # store in session cache keyed by project root
                key = str(self.project_root.resolve())
                StaticAnalyzer._session_cache[key] = data
                return data
            else:
                # quiet error: log only head of stderr if any
                stderr_head = (result.stderr or "").splitlines()[:6]
                if stderr_head:
                    logger.error("Slither failed:\n  " + "\n  ".join(stderr_head))
                return None

        except subprocess.TimeoutExpired:
            from config import config as _cfg
            logger.warning(f"Slither timed out after {_cfg.SLITHER_TIMEOUT} seconds",
                         extra={"timeout": _cfg.SLITHER_TIMEOUT})
            return None
        except Exception as e:
            logger.warning(f"Error running Slither: {e}", exc_info=True)
            return None

    def _parse_slither_output(self, slither_data: Dict, project: ProjectStructure) -> List[StaticAnalysisFinding]:
        """parse slither json output into our finding format"""
        findings = []

        # slither json has "results" -> "detectors" list
        detectors = slither_data.get("results", {}).get("detectors", [])

        for detector in detectors:
            try:
                finding = self._parse_detector(detector, project)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.warning(f"Error parsing detector: {e}", exc_info=True)
                continue

        return findings

    def _parse_detector(self, detector: Dict, project: ProjectStructure) -> Optional[StaticAnalysisFinding]:
        """parse a single slither detector finding"""
        detector_id = detector.get("check", "unknown")
        description = detector.get("description", "")
        impact = detector.get("impact", "Informational")
        confidence = detector.get("confidence", "Medium")

        # map to our types
        vuln_type = SLITHER_TO_VULN_TYPE.get(detector_id, VulnerabilityType.UNKNOWN)
        severity = SLITHER_IMPACT_TO_SEVERITY.get(impact, Severity.INFORMATIONAL)
        confidence_score = SLITHER_CONFIDENCE_TO_FLOAT.get(confidence, 0.5)

        elements = detector.get("elements", [])
        locations = []
        affected_contracts = []

        for element in elements:
            if element.get("type") in ["contract", "function"]:
                contract_name = element.get("name", "")
                if contract_name and contract_name not in affected_contracts:
                    affected_contracts.append(contract_name)

            source_mapping = element.get("source_mapping", {})
            if source_mapping:
                filename = source_mapping.get("filename_short", "")
                lines = source_mapping.get("lines", [])
                if filename and lines:
                    locations.append(f"{filename}:{lines[0] if lines else '?'}")

        # find affected contract from project structure
        affected_contract_obj = None
        if affected_contracts:
            for contract in project.contracts:
                if contract.name in affected_contracts:
                    affected_contract_obj = contract
                    break

        return StaticAnalysisFinding(
            detector_name=detector_id,
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=confidence_score,
            description=description,
            location="; ".join(locations) if locations else "unknown",
            affected_contract=affected_contract_obj,
            raw_output=detector
        )

def analyze_project(project: ProjectStructure) -> List[StaticAnalysisFinding]:
    """convenience function to run static analysis on a project"""
    analyzer = StaticAnalyzer(project.project_root)
    return analyzer.analyze(project)
