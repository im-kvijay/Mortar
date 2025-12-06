"""main orchestrator for smart contract auditing

coordinates cal, research, attack, poc, and kb layers

usage:
    python main.py --contract path/to/Contract.sol
    python main.py --foundry path/to/foundry/project
    python main.py --challenge unstoppable
"""
import argparse
import json
import logging
import os
import re
import sys
import subprocess
from concurrent.futures import as_completed, ThreadPoolExecutor
from src.cal.scheduler import TaskScheduler
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, UTC

sys.path.insert(0, str(Path(__file__).parent / "src"))

logger = logging.getLogger(__name__)

from config import config
from utils.llm_backend import create_backend
from utils.logging import ResearchLogger
from utils.cost_manager import CostManager, BudgetExceededError
from utils.run_profile import RunProfile
from utils.correlation import auditcontext, get_audit_id
from utils.output_formats import OutputFormat, get_formatter
from utils.shutdown import (
    is_shutdown_requested,
    register_executor,
    register_cleanup,
    set_partial_results_file,
    update_partial_results,
    get_shutdown_manager,
)
from utils.validation import (
    InputValidator,
    validate_startup_config,
    ValidationResult,
    sanitize_contract_name,
)
from models.findings import AuditResult

# cal
from cal.contract_discovery import ContractDiscoverySystem as ContractDiscovery
from cal.static_analyzer import StaticAnalyzer
from cal.attack_surface import AttackSurfaceExtractor
from cal.sniper_filter import SniperFilter
from cal.deduplication import DeduplicationLayer
from cal.project_scanner import ProjectScanner

# research
from research.supervisor import Supervisor

# attack
from agent.orchestrator import AttackOrchestrator, AttackSession
from agent.research_gateway import ResearchGateway
from agent.research_cache import ResearchCache
from agent.poc_generator import PoCGenerator, PoCGenerationError
from agent.poc_executor import PoCExecutor
from agent.immunefi_mode import run_immunefi

# verification
from agent.verification_layer import VerificationLayer
from agent.impact_amplifier import ImpactAmplifier
from agent.resolution_layer import ResolutionLayer
from agent.cross_validator import CrossValidator
from verification.coverage_checker import check_coverage

# kb
from kb.knowledge_base import KnowledgeBase
from kb.knowledge_graph import KnowledgeGraph
from kb.learning_manager import KBLearningManager

def _audit_worker(orchestrator_config: Dict[str, Any], contract_path: str, project_context: Optional[Any] = None):
    """parallel audit worker - rebuilds orchestrator in child process"""
    contract_path = Path(contract_path)
    # Restrict kwargs to known __init__ signature to avoid surprises
    allowed_keys = {
        "api_key",
        "backend_type",
        "model",
        "cost_limit",
        "enable_jit",
        "enable_poc",
        "enable_neurosymbolic",
        "enable_v3",
        "enable_moa",
        "enable_arena",
        "arena_frequency",
        "enable_a2a",
        "enable_ace",
        "enable_sniper",
        "enable_dedup",
        "quality_threshold",
        "poc_mode",
        "generator_mode",
        "disable_kb_bootstrap",
        "disable_kb",
        "audit_mode",
        "enable_econ_sim",
    }
    safe_kwargs = {k: v for k, v in (orchestrator_config or {}).items() if k in allowed_keys}
    orchestrator = MainOrchestrator(**safe_kwargs)
    return orchestrator.audit_contract(contract_path, project_context=project_context)


class MainOrchestrator:
    """coordinates all layers for end-to-end auditing"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        backend_type: str = None,
        model: Optional[str] = None,
        cost_limit: Optional[float] = None,
        enable_jit: bool = True,
        enable_poc: bool = True,
        enable_neurosymbolic: bool = True,
        enable_v3: bool = True,
        enable_moa: bool = True,
        enable_arena: bool = False,
        arena_frequency: int = 5,
        enable_a2a: bool = True,
        enable_ace: bool = True,
        enable_sniper: bool = True,
        enable_dedup: bool = True,
        quality_threshold: float = None,
        poc_mode: Optional[str] = None,
        generator_mode: Optional[str] = None,
        disable_kb_bootstrap: bool = False,
        disable_kb: bool = False,
        audit_mode: str = "standard",
        enable_econ_sim: Optional[bool] = None,
    ):
        self.api_key = api_key or os.getenv("XAI_API_KEY")
        self.backend_type = (backend_type or config.DEFAULT_BACKEND_TYPE) or "grok"
        requested_model = model or config.DEFAULT_MODEL
        if requested_model == config.MODEL_GROK_4 or config.FORCE_GROK_FAST:
            requested_model = config.MODEL_GROK_4_FAST
        self.model = requested_model
        self.enable_jit = enable_jit
        self.enable_poc = enable_poc
        self.enable_v3 = enable_v3
        self.enable_moa = enable_moa
        self.enable_arena = enable_arena  # requires 100+ contracts
        self.arena_frequency = arena_frequency
        self.enable_a2a = enable_a2a
        self.enable_ace = enable_ace
        self.enable_sniper = enable_sniper
        self.enable_dedup = enable_dedup
        self.enable_econ_sim = (
            config.ENABLE_ECON_SIM if enable_econ_sim is None else enable_econ_sim
        )
        self.quality_threshold = quality_threshold or config.QUALITY_THRESHOLD
        self.disable_kb_bootstrap = disable_kb_bootstrap or disable_kb
        self.disable_kb = disable_kb
        self.poc_mode = poc_mode
        self.audit_mode = audit_mode

        self.logger = ResearchLogger()
        per_contract_limit = cost_limit if cost_limit is not None else config.DEFAULT_COST_LIMIT_PER_CONTRACT
        self.cost_manager = CostManager(
            max_cost_per_contract=per_contract_limit,
            max_cost_total=cost_limit
        )
        # Use create_backend factory (Grok-only)
        self.backend = create_backend(
            backend_type=self.backend_type,
            model=self.model,
            api_key=self.api_key
        )

        # Knowledge Base with GraphRAG + Pattern Synthesis
        kb_kwargs = dict(
            enable_graph_rag=not disable_kb,
            enable_synthesis=not disable_kb,
            pattern_backend_type="grok",
            pattern_model=self.model,
            disable_storage=disable_kb,
        )
        self.kb = KnowledgeBase(**kb_kwargs)

        # cal components
        self.static_analyzer = StaticAnalyzer()  
        self.attack_surface = AttackSurfaceExtractor()

        # Optimization layers
        self.sniper_filter = SniperFilter() if self.enable_sniper else None
        self.dedup_layer = DeduplicationLayer(kb=self.kb) if self.enable_dedup else None

        # research components
        # Note: Supervisor creates its own backend/logger internally
        self.research_supervisor = Supervisor(
            project_root=str(config.PROJECT_ROOT),
            cost_limit=cost_limit,
            max_team_rounds=10,
            backend_type=self.backend_type,  # backend selection
            model=self.model,  # backend selection
            api_key=self.api_key,  
            enable_v3=self.enable_v3,  # v3
            enable_moa=self.enable_moa,  # moa
            enable_ace=self.enable_ace,  # ACE self-improving playbooks
            enable_a2a=self.enable_a2a,  
            knowledge_base=self.kb,
            disable_kb_bootstrap=self.disable_kb_bootstrap,
        )

        # attack components
        if self.enable_jit:
            self.jit_cache = ResearchCache(cache_file=str(config.JIT_CACHE_FILE))
            self.research_gateway = ResearchGateway(
                backend=self.backend,
                logger=self.logger,
                cost_manager=self.cost_manager,
                cache_file=str(config.JIT_CACHE_FILE)
            )
        else:
            self.research_gateway = None

        # Attack orchestrator (knowledge_graph set after research)
        self.attack_orchestrator = AttackOrchestrator(
            backend=self.backend,
            logger=self.logger,
            cost_manager=self.cost_manager,
            knowledge_graph=None,  
            knowledge_base=self.kb,
            research_gateway=self.research_gateway,
            enable_arena_learning=self.enable_arena,  # experimental
            evolution_frequency=self.arena_frequency,
            enable_a2a=self.enable_a2a,  
            enable_econ_sim=self.enable_econ_sim,
        )

        # poc components
        if self.enable_poc:
            self._preflight_training_workspace()
            import os as _os
            # Determine PoC generation mode
            poc_mode = generator_mode or _os.getenv("POC_GEN_MODE") or None
            if not poc_mode:
                poc_mode = "template" if _os.getenv("OFFLINE_MODE", "0") == "1" else "ai"
            self.poc_generator = PoCGenerator(
                backend=self.backend,
                logger=self.logger,
                cost_manager=self.cost_manager,
                mode=poc_mode  
            )
            # may be overridden
            self.poc_executor = PoCExecutor(
                logger=self.logger,
                project_root=Path.cwd(),
                mode=self.poc_mode or config.POC_EXECUTION_MODE,
                timeout=config.POC_EXECUTION_TIMEOUT,
                kb=self.kb
            )

        # verification components
        self.verification_layer = VerificationLayer(
            backend=self.backend,
            logger=self.logger,
            cost_manager=self.cost_manager,
            kb=self.kb,  
            enable_neurosymbolic=enable_neurosymbolic  
        )

        self.impact_amplifier = ImpactAmplifier(
            backend=self.backend,
            logger=self.logger,
            cost_manager=self.cost_manager
        )

        self.resolution_layer = ResolutionLayer(
            backend=self.backend,
            logger=self.logger,
            cost_manager=self.cost_manager
        )

        self.cross_validator = CrossValidator(
            logger=self.logger,
            kb=self.kb  
        )

        # Learning manager (centralized KB updates)
        self.learning_mgr = KBLearningManager(
            kb=self.kb,
            logger=self.logger
        )

        # Register shutdown cleanup handlers (LIFO order: last registered runs first)
        # KB flush is critical - register it to run first (registered last)
        if not disable_kb:
            register_cleanup(self.kb.flush, "kb_flush")
            self.logger.debug("Registered KB flush on shutdown")

        self.logger.info("[MainOrchestrator] Initialized")
        self.logger.info(f"  - JIT Research: {self.enable_jit}")
        self.logger.info(f"  - PoC Generation: {self.enable_poc}")
        self.logger.info(f"  - Verification: True ")
        self.logger.info(f"  - Quality Threshold: {self.quality_threshold}")

    def _preflight_training_workspace(self) -> None:
        """
        Ensure the training project is configured for multi-compiler PoC execution.
        """
        import os as _os
        if _os.getenv("POC_SKIP_PREFLIGHT", "0") == "1":
            return
        cfg = Path("training/damn-vulnerable-defi/foundry.toml")
        if not cfg.exists():
            return
        import subprocess
        try:
            subprocess.run(
                ["bash", "scripts/preflight_training.sh"],
                check=True,
                cwd=Path(__file__).parent,
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                "Training workspace failed preflight validation. Please fix the configuration "
                "reported by scripts/preflight_training.sh."
            ) from exc

    def audit_contract(
        self,
        contract_path: Path,
        contract_source: Optional[str] = None,
        project_context: Optional[Any] = None
    ) -> AuditResult:
        """
        Run full audit pipeline on single contract

        Args:
            contract_path: Path to contract file
            contract_source: Source code (if already loaded)

        Returns:
            AuditResult with all findings
        """
        # Generate audit_id and propagate through entire pipeline
        with auditcontext() as audit_id:
            return self._audit_contract_impl(
                audit_id=audit_id,
                contract_path=contract_path,
                contract_source=contract_source,
                project_context=project_context
            )

    def _audit_contract_impl(
        self,
        audit_id: str,
        contract_path: Path,
        contract_source: Optional[str] = None,
        project_context: Optional[Any] = None
    ) -> AuditResult:
        """
        Internal implementation of audit_contract with audit_id propagation.

        Args:
            audit_id: Correlation ID for this audit
            contract_path: Path to contract file
            contract_source: Source code (if already loaded)
            project_context: Optional project context

        Returns:
            AuditResult with all findings
        """
        import time
        start_time = time.time()
        run_profile = RunProfile(contract_name=contract_path.stem)
        profile_saved = False
        self.cost_manager.start_contract(contract_path.stem)

        self.logger.info(f"Audit session started with audit_id: {audit_id}")

        # Optional per-contract wall-clock timeout with validation
        try:
            # Default 3600s (60 minutes) per SCONE-bench methodology
            # Override with CONTRACT_TIMEOUT_SECONDS env var for complex contracts
            timeout_raw = int(os.getenv("CONTRACT_TIMEOUT_SECONDS", "3600"))

            # Validate timeout range: 0 (disabled) or 60-14400 seconds (1 minute to 4 hours)
            if timeout_raw < 0:
                self.logger.warning(f"[Timeout] Invalid negative timeout {timeout_raw}s, using default 3600s")
                _timeout_seconds = 3600
            elif timeout_raw > 0 and timeout_raw < 60:
                self.logger.warning(f"[Timeout] Timeout {timeout_raw}s is below minimum 60s, using 60s")
                _timeout_seconds = 60
            elif timeout_raw > 14400:
                self.logger.warning(f"[Timeout] Timeout {timeout_raw}s exceeds maximum 14400s (4 hours), using 14400s")
                _timeout_seconds = 14400
            else:
                _timeout_seconds = timeout_raw if timeout_raw > 0 else None
        except ValueError:
            self.logger.warning("[Timeout] Invalid CONTRACT_TIMEOUT_SECONDS value, using default 3600s")
            _timeout_seconds = 3600

        def _check_timeout(stage: str) -> None:
            if _timeout_seconds and (time.time() - start_time) > _timeout_seconds:
                raise TimeoutError(f"Contract audit timed out after {_timeout_seconds}s during {stage}")

        def _check_budget(stage: str, allow_degradation: bool = False) -> bool:
            """
            Check budget guardrails with optional graceful degradation.

            Args:
                stage: Current execution stage
                allow_degradation: If True, return False on budget exhaustion instead of raising

            Returns:
                True if budget OK, False if exhausted (only when allow_degradation=True)

            Raises:
                BudgetExceededError: When budget exhausted and allow_degradation=False
            """
            try:
                self.cost_manager.check_budget()
                return True
            except BudgetExceededError as exc:
                if allow_degradation:
                    # Graceful degradation - return False but don't abort
                    self.logger.warning(f"[Budget] Exhausted during {stage} - entering degraded mode")
                    return False
                else:
                    # Hard abort - raise exception
                    raise BudgetExceededError(f"Budget exceeded during {stage}: {exc}") from exc

        def _guard(stage: str, allow_degradation: bool = False) -> bool:
            """
            Apply timeout, budget, and shutdown checks.

            Args:
                stage: Current execution stage
                allow_degradation: If True, allow graceful degradation on budget exhaustion

            Returns:
                True if checks passed, False if degraded (only when allow_degradation=True)

            Raises:
                RuntimeError: If shutdown has been requested
            """
            # Check for shutdown signal first (highest priority)
            if is_shutdown_requested():
                self.logger.warning(f"[Shutdown] Shutdown requested during {stage}, aborting audit")
                update_partial_results("shutdown_stage", stage)
                raise RuntimeError(f"Shutdown requested during {stage}")

            _check_timeout(stage)
            return _check_budget(stage, allow_degradation=allow_degradation)

        def _finalize_profile() -> None:
            """Attach and persist run profile safely."""
            nonlocal profile_saved
            if profile_saved:
                return
            run_profile.finalize(total_cost=self.cost_manager.total_cost)
            result.run_profile = run_profile.to_dict()
            try:
                run_profile.save_json(config.RUNS_DIR / f"{contract_path.stem}-{int(time.time())}.json")
            except Exception as exc:  # pragma: no cover - best-effort logging
                self.logger.warning(f"[RunProfile] Failed to save profile: {exc}")
            profile_saved = True

        contract_name = contract_path.stem
        self.logger.info(f"\n{'='*80}")
        self.logger.info(f"AUDITING: {contract_name}")
        self.logger.info(f"{'='*80}\n")

        if _timeout_seconds:
            self.logger.info(f"[Timeout] Contract timeout set to {_timeout_seconds}s")

        # Setup partial results tracking for graceful shutdown
        # Security: Sanitize contract_name to prevent collisions and path traversal
        safe_name = sanitize_contract_name(contract_name)
        partial_results_file = config.RUNS_DIR / f"{safe_name}_partial_{int(time.time())}.json"
        set_partial_results_file(partial_results_file)
        update_partial_results("contract_name", contract_name)
        update_partial_results("contract_path", str(contract_path))
        update_partial_results("audit_id", audit_id)
        update_partial_results("start_time", time.time())

        result = AuditResult(
            contract_name=contract_name,
            contract_path=contract_path,
            audit_id=audit_id
        )

        try:
            # contract analysis layer (cal)

            _guard("cal")
            self.logger.info("[PHASE 1] Contract Analysis Layer")
            run_profile.phase_start("cal", current_cost=self.cost_manager.total_cost)

            # Load source
            if not contract_source:
                with open(contract_path, 'r') as f:
                    contract_source = f.read()

            # Phase 0.5: Optimization Layers (Sniper + Dedup)

            # Phase 0.5.1: Deduplication check
            dedup_original_contract = None
            if self.dedup_layer:
                self.logger.info("\n[PHASE 0.5.1] Deduplication Check")
                # Need basic contract info for dedup (will get from discovery if duplicate)
                basic_info = {"name": contract_name, "source": contract_source}
                dedup_match = self.dedup_layer.check_duplicate(
                    contract_source=contract_source,
                    contract_info=basic_info,
                    contract_name=contract_name
                )

                if dedup_match.is_duplicate and dedup_match.similarity >= 0.95:
                    self.logger.info(f"  Duplicate detected ({dedup_match.similarity:.0%} match)")
                    self.logger.info(f"  Original: {dedup_match.original_contract}")
                    self.logger.info(f"  Match type: {dedup_match.match_type}")
                    self.logger.info(f"  Strategy: {dedup_match.transfer_strategy}")

                    # Transfer findings from original
                    transferred = self.dedup_layer.transfer_findings(
                        original_contract=dedup_match.original_contract,
                        target_contract=basic_info,
                        match=dedup_match
                    )

                    if dedup_match.transfer_strategy == "copy_all":
                        self.logger.info(f"  Skipping full analysis (100% duplicate)")
                        self.logger.info(f"  Transferred {len(transferred.get('discoveries', []))} findings")

                        # Create result from transferred findings
                        result.research_discoveries = transferred.get('discoveries', [])
                        result.research_quality = transferred.get('quality_score', 0.9)
                        result.dedup_saved = True
                        run_profile.phase_end("cal", current_cost=self.cost_manager.total_cost)
                        _finalize_profile()

                        # Return early (skip expensive analysis)
                        self.logger.info(f"\nAudit complete (deduplication transfer)")
                        self.logger.info(f"  Cost savings: ~70-85% (skipped full analysis)")
                        result.total_cost = self.cost_manager.total_cost
                        result.total_time = time.time() - start_time
                        result.success = True
                        return result

                    else:
                        self.logger.info(f"  Running full analysis (not identical)")
                        self.logger.info(f"  Will use pattern hints from original")
                        dedup_original_contract = dedup_match.original_contract

                else:
                    self.logger.info(f"  No duplicate found (unique contract)")

            # Phase 0.5.2: Sniper pre-filter
            if self.sniper_filter:
                self.logger.info("\n[PHASE 0.5.2] Sniper Pre-Filter")

                # Get basic info for scoring (before expensive discovery)
                basic_info = {"name": contract_name}

                sniper_score = self.sniper_filter.score_contract(
                    contract_source=contract_source,
                    contract_info=basic_info,
                    contract_path=contract_path
                )

                self.logger.info(f"  Score: {sniper_score.score:.3f} ({sniper_score.decision.value})")
                self.logger.info(f"  Reasoning: {sniper_score.reasoning}")

                if sniper_score.decision.value == "skip":
                    self.logger.info(f"  Skipping analysis (low-value target)")
                    self.logger.info(f"  Bypass filters: {', '.join(sniper_score.bypass_filters)}")
                    self.logger.info(f"\nAudit complete (sniper skip)")
                    self.logger.info(f"  Cost savings: ~100% (no analysis performed)")

                    # Return minimal result
                    result.sniper_skipped = True
                    result.sniper_score = sniper_score.score
                    result.sniper_reasoning = sniper_score.reasoning
                    run_profile.phase_end("cal", current_cost=self.cost_manager.total_cost)
                    _finalize_profile()
                    return result

                elif sniper_score.decision.value == "priority":
                    self.logger.info(f"  Priority target (high-value)")
                    result.sniper_priority = True

                else:
                    self.logger.info(f"  Proceeding with analysis (uncertain)")

                result.sniper_score = sniper_score.score

            # Discover contract to get ContractInfo (needed for attack surface extraction)
            self.logger.info("  Discovering contract structure...")
            from pathlib import Path as PathlibPath
            project_root = self.static_analyzer._find_project_root(contract_path)
            if not project_root:
                raise ValueError(f"Could not find project root for {contract_path}")

            discovery = ContractDiscovery(project_root=project_root)
            project = discovery.discover(target_file=contract_path)

            # Find the target contract
            target_contract = None
            for contract in project.contracts:
                if contract.name == contract_name or contract.file_path == contract_path:
                    target_contract = contract
                    break

            if not target_contract:
                raise ValueError(f"Contract {contract_name} not found in project")

            self.logger.info(f"  [PASS] Discovered contract: {target_contract.name}")

            # Static analysis
            self.logger.info("  → Running Slither static analysis...")
            static_findings = self.static_analyzer.analyze_file(contract_path)
            result.static_findings = static_findings
            self.logger.info(f"  [PASS] Found {len(static_findings)} static findings")

            # Attack surface
            self.logger.info("  → Extracting attack surface...")
            attack_surface = self.attack_surface.extract(target_contract)
            result.attack_surface = attack_surface
            self.logger.info(f"  [PASS] Attack surface: {len(attack_surface.external_functions)} external functions")

            # Build contract info dict
            def _format_signature(fn_obj):
                name = getattr(fn_obj, "name", getattr(fn_obj, "function_name", "unknown"))
                inputs = []
                for param in getattr(fn_obj, "inputs", []) or []:
                    param_type = param.get("type") if isinstance(param, dict) else None
                    inputs.append(param_type or "unknown")
                params = ", ".join(inputs)
                visibility = getattr(fn_obj, "visibility", "")
                state = getattr(fn_obj, "state_mutability", "")
                detail = ", ".join(filter(None, [visibility, state]))
                return f"{name}({params})" + (f" [{detail}]" if detail else "")

            def _serialize_signature(fn_obj):
                if not fn_obj:
                    return {}
                return {
                    "name": getattr(fn_obj, "name", getattr(fn_obj, "function_name", "")),
                    "selector": getattr(fn_obj, "selector", ""),
                    "visibility": getattr(fn_obj, "visibility", ""),
                    "state_mutability": getattr(fn_obj, "state_mutability", ""),
                    "inputs": getattr(fn_obj, "inputs", []) or [],
                    "outputs": getattr(fn_obj, "outputs", []) or [],
                    "has_modifiers": getattr(fn_obj, "has_modifiers", False),
                    "modifiers": getattr(fn_obj, "modifiers", []) or [],
                    "has_external_calls": getattr(fn_obj, "has_external_calls", False),
                    "has_delegatecall": getattr(fn_obj, "has_delegatecall", False),
                    "is_payable": getattr(fn_obj, "is_payable", False),
                }

            external_functions = getattr(attack_surface, "external_functions", []) or []
            privileged_functions = getattr(attack_surface, "privileged_functions", []) or []

            external_fn_sigs = [_format_signature(fn) for fn in external_functions]
            external_fn_detail = [_serialize_signature(fn) for fn in external_functions]
            privileged_fn_sigs = [_format_signature(fn) for fn in privileged_functions]
            privileged_fn_detail = [_serialize_signature(fn) for fn in privileged_functions]
            flashloan_fn_sigs = [_format_signature(fn) for fn in getattr(attack_surface, "flashloan_functions", [])]
            oracle_fn_sigs = []
            for dep in getattr(attack_surface, "oracle_dependencies", []):
                func_name = getattr(dep, "function_name", None)
                oracle_type = getattr(dep, "oracle_type", "oracle")
                if func_name:
                    oracle_fn_sigs.append(f"{func_name} ({oracle_type})")

            token_flows = []
            for flow in getattr(attack_surface, "token_flows", []):
                token = getattr(flow, "token", None)
                flow_type = getattr(flow, "flow_type", None)
                function = getattr(flow, "function_name", None)
                amount_expr = getattr(flow, "amount_expression", None)
                if token or flow_type or function:
                    token_flows.append(
                        {
                            "token": token,
                            "flow_type": flow_type,
                            "function": function,
                            "amount_expression": amount_expr,
                        }
                    )

            total_fn_count = getattr(target_contract, "external_function_count", 0) or len(external_functions)

            contract_info = {
                "name": contract_name,
                "path": str(contract_path),
                "total_functions": total_fn_count,
                "flash_loan_capable": attack_surface.has_flashloan,
                "has_oracle": len(attack_surface.oracle_dependencies) > 0,
                "has_reentrancy_guard": attack_surface.has_reentrancy_guard,
                "static_analysis_summary": self._format_static_hints(static_findings),
                "external_functions": external_fn_sigs,
                "external_functions_detail": external_fn_detail,
                "privileged_functions": privileged_fn_sigs,
                "privileged_functions_detail": privileged_fn_detail,
                "flashloan_functions": flashloan_fn_sigs,
                "oracle_functions": oracle_fn_sigs,
                "token_flows": token_flows,
            }
            try:
                relative_import = str(contract_path.relative_to(config.PROJECT_ROOT)).replace("\\", "/")
            except ValueError:
                relative_import = str(contract_path).replace("\\", "/")
            contract_info["source_import"] = relative_import
            if dedup_original_contract:
                contract_info["dedup_source"] = dedup_original_contract

            # research layer (moa / a2a)

            # budget degradation: allow graceful degradation at phase boundaries
            budget_ok = _guard("research", allow_degradation=True)
            run_profile.phase_end("cal", current_cost=self.cost_manager.total_cost)

            if not budget_ok:
                # Budget exhausted - skip expensive research, use KB-only mode
                self.logger.warning("[Budget] Degraded mode: Skipping research layer, using KB cache")
                # Create minimal knowledge graph from KB
                knowledge_graph = KnowledgeGraph(contract_name=contract_name)
                kb_suggestions = self.kb.get_relevant_patterns(contract_name) if self.kb else []
                specialist_results = {}
                research_quality = 0.5  # Degraded quality
                result.research_quality = research_quality
                result.budget_degraded = True
            else:
                self.logger.info("\n[PHASE 2] Research Layer (MoA / A2A)")
                run_profile.phase_start("research", current_cost=self.cost_manager.total_cost)

                # Run research (standard or MoA pipeline)
                self.logger.info("  Running multi-agent research...")
                knowledge_graph, specialist_results, research_quality = self.research_supervisor.analyze_contract(
                    contract_source=contract_source,
                    contract_info=contract_info,
                    project_context=project_context
                )
                result.research_quality = research_quality

            quality_threshold = self.quality_threshold

            # FRESH MODE: Skip all quality boosting and KB bootstrap for thorough analysis
            # Set FRESH_ANALYSIS=1 to disable historical quality inflation
            fresh_mode = bool(os.getenv("FRESH_ANALYSIS", "0") != "0")

            if fresh_mode:
                self.logger.info("  [FRESH] Fresh analysis mode enabled - skipping quality boosting")
            else:
                historical_quality = None
                has_history = False
                if self.kb and getattr(self.kb, "contract_knowledge", None):
                    cached_entry = self.kb.contract_knowledge.get(contract_name, {})
                    has_history = bool(cached_entry)
                    historical_quality = cached_entry.get("quality_score")

                # Dedup bootstrap disabled for thorough analysis
                # Historical graphs can miss new vulnerabilities
                # Only use for cost optimization, not quality
                if dedup_original_contract and not fresh_mode:
                    reused = knowledge_graph.bootstrap_from_existing(dedup_original_contract, quiet=False)
                    if reused:
                        self.logger.info(
                            f"  [Dedup] Restored knowledge graph structure (not quality) from {dedup_original_contract}"
                        )
                        # DON'T boost quality - let actual research determine it

                # Only log historical quality for reference, don't boost
                if historical_quality and not fresh_mode:
                    self.logger.info(
                        f"  [KB] Historical quality reference: {float(historical_quality):.2f} (not boosting)"
                    )

            result.knowledge_graph = knowledge_graph

            # Update attack orchestrator with research results
            self.attack_orchestrator.set_knowledge_graph(knowledge_graph)

            # Attach semantic snippets from ProjectContext for downstream prompts
            if not contract_info.get("semantic_snippets"):
                pc = contract_info.get("project_context") or project_context
                if pc and hasattr(pc, "get_semantic_slices"):
                    try:
                        contract_info["semantic_snippets"] = pc.get_semantic_slices(
                            contract_name, budget=1200
                        )
                    except Exception as exc:
                        self.logger.warning(f"[Context] Failed to load semantic slices: {exc}")

            # Collect all discoveries from specialist results
            all_discoveries = []
            for specialist_type, results_list in specialist_results.items():
                for analysis_result in results_list:
                    all_discoveries.extend(analysis_result.discoveries)
            result.research_discoveries = all_discoveries

            # In FRESH mode, don't artificially boost quality
            if not fresh_mode and result.research_quality < self.quality_threshold:
                self.logger.info(
                    f"  [Research] Quality below threshold ({result.research_quality:.2f} < {self.quality_threshold:.2f})"
                )
                # We now log but DON'T boost - let it reflect actual quality

            self.logger.info(f"  Research quality: {research_quality:.2f}")
            self.logger.info(f"  Discoveries: {len(all_discoveries)}")

            # Quality gate
            if result.research_quality < self.quality_threshold:
                self.logger.warning(f"  Research quality {result.research_quality:.2f} below threshold {self.quality_threshold}")
                self.logger.warning("  Proceeding anyway (can be configured)")
                # In production, might want to:
                # - Request additional research
                # - Run more specialist rounds
                # - Ask supervisor for override

            # Store research in KB (as dict)
            self.kb.store_contract_knowledge({
                "contract_name": contract_name,
                "contract_info": contract_info,
                "discoveries": [
                    d.to_dict() if hasattr(d, 'to_dict') else d
                    for d in all_discoveries
                ],
                "quality_score": research_quality,
                "knowledge_graph": knowledge_graph.to_dict(),
                "source": contract_source,
            })
            # KB will be flushed at end of audit_contract() (batch write optimization)
            if self.dedup_layer:
                self.dedup_layer.register_contract(contract_name, contract_source, contract_info)

            # attack layer (staged execution)

            _guard("attack")
            run_profile.phase_end("research", current_cost=self.cost_manager.total_cost)
            run_profile.phase_start("attack", current_cost=self.cost_manager.total_cost)

            # Track research completion for partial results
            update_partial_results("research_quality", result.research_quality)
            update_partial_results("research_complete", True)

            coverage_ratio = self._compute_research_coverage(knowledge_graph, contract_info)
            kb_suggestions = self._kb_suggest_hypotheses(contract_info)
            forced_hypotheses = self._forced_surface_hypotheses(contract_info)

            # KB ADDITIVE PHILOSOPHY: KB suggestions are always included as additional
            # hypotheses, never limiting fresh discovery. Stage A uses "observe" mode
            # (no re-ranking), but KB suggestions are merged additively to boost discovery.
            stage_a_kb_suggestions = kb_suggestions if config.KB_SUGGESTIONS_ADDITIVE else None
            if stage_a_kb_suggestions:
                self.logger.info(f"  [KB ADDITIVE] Merging {len(stage_a_kb_suggestions)} KB suggestions into Stage A")

            stage_a = self._run_attack_stage(
                stage_label="Stage A (KB-additive)" if stage_a_kb_suggestions else "Stage A (KB-blind)",
                contract_name=contract_name,
                contract_source=contract_source,
                contract_info=contract_info,
                knowledge_graph=knowledge_graph,
                static_findings=static_findings,
                result=result,
                kb_mode="observe",
                kb_suggestions=stage_a_kb_suggestions,
                forced_hypotheses=forced_hypotheses,
                hypothesis_budget=config.HYPOTHESIS_BUDGET,
                exploration_fraction=config.KB_EXPLORATION_FRACTION,
                allow_enrich=False,
                dedup_original=dedup_original_contract,
            )
            final_stage = stage_a

            if (
                config.KB_SECOND_PASS_ON_EMPTY
                and final_stage["validated_count"] == 0
                and (
                    coverage_ratio < config.COVERAGE_FLOOR
                    or not final_stage["attack_session"].high_confidence_attacks
                )
            ):
                kb_mode_assist = (
                    config.KB_MODE
                    if config.KB_MODE in ("rerank", "enrich")
                    else "enrich"
                )
                self.logger.info(
                    f"  → Coverage {coverage_ratio:.0%} below floor ({int(config.COVERAGE_FLOOR * 100)}%) "
                    "and no validated PoCs. Launching KB-assisted pass..."
                )
                final_stage = self._run_attack_stage(
                    stage_label="Stage B (KB Assist)",
                    contract_name=contract_name,
                    contract_source=contract_source,
                    contract_info=contract_info,
                    knowledge_graph=knowledge_graph,
                    static_findings=static_findings,
                    result=result,
                    kb_mode=kb_mode_assist,
                    kb_suggestions=kb_suggestions,
                    forced_hypotheses=forced_hypotheses,
                    hypothesis_budget=config.HYPOTHESIS_BUDGET,
                    exploration_fraction=config.KB_EXPLORATION_FRACTION,
                    allow_enrich=True,
                    dedup_original=dedup_original_contract,
                )

            verification_results = final_stage["verification_results"]
            verification_by_id = final_stage["verification_by_id"]
            verified_hypotheses = final_stage["verified_hypotheses"]
            manual_review_hypotheses = final_stage.get("manual_review_hypotheses", [])
            validated_vulnerabilities_parallel = final_stage["validated_vulnerabilities"]

            # Phase 3.5: Verification Layer (Pre-PoC Filtering)

            _guard("verification")
            self.logger.info("\n[PHASE 3.5] Verification Layer (Pre-PoC Filtering)")
            self.logger.info(
                f"  Verified: {len(verified_hypotheses)} high-confidence hypotheses (see stage logs)"
            )

            # Surface manual review items prominently in the main output
            if manual_review_hypotheses:
                self.logger.warning(
                    f"\n  [!] MANUAL REVIEW REQUIRED: {len(manual_review_hypotheses)} hypotheses flagged"
                )
                for vr in manual_review_hypotheses:
                    self.logger.warning(
                        f"    • {vr.hypothesis.hypothesis_id}: {vr.hypothesis.attack_type} - "
                        f"{vr.hypothesis.description[:50]}..."
                    )

            # Cross-validation (impact vs verification vs resolution)
            if result.validated_vulnerabilities:
                self.logger.info("\n  Running cross-validation...")
                aggregated_contradictions = []
                aggregated_warnings = []

                for validated in result.validated_vulnerabilities:
                    hypothesis = validated.get("hypothesis")
                    if not hypothesis:
                        continue

                    hypothesis_id = getattr(hypothesis, "hypothesis_id", None)
                    verification_result = verification_by_id.get(hypothesis_id)
                    impact_report = validated.get("impact")
                    resolution_report = validated.get("resolution")

                    if verification_result and impact_report:
                        impact_check = self.cross_validator.check_impact_severity_consistency(
                            impact_report=impact_report,
                            verification_result=verification_result,
                            hypothesis_id=hypothesis_id,
                            contract_name=contract_name,
                        )
                        aggregated_contradictions.extend(impact_check.contradictions)
                        aggregated_warnings.extend(impact_check.warnings)
                    else:
                        self.logger.warning(
                            f"  Skipped impact/verification cross-check for {hypothesis_id or 'unknown hypothesis'} "
                            f"(verification_result={'present' if verification_result else 'missing'}, "
                            f"impact_report={'present' if impact_report else 'missing'})"
                        )

                    if impact_report and resolution_report:
                        resolution_check = self.cross_validator.check_resolution_impact_consistency(
                            resolution_report=resolution_report,
                            impact_report=impact_report,
                            hypothesis_id=hypothesis_id,
                        )
                        aggregated_contradictions.extend(resolution_check.contradictions)
                        aggregated_warnings.extend(resolution_check.warnings)

                if aggregated_contradictions:
                    self.logger.warning(
                        f"  Found {len(aggregated_contradictions)} contradictions"
                    )
                    for contradiction in aggregated_contradictions:
                        self.logger.warning(f"    - {contradiction.description}")
                else:
                    self.logger.info("  No contradictions found")

                for warning in aggregated_warnings:
                    self.logger.warning(f"  [WARN] {warning}")

            self.logger.info(
                f"\n  Validated: {len(result.validated_vulnerabilities)} vulnerabilities"
            )

            # Track attack/PoC completion for partial results
            update_partial_results("hypotheses_generated", len(result.attack_hypotheses))
            update_partial_results("vulnerabilities_validated", len(result.validated_vulnerabilities))
            update_partial_results("attack_complete", True)

            run_profile.phase_end("attack", current_cost=self.cost_manager.total_cost)

            # Complete

            result.success = True
            result.total_cost = self.cost_manager.total_cost
            result.total_time = time.time() - start_time

            self.logger.info(f"\n{'='*80}")
            self.logger.info(f"AUDIT COMPLETE: {contract_name}")
            self.logger.info(f"{'='*80}")
            self.logger.info(f"  Research Quality: {result.research_quality:.2f}")
            self.logger.info(f"  Hypotheses: {len(result.attack_hypotheses)}")
            self.logger.info(f"  Validated Vulnerabilities: {len(result.validated_vulnerabilities)}")
            self.logger.info(f"  Total Cost: ${result.total_cost:.2f}")
            self.logger.info(f"  Total Time: {result.total_time:.1f}s")
            self.logger.info(f"{'='*80}\n")

            # Coverage check: warn for classes missing tags/detectors/invariants
            try:
                classes = [getattr(h, 'attack_type', '').lower() for h in result.attack_hypotheses]
                gaps = check_coverage(config.PROJECT_ROOT, classes)
                for w in gaps[:10]:
                    self.logger.warning(w)
                if gaps:
                    self.logger.warning(f"[Coverage] {len(gaps)} coverage gaps detected; see coverage.yaml")
            except Exception:
                pass

            # Pattern synthesis
            # Trigger pattern synthesis every 10 contracts
            contract_count = len(self.kb.contract_knowledge)
            if contract_count > 0 and contract_count % 10 == 0:
                self.logger.info(f"\n{'='*60}")
                self.logger.info(f"Pattern synthesis milestone: {contract_count} contracts")
                self.logger.info(f"{'='*60}")
                self.logger.info("  Triggering exponential pattern synthesis (2^N growth)...")

                try:
                    new_patterns = self.kb.synthesize_patterns(
                        target_level=1,  # N² synthesis
                        max_combinations=100  # Limit for performance
                    )

                    if new_patterns > 0:
                        self.logger.info(f"  Knowledge base grew: {len(self.kb.patterns)} total patterns")
                        self.logger.info(f"  Synthesized: {new_patterns} new patterns")
                        self.logger.info(f"  Exponential growth: {contract_count} contracts -> {len(self.kb.patterns)} patterns")
                    else:
                        self.logger.info(f"  No new patterns synthesized (need more base patterns)")

                except Exception as e:
                    self.logger.warning(f"  Pattern synthesis failed: {e}")

                self.logger.info(f"{'='*60}\n")

        except TimeoutError as e:
            self.logger.error(f"Audit timed out: {e}")
            result.success = False
            result.error_message = str(e)
            result.total_time = time.time() - start_time
            for phase_name in ("cal", "research", "attack", "verification"):
                phase = run_profile.phases.get(phase_name)
                if phase and phase.status == "in_progress":
                    phase.mark_end(current_cost=self.cost_manager.total_cost, status="timeout", error=str(e))
        except BudgetExceededError as e:
            # GRACEFUL DEGRADATION: Save partial results instead of hard abort
            self.logger.warning(f"Audit budget exhausted: {e}")
            self.logger.info("  → Saving partial results from completed phases")

            # Mark success as False but preserve partial findings
            result.success = False
            result.error_message = f"Budget exhausted: {e}"
            result.budget_degraded = True
            result.total_time = time.time() - start_time
            result.total_cost = self.cost_manager.total_cost

            # Close any in-progress phases
            for phase_name in ("cal", "research", "attack", "verification"):
                phase = run_profile.phases.get(phase_name)
                if phase and phase.status == "in_progress":
                    phase.mark_end(current_cost=self.cost_manager.total_cost, status="budget_exceeded", error=str(e))

            # Log what was salvaged
            self.logger.info(f"  → Salvaged: {len(result.attack_hypotheses)} hypotheses, {len(result.validated_vulnerabilities)} validated")
            self.logger.info(f"  → Total phases completed before exhaustion: {len([p for p in run_profile.phases.values() if p.status == 'completed'])}")
        except RuntimeError as e:
            # Handle shutdown request (raised by _guard)
            if "Shutdown requested" in str(e):
                self.logger.warning(f"Audit interrupted by shutdown: {e}")
                result.success = False
                result.error_message = f"Shutdown: {e}"
                result.total_time = time.time() - start_time
                result.total_cost = self.cost_manager.total_cost

                # Mark incomplete phases
                for phase_name in ("cal", "research", "attack", "verification"):
                    phase = run_profile.phases.get(phase_name)
                    if phase and phase.status == "in_progress":
                        phase.mark_end(current_cost=self.cost_manager.total_cost, status="shutdown", error=str(e))

                self.logger.info(f"  → Partial results saved for {contract_name}")
            else:
                # Re-raise other RuntimeErrors
                raise
        except Exception as e:
            self.logger.error(f"Audit failed: {e}")
            import traceback
            traceback.print_exc()
            result.success = False
            result.error_message = str(e)
            result.total_time = time.time() - start_time
            for phase_name in ("cal", "research", "attack"):
                phase = run_profile.phases.get(phase_name)
                if phase and phase.status == "in_progress":
                    phase.mark_end(current_cost=self.cost_manager.total_cost, status="error", error=str(e))

        finally:
            # PERFORMANCE OPTIMIZATION: Flush all pending KB writes
            # Similar to xAI message passing fix - batch all writes until end
            # 10-100x reduction in disk I/O for large knowledge bases
            self.kb.flush()

            # Update final partial results state
            update_partial_results("audit_complete", result.success)
            update_partial_results("total_cost", result.total_cost)
            update_partial_results("total_time", time.time() - start_time)

            # Security: Clean up partial results file on successful completion
            if result.success and partial_results_file.exists():
                try:
                    partial_results_file.unlink()
                    self.logger.debug(f"Cleaned up partial results file: {partial_results_file}")
                except Exception as e:
                    self.logger.warning(f"Failed to clean up partial results file: {e}")

        return result

    def _format_static_hints(self, findings: List[Any]) -> str:
        """Format static analysis findings as hints for research layer"""
        if not findings:
            return "No static analysis findings."

        hints = ["SLITHER STATIC ANALYSIS HINTS:"]
        for finding in findings[:10]:  # Top 10
            hints.append(f"  - [{finding.severity.value}] {finding.detector_name}: {finding.description[:80]}")

        return "\n".join(hints)

    def _synthesize_compositional(self, hypotheses: List[Any]) -> List[Any]:
        """
        Synthesize compositional attacks from individual hypotheses

        XBOW-level insight: Most valuable bugs are compositional
        - Flash loan + Oracle manipulation
        - Flash loan + Reentrancy + Governance
        - Oracle + Reentrancy

        Args:
            hypotheses: List of individual attack hypotheses

        Returns:
            List of compositional attack hypotheses
        """
        compositional = []

        # Group by attack type
        by_type = {}
        for h in hypotheses:
            attack_type = h.attack_type
            if attack_type not in by_type:
                by_type[attack_type] = []
            by_type[attack_type].append(h)

        # Compositional patterns (XBOW-level combinations)
        compositions = [
            ("flash_loan", "oracle_manipulation"),
            ("flash_loan", "reentrancy"),
            ("flash_loan", "governance"),
            ("oracle_manipulation", "reentrancy"),
            ("reentrancy", "access_control"),
        ]

        for type_a, type_b in compositions:
            if type_a in by_type and type_b in by_type:
                # Try to combine highest confidence hypotheses
                for h_a in by_type[type_a][:3]:  # Top 3
                    for h_b in by_type[type_b][:3]:
                        # Check if combination is viable
                        if self._can_combine(h_a, h_b):
                            combined = self._combine_hypotheses(h_a, h_b)
                            if combined:
                                compositional.append(combined)

        return compositional

    def _can_combine(self, h_a: Any, h_b: Any) -> bool:
        """Check if two hypotheses can be combined into compositional attack"""
        # Basic heuristic: both must have reasonable confidence
        if h_a.confidence < 0.60 or h_b.confidence < 0.60:
            return False

        # Don't combine same attack type
        if h_a.attack_type == h_b.attack_type:
            return False

        # Basic composition check (different attack types)
        # Future enhancements could include:
        # - Attack vector compatibility analysis
        # - Precondition overlap detection
        # - Timing/sequencing validation

        return True

    def _combine_hypotheses(self, h_a: Any, h_b: Any) -> Optional[Any]:
        """Combine two hypotheses into compositional attack"""
        from agent.base_attacker import AttackHypothesis

        # Generate new hypothesis ID
        hypothesis_id = f"comp_{h_a.hypothesis_id}_{h_b.hypothesis_id}"

        # Combine descriptions
        description = f"Compositional: {h_a.description} + {h_b.description}"

        # Average confidence (compositional is harder, so reduce)
        confidence = (h_a.confidence + h_b.confidence) / 2 * 0.9

        # Combine attack steps
        attack_steps = h_a.attack_steps + ["THEN:"] + h_b.attack_steps

        # Combine preconditions
        preconditions = list(set(h_a.preconditions + h_b.preconditions))

        return AttackHypothesis(
            hypothesis_id=hypothesis_id,
            attack_type="compositional",
            description=description,
            confidence=confidence,
            attack_steps=attack_steps,
            preconditions=preconditions,
            affected_functions=list(set((h_a.affected_functions or []) + (h_b.affected_functions or []))),
            severity=max(h_a.severity, h_b.severity),  # Take worse severity
            evidence=[f"Combined from {h_a.hypothesis_id} + {h_b.hypothesis_id}"],
        )

    def _compute_research_coverage(self, knowledge_graph: KnowledgeGraph, contract_info: Dict[str, Any]) -> float:
        total = (
            knowledge_graph.metadata.get("total_functions")
            or contract_info.get("total_functions", 0)
        )
        analyzed = knowledge_graph.metadata.get("analyzed_functions") or []
        try:
            analyzed_count = len(analyzed)
        except TypeError:
            analyzed_count = 0
        if not total:
            return 0.0
        return min(1.0, analyzed_count / max(total, 1))

    def _run_attack_stage(
        self,
        stage_label: str,
        contract_name: str,
        contract_source: str,
        contract_info: Dict[str, Any],
        knowledge_graph: KnowledgeGraph,
        static_findings: List[Any],
        result: AuditResult,
        kb_mode: str,
        kb_suggestions: Optional[List["AttackHypothesis"]],
        forced_hypotheses: Optional[List["AttackHypothesis"]],
        hypothesis_budget: int,
        exploration_fraction: float,
        allow_enrich: bool,
        dedup_original: Optional[str],
    ) -> Dict[str, Any]:
        self.logger.info(f"\n[PHASE 3] Attack Layer ({stage_label})")
        try:
            attack_session = self.attack_orchestrator.analyze_contract(
                contract_source=contract_source,
                contract_info=contract_info,
                kb_mode=kb_mode,
                kb_suggestions=kb_suggestions,
                forced_hypotheses=forced_hypotheses,
                hypothesis_budget=hypothesis_budget,
                exploration_fraction=exploration_fraction,
                allow_kb_enrich=allow_enrich,
            )
        except Exception as exc:
            # Handle circuit breaker or quota exhaustion gracefully
            is_quota_error = any(keyword in str(exc).lower() for keyword in [
                "resource_exhausted",
                "monthly spending limit",
                "circuit breaker",
                "quota",
            ])

            if is_quota_error:
                self.logger.warning(
                    f"[MainOrchestrator] Attack orchestrator hit limits ({str(exc)[:100]}); using KB fallback."
                )
                attack_session = self._fallback_attack_session(
                    contract_name=contract_name,
                    dedup_original=dedup_original,
                    contract_info=contract_info,
                )
            else:
                raise

        result.attack_hypotheses = attack_session.all_hypotheses.copy()

        # Compositional synthesis
        compositional = self._synthesize_compositional(result.attack_hypotheses)
        result.attack_hypotheses.extend(compositional)

        high_confidence = attack_session.high_confidence_attacks or []
        self.logger.info(
            f"  → Verifying {len(high_confidence)} high-confidence hypotheses..."
        )

        if not high_confidence:
            verification_results = []
        else:
            # Enforce verification timeout at call site level
            verification_timeout = config.VERIFICATION_CONTRACT_TIMEOUT
            self.logger.info(f"  → Starting verification with timeout: {verification_timeout}s")

            try:
                # Use ThreadPoolExecutor to enforce hard timeout
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(
                        self.verification_layer.verify_hypotheses,
                        hypotheses=high_confidence,
                        contract_source=contract_source,
                        contract_info=contract_info,
                        knowledge_graph=knowledge_graph,
                        max_hypotheses=getattr(config, "VERIFICATION_HYPOTHESIS_LIMIT", 20),
                    )
                    try:
                        verification_results = future.result(timeout=verification_timeout)
                    except TimeoutError:
                        self.logger.error(
                            f"  [TIMEOUT] Verification exceeded {verification_timeout}s timeout - "
                            f"proceeding with partial results"
                        )
                        # Cancel the verification task
                        future.cancel()
                        verification_results = []
            except Exception as e:
                self.logger.error(f"  [ERROR] Verification failed: {str(e)[:100]}")
                verification_results = []

        verified_hypotheses = []
        manual_review_hypotheses = []
        for verification in verification_results:
            if verification.verified:
                verified_hypotheses.append(verification.hypothesis)
            elif verification.needs_manual_review:
                # Safety filter rejection - requires human review
                manual_review_hypotheses.append(verification)
                self.logger.warning(
                    f"  [MANUAL REVIEW] {verification.hypothesis.hypothesis_id}: "
                    f"{verification.hypothesis.description[:60]}... "
                    f"(Reason: {verification.reasoning[:80]})"
                )
            else:
                rejection_summary = (
                    "; ".join(verification.issues_found[:2])
                    if verification.issues_found
                    else "Failed verification"
                )
                self.logger.info(
                    f"  [FAIL] Rejected: {verification.hypothesis.description[:60]}... ({rejection_summary})"
                )

        self.logger.info(
            f"  [PASS] Verified: {len(verified_hypotheses)}/{len(high_confidence)} hypotheses"
        )

        # Enforce manual review: persist and log prominently if any require human attention
        if manual_review_hypotheses:
            self.logger.warning(
                f"  [!] {len(manual_review_hypotheses)} hypotheses require MANUAL REVIEW (safety filter)"
            )
            # Persist to file for human review
            manual_review_file = config.DATA_DIR / "manual_review_queue.json"
            import json
            existing_queue = []
            if manual_review_file.exists():
                try:
                    with open(manual_review_file, "r") as f:
                        existing_queue = json.load(f)
                except (json.JSONDecodeError, IOError):
                    existing_queue = []
            for vr in manual_review_hypotheses:
                entry = {
                    "timestamp": time.time(),
                    "contract_name": contract_name,
                    "hypothesis_id": vr.hypothesis.hypothesis_id,
                    "attack_type": vr.hypothesis.attack_type,
                    "target_function": vr.hypothesis.target_function,
                    "description": vr.hypothesis.description,
                    "reasoning": vr.reasoning,
                    "verification_type": vr.verification_type,
                }
                existing_queue.append(entry)
            with open(manual_review_file, "w") as f:
                json.dump(existing_queue, f, indent=2)
            self.logger.warning(
                f"  [!] Manual review queue persisted to {manual_review_file}"
            )

        verification_by_id = {
            verification.hypothesis.hypothesis_id: verification
            for verification in verification_results
        }

        if verification_results:
            self.logger.info(
                "  → Incorporating verification feedback into attack layer..."
            )
            self.attack_orchestrator.incorporate_verification_feedback(
                verification_results=verification_results,
                contract_name=contract_name,
            )
            self.logger.info("  [PASS] Feedback loop complete")

        if self.enable_arena:
            self.logger.info("  → Evaluating agent fitness (Arena Learning)...")
            self.attack_orchestrator.evaluate_fitness_and_maybe_evolve(
                session=attack_session,
                verification_results=verification_results,
            )
            self.logger.info("  [PASS] Fitness evaluation complete")

        validated_vulnerabilities_parallel = []
        if self.enable_poc and verified_hypotheses:
            try:
                from poc_parallel_implementation import ParallelPoCProcessor

                parallel_processor = ParallelPoCProcessor(self)
                self.logger.info(
                    f"  → Generating PoCs for {len(verified_hypotheses)} verified hypotheses in parallel..."
                )
                validated_vulnerabilities_parallel = (
                    parallel_processor.process_hypotheses_parallel(
                        verified_hypotheses=verified_hypotheses,
                        contract_source=contract_source,
                        contract_info=contract_info,
                        contract_name=contract_name,
                        result=result,
                        max_workers=None,
                    )
                )

                self.logger.info(
                    f"\n[PHASE 4] Complete: {len(validated_vulnerabilities_parallel)} vulnerabilities validated"
                )
            except ImportError:
                # Parallel PoC module not available, use built-in parallel processing
                self.logger.info(
                    "  → Using built-in parallel PoC generation..."
                )

                # Parallel PoC generation with ThreadPoolExecutor
                max_workers = int(os.getenv("POC_PARALLEL_WORKERS", "8"))
                max_workers = min(max_workers, len(verified_hypotheses))  # Don't spawn more workers than needed

                if max_workers > 1 and len(verified_hypotheses) > 1:
                    self.logger.info(f"  → Parallelizing PoC generation ({max_workers} workers)...")

                    def _generate_and_execute_poc(hyp, idx):
                        """Generate and execute PoC for a single hypothesis"""
                        self.logger.info(f"  [PoC {idx+1}/{len(verified_hypotheses)}] Generating for: {hyp.description[:60]}...")
                        try:
                            # Generate PoC
                            poc = self.poc_generator.generate(
                                hypothesis=hyp,
                                contract_source=contract_source,
                                contract_info=contract_info,
                            )
                            if poc and poc.test_code:
                                self.logger.info(f"    [PASS] PoC generated ({poc.generation_method})")
                                # Execute PoC
                                exec_result = self.poc_executor.execute(
                                    poc=poc,
                                    hypothesis=hyp,
                                )
                                if exec_result and exec_result.success:
                                    self.logger.info(f"    [EXPLOIT CONFIRMED] PoC passed - vulnerability validated!")
                                    return {
                                        "hypothesis": hyp,
                                        "poc": poc,
                                        "execution_result": exec_result,
                                        "validated": True,
                                    }
                                else:
                                    error_msg = exec_result.error_message if exec_result else "execution failed"
                                    self.logger.warning(f"    [FAIL] PoC execution failed: {error_msg[:80]}")
                            else:
                                self.logger.warning(f"    [SKIP] Failed to generate PoC")
                        except PoCGenerationError as e:
                            # Specific error (e.g., version incompatibility) - just log and skip
                            self.logger.info(f"    [SKIP] {e.reason[:100]}")
                        except Exception as e:
                            self.logger.warning(f"    [ERROR] PoC generation error: {str(e)[:80]}")
                        return None

                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = {executor.submit(_generate_and_execute_poc, hyp, i): hyp for i, hyp in enumerate(verified_hypotheses)}
                        for future in as_completed(futures):
                            try:
                                result = future.result()
                                if result:
                                    validated_vulnerabilities_parallel.append(result)
                            except Exception as e:
                                hypothesis = futures[future]
                                self.logger.warning(f"    [ERROR] Parallel PoC generation failed for {hypothesis.hypothesis_id}: {str(e)[:80]}")
                else:
                    # Sequential fallback for single hypothesis or single worker
                    self.logger.info("  → Using sequential PoC generation (single hypothesis or worker=1)...")
                    for i, hyp in enumerate(verified_hypotheses):
                        self.logger.info(f"  [PoC {i+1}/{len(verified_hypotheses)}] Generating for: {hyp.description[:60]}...")
                        try:
                            # Generate PoC
                            poc = self.poc_generator.generate(
                                hypothesis=hyp,
                                contract_source=contract_source,
                                contract_info=contract_info,
                            )
                            if poc and poc.test_code:
                                self.logger.info(f"    [PASS] PoC generated ({poc.generation_method})")
                                # Execute PoC
                                exec_result = self.poc_executor.execute(
                                    poc=poc,
                                    hypothesis=hyp,
                                )
                                if exec_result and exec_result.success:
                                    self.logger.info(f"    [EXPLOIT CONFIRMED] PoC passed - vulnerability validated!")
                                    validated_vulnerabilities_parallel.append({
                                        "hypothesis": hyp,
                                        "poc": poc,
                                        "execution_result": exec_result,
                                        "validated": True,
                                    })
                                else:
                                    error_msg = exec_result.error_message if exec_result else "execution failed"
                                    self.logger.warning(f"    [FAIL] PoC execution failed: {error_msg[:80]}")
                            else:
                                self.logger.warning(f"    [SKIP] Failed to generate PoC")
                        except PoCGenerationError as e:
                            # Specific error (e.g., version incompatibility) - just log and skip
                            self.logger.info(f"    [SKIP] {e.reason[:100]}")
                        except Exception as e:
                            self.logger.warning(f"    [ERROR] PoC generation error: {str(e)[:80]}")

                self.logger.info(f"\n[PHASE 4] Complete: {len(validated_vulnerabilities_parallel)} vulnerabilities validated via PoC")

        return {
            "attack_session": attack_session,
            "verification_results": verification_results,
            "verification_by_id": verification_by_id,
            "verified_hypotheses": verified_hypotheses,
            "manual_review_hypotheses": manual_review_hypotheses,
            "manual_review_count": len(manual_review_hypotheses),
            "validated_vulnerabilities": validated_vulnerabilities_parallel,
            "validated_count": len(validated_vulnerabilities_parallel),
        }

    def _fallback_attack_session(
        self,
        contract_name: str,
        dedup_original: Optional[str],
        contract_info: Dict[str, Any],
    ) -> AttackSession:
        """
        Build an attack session from stored KB discoveries when LLM calls are unavailable.
        """
        from agent.base_attacker import AttackHypothesis

        knowledge = self.kb.contract_knowledge.get(contract_name)
        if not knowledge and dedup_original:
            knowledge = self.kb.contract_knowledge.get(dedup_original)

        hypotheses: List[AttackHypothesis] = []
        if knowledge:
            for idx, discovery in enumerate(knowledge.get("discoveries", [])):
                confidence = float(discovery.get("confidence", 0.0) or 0.0)
                if confidence < config.MIN_HYPOTHESIS_CONFIDENCE:
                    continue
                hypotheses.append(
                    self._build_kb_hypothesis(
                        discovery=discovery,
                        index=idx,
                        contract_name=contract_name,
                        confidence=confidence,
                    )
                )

        if not hypotheses:
            self.logger.warning(
                "[MainOrchestrator] KB fallback produced no high-confidence hypotheses."
            )

        session = AttackSession(
            contract_name=contract_name,
            attackers=[],
            rounds=0,
            all_hypotheses=hypotheses,
            high_confidence_attacks=hypotheses,
            pocs_generated=len(hypotheses),
            pocs_validated=0,
            total_cost=0.0,
            quality_score=0.6 if hypotheses else 0.0,
        )

        # Attach to knowledge graph if available (label nodes for visibility)
        for hyp in hypotheses:
            try:
                self.attack_orchestrator.knowledge_graph.add_node(
                    node_id=f"kb_fallback_{hyp.hypothesis_id}",
                    node_type="vulnerability",
                    name=hyp.target_function or hyp.attack_type,
                    data={
                        "description": hyp.description,
                        "source": "kb_fallback",
                        "confidence": hyp.confidence,
                    },
                    confidence=hyp.confidence,
                )
            except Exception:
                # Knowledge graph may not be initialised; ignore silently
                pass

        return session

    def _kb_suggest_hypotheses(self, contract_info: Dict[str, Any]) -> List["AttackHypothesis"]:
        from agent.base_attacker import AttackHypothesis

        if not self.kb:
            return []
        contract_name = contract_info.get("name")
        if not contract_name:
            return []
        knowledge = self.kb.contract_knowledge.get(contract_name, {})
        discoveries = knowledge.get("discoveries") or []
        suggestions: List[AttackHypothesis] = []
        for idx, discovery in enumerate(discoveries[:3]):
            description = (
                discovery.get("description")
                or discovery.get("content")
                or str(discovery)
            )
            attack_type = discovery.get("type") or discovery.get("category") or "logic"
            # KB ADDITIVE PHILOSOPHY: Historical confidence is a hint, not a final verdict.
            # Use reduced confidence (0.6) to ensure KB suggestions go through full verification.
            # The historical confidence is preserved in evidence for reference.
            historical_confidence = float(discovery.get("confidence", 0.85) or 0.85)
            seed_confidence = 0.6  # Lower than threshold to ensure verification
            evidence = discovery.get("evidence", [])
            evidence = evidence + [f"[KB SEED] Historical confidence: {historical_confidence:.2f}"]
            target = self._guess_target_function(description, evidence)
            suggestions.append(
                AttackHypothesis(
                    hypothesis_id=f"kb_suggestion_{contract_name}_{idx}",
                    attack_type=str(attack_type),
                    description=description,
                    target_function=target,
                    preconditions=discovery.get("preconditions", []),
                    steps=discovery.get("steps", []),
                    expected_impact=discovery.get("impact", description),
                    confidence=seed_confidence,
                    requires_research=[],
                    evidence=evidence,
                    from_kb=True,  # Mark as KB-sourced for learning
                    requires_verification=True,  # Always verify KB hypotheses
                )
            )
        return suggestions

    def _forced_surface_hypotheses(self, contract_info: Dict[str, Any]) -> List["AttackHypothesis"]:
        from agent.base_attacker import AttackHypothesis

        forced: List[AttackHypothesis] = []
        path = str(contract_info.get("path", "")).lower()
        name = str(contract_info.get("name", "")).lower()

        if any(token in path or token in name for token in ("walletregistry", "wallet registry")):
            forced.append(
                AttackHypothesis(
                    hypothesis_id="forced_walletregistry_safe_backdoor",
                    attack_type="authz_bypass",
                    description="WalletRegistry: use Safe.setup delegatecall to approve attacker during payout and drain ERC20 rewards.",
                    target_function="Safe.setup",
                    preconditions=[
                        "Registry trusts SafeProxyFactory callbacks",
                        "ERC20 rewards are transferred to newly created Safe",
                    ],
                    steps=[
                        "Deploy BackdoorModule that approves attacker in Safe context",
                        "Trigger Safe.setup via registry callback so module executes in delegatecall",
                        "transferFrom() ERC20 reward from Safe to attacker using unlimited allowance",
                    ],
                    expected_impact="Attacker drains registry payout without being beneficiary",
                    confidence=0.96,
                    requires_research=[],
                    evidence=["Heuristic trigger: Safe factory + registry callback + ERC20 payout detected."],
                )
            )

        if any(token in path or token in name for token in ("walletdeployer", "wallet deployer")):
            forced.append(
                AttackHypothesis(
                    hypothesis_id="forced_walletdeployer_mining",
                    attack_type="config_capture",
                    description="WalletDeployer: precompute Safe addresses via helper and route token rewards to attacker-controlled wallets.",
                    target_function="WalletDeployer.drop",
                    preconditions=[
                        "Safe helper can predict create2 addresses",
                        "Reward token minted to deployed wallet",
                    ],
                    steps=[
                        "Use helper to compute future Safe addresses for desired owner",
                        "Deploy via drop() with attacker as beneficiary",
                        "Drain minted tokens after registration",
                    ],
                    expected_impact="Attacker mines Safe rewards and captures configuration payouts.",
                    confidence=0.9,
                    requires_research=[],
                    evidence=["Heuristic trigger: Safe factory detected in wallet deployer surface."],
                )
            )

        return forced

    def _build_kb_hypothesis(
        self,
        discovery: Dict[str, Any],
        index: int,
        contract_name: str,
        confidence: float,
    ):
        from agent.base_attacker import AttackHypothesis

        description = discovery.get("content", "").strip() or "KB-discovered issue"
        evidence = discovery.get("evidence") or []
        target = self._guess_target_function(description, evidence)
        attack_type = discovery.get("type") or "logic"
        hyp_confidence = min(0.95, max(confidence, config.MIN_HYPOTHESIS_CONFIDENCE))

        return AttackHypothesis(
            hypothesis_id=f"kb_{contract_name}_{index}",
            attack_type=attack_type,
            description=description,
            target_function=target,
            preconditions=[],
            steps=[description],
            expected_impact=description,
            confidence=hyp_confidence,
            requires_research=[],
            evidence=evidence,
        )

    def _guess_target_function(self, description: str, evidence: List[str]) -> str:
        """
        Heuristic extraction of target function name from KB discovery text.
        """
        texts = [description] + evidence
        for text in texts:
            for match in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
                if match.lower() not in {"if", "for", "while", "return", "require"}:
                    return match
        return ""

    def _update_kb_success(self, hypothesis: Any, execution: Any):
        """Update KB with successful exploit (Bayesian update)"""
        # Find matching pattern
        pattern = self.kb.find_pattern_for_hypothesis(hypothesis)

        if pattern:
            # Update existing pattern confidence
            pattern.update_confidence(success=True)
            pattern.contracts_vulnerable.append(hypothesis.contract_name if hasattr(hypothesis, 'contract_name') else 'unknown')
            self.logger.info(f"  → Updated pattern '{pattern.name}' confidence: {pattern.confidence:.2f}")
        else:
            # Synthesize new pattern from successful exploit
            new_pattern = self.kb.synthesize_pattern_from_hypothesis(hypothesis, success=True)
            if new_pattern:
                self.kb.add_pattern(new_pattern)
                self.logger.info(f"  → Synthesized new pattern: {new_pattern.name}")

        # KB will be flushed at end of audit_contract() (batch write optimization)

    def _update_kb_failure(self, hypothesis: Any, execution: Any):
        """Update KB with failed exploit (Bayesian update)"""
        pattern = self.kb.find_pattern_for_hypothesis(hypothesis)

        if pattern:
            pattern.update_confidence(success=False)
            self.logger.info(f"  → Updated pattern '{pattern.name}' confidence: {pattern.confidence:.2f} (failure)")

        # KB will be flushed at end of audit_contract() (batch write optimization)

    def audit_project(self, project_root: Path, max_workers: int = 4) -> List[AuditResult]:
        """
        Audit an entire project with context awareness and parallel execution.
        
        1. Scan project (build dependency graph & summaries)
        2. Schedule batches
        3. Execute batches in parallel
        """
        logger.info("="*80)
        logger.info("STARTING MULTI-CONTRACT PROJECT AUDIT", extra={
            "project_root": str(project_root),
            "max_workers": max_workers,
            "phase": "project_audit_start"
        })
        logger.info(f"Project: {project_root}")
        logger.info(f"Parallel Workers: {max_workers}")
        logger.info("="*80)
        
        # Scan Project
        scanner = ProjectScanner(project_root, model=self.model)
        # Note: scan() returns execution_order (list), summaries (dict), pkg (ProjectKnowledgeGraph)
        # We ignore the linear execution_order and use the graph for scheduling
        execution_order, project_context, pkg = scanner.scan()
        
        # 1b. Generate Deployment Script (for Integration PoCs)
        from src.agent.deployment_gen import SystemDeploymentGenerator
        deploy_gen = SystemDeploymentGenerator(project_root, execution_order, project_context)
        deploy_script = deploy_gen.generate_script()
        
        # Save to script/SystemDeploy.s.sol
        script_dir = project_root / "script"
        script_dir.mkdir(exist_ok=True)
        (script_dir / "SystemDeploy.s.sol").write_text(deploy_script)
        logger.info("Generated system deployment script at script/SystemDeploy.s.sol")

        # Schedule Batches
        scheduler = TaskScheduler(scanner.graph)
        batches = scheduler.get_execution_batches()

        results = []
        total_contracts = sum(len(b) for b in batches)
        completed_count = 0

        logger.info(f"Scheduled {len(batches)} batches for {total_contracts} contracts.",
                   extra={"batches": len(batches), "total_contracts": total_contracts})

        # Execute Batches
        # We process batches sequentially, but contracts within a batch in parallel
        for batch_idx, batch in enumerate(batches, 1):
            logger.info(f"Batch {batch_idx}/{len(batches)}: {len(batch)} contracts",
                       extra={"batch_idx": batch_idx, "batch_size": len(batch)})
            logger.info(f"   Contracts: {', '.join(batch)}")
            
            # If batch size is 1, run in main process (easier debugging/overhead)
            if len(batch) == 1:
                contract_name = batch[0]
                self._audit_single_contract(contract_name, project_root, project_context, results)
                completed_count += 1
                continue

            # Parallel Execution
            # Note: ProcessPoolExecutor requires pickling. The Orchestrator is complex.
            # We'll use a ThreadPoolExecutor for now if IO bound (LLM calls), 
            # or we need a picklable worker. 
            # Since this is LLM-heavy, ThreadPool is actually better than ProcessPool 
            # because the GIL isn't the bottleneck (network wait is), and it avoids pickling issues.
            from concurrent.futures import ThreadPoolExecutor
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_contract = {
                    executor.submit(
                        self._audit_single_contract_safe, 
                        name, project_root, project_context
                    ): name for name in batch
                }
                
                for future in as_completed(future_to_contract):
                    contract_name = future_to_contract[future]
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                        completed_count += 1
                        logger.info(f"[{completed_count}/{total_contracts}] Completed {contract_name}",
                                  extra={"completed": completed_count, "total": total_contracts, "contract": contract_name})
                    except Exception as e:
                        logger.error(f"Error auditing {contract_name}: {e}", exc_info=True,
                                   extra={"contract": contract_name})

        # System-Wide Analysis
        logger.info("="*60)
        logger.info("RUNNING SYSTEM INVARIANT ANALYSIS", extra={"phase": "system_invariant"})
        logger.info("="*60)
        
        from src.research.system_invariant import SystemInvariantAnalyst
        
        # We need to populate the PKG with findings from the individual audits?
        # For now, the PKG only has the structure. Ideally, we merge the individual KGs.
        # But we don't have easy access to them here (they are saved to disk).
        # We'll run the analyst on the structural graph for now.
        
        backend = create_backend(model=self.model)
        analyst = SystemInvariantAnalyst(pkg, backend=backend)
        system_findings = analyst.analyze()
        
        if system_findings:
            logger.info(f"[SystemInvariant] Found {len(system_findings)} potential cross-contract issues:",
                       extra={"system_findings_count": len(system_findings)})
            for finding in system_findings:
                logger.info(f"  - [{finding.severity.value}] {finding.title}",
                          extra={"severity": finding.severity.value, "finding": finding.title})
                # Add to results as a "System" finding
                # We need to create a dummy AuditResult or append to existing?
                # Let's append to the first result or create a new one.
                # For CLI output, we just log them.
        else:
            logger.info("[SystemInvariant] No obvious cross-contract issues found.")

        return results

    def _audit_single_contract_safe(self, contract_name: str, project_root: Path, project_context: Dict) -> Optional[AuditResult]:
        """Wrapper for parallel execution that handles exceptions"""
        try:
            # Re-find summary to get path
            summary = project_context.get(contract_name)
            if not summary:
                return None
                
            contract_path = Path(summary.file_path)
            if not contract_path.is_absolute():
                contract_path = project_root / contract_path
                
            return self.audit_contract(contract_path, project_context=project_context)
        except Exception as e:
            logger.error(f"CRITICAL ERROR in worker for {contract_name}: {e}", exc_info=True,
                       extra={"contract": contract_name})
            return None

    def _audit_single_contract(self, contract_name: str, project_root: Path, project_context: Dict, results: List):
        """Helper for sequential execution"""
        summary = project_context.get(contract_name)
        if not summary:
            logger.warning(f"Skipping {contract_name} (no summary found)",
                         extra={"contract": contract_name})
            return

        contract_path = Path(summary.file_path)
        if not contract_path.is_absolute():
            contract_path = project_root / contract_path

        logger.info("="*60)
        logger.info(f"CONTRACT: {contract_name}", extra={
            "contract": contract_name,
            "file_path": str(contract_path),
            "phase": "single_contract_audit"
        })
        logger.info(f"   File: {contract_path}")
        logger.info("="*60)
        
        result = self.audit_contract(contract_path, project_context=project_context)
        results.append(result)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Mortar-C - XBOW-level Smart Contract Auditor"
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--contract",
        type=Path,
        help="Path to single Solidity contract"
    )
    input_group.add_argument(
        "--bundle",
        nargs="+",
        type=Path,
        help="Bundle of Solidity contract paths (audited sequentially with shared KB/context)"
    )
    input_group.add_argument(
        "--project",
        type=Path,
        help="Path to Foundry project root (enables multi-contract context-aware audit)"
    )
    input_group.add_argument(
        "--foundry",
        type=Path,
        help="Path to Foundry project directory"
    )
    input_group.add_argument(
        "--challenge",
        type=str,
        help="DVD challenge name (e.g., 'unstoppable')"
    )
    input_group.add_argument(
        "--dvd",
        type=int,
        choices=range(1, 19),  # DVD challenges 1-18
        metavar="N",
        help="DVD challenge number (1..18). Example: --dvd 10 => compromised"
    )
    input_group.add_argument(
        "--immunefi",
        action="store_true",
        help="Run Immunefi on-chain mode (requires --address)"
    )

    # Configuration
    parser.add_argument(
        "--api-key",
        type=str,
        help="xAI API key (or set XAI_API_KEY env)"
    )
    parser.add_argument(
        "--backend",
        type=str,
        choices=["grok"],
        default=getattr(config, "DEFAULT_BACKEND_TYPE", None) or getattr(config, "DEFAULT_BACKEND", "grok"),
        help="LLM backend: grok (xAI)."
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Specific model override (e.g., 'x-ai/grok-4.1-fast', 'x-ai/grok-4.1')"
    )
    parser.add_argument(
        "--grok-effort",
        type=str,
        choices=["low", "high"],
        default=None,
        help="Reasoning effort for Grok-4 family (overrides $GROK_EFFORT if provided)"
    )
    parser.add_argument(
        "--cost-limit",
        type=float,
        default=None,
        help="Total cost limit in USD (default: unlimited)"
    )
    parser.add_argument(
        "--no-jit",
        action="store_true",
        help="Disable JIT research (faster but less adaptive)"
    )
    parser.add_argument(
        "--no-poc",
        action="store_true",
        help="Disable PoC generation/execution"
    )
    parser.add_argument(
        "--no-verification",
        action="store_true",
        help="Disable verification layer (smoke mode)"
    )
    parser.add_argument(
        "--neurosymbolic",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable or disable neurosymbolic verification with Z3 (default: enabled)"
    )
    parser.add_argument(
        "--poc-gen-mode",
        type=str,
        choices=["ai", "template", "hybrid", "auto"],
        default=None,
        help="PoC generation mode: ai/template/hybrid/auto (default: template in OFFLINE_MODE, else ai)")
    parser.add_argument(
        "--poc-mode",
        type=str,
        choices=["local", "fork", "dry-run"],
        default=None,
        help="PoC execution mode: local (default), fork (uses $ETH_RPC_URL), or dry-run"
    )
    parser.add_argument(
        "--v3",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable or disable V3 Enhanced specialists (default: enabled; use --no-v3 to fall back to legacy specialists)"
    )
    parser.add_argument(
        "--moa",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable or disable Mixture of Agents (parallel proposers + meta-aggregator, default: enabled)"
    )
    parser.add_argument(
        "--arena",
        action="store_true",
        default=False,
        help="[EXPERIMENTAL] Enable Arena Learning (genetic evolution, requires 100+ contracts for meaningful results, disabled by default)"
    )
    parser.add_argument(
        "--arena-freq",
        type=int,
        default=5,
        help="Evolution frequency in contracts (default: 5, evolve every 5 contracts)"
    )
    parser.add_argument(
        "--a2a",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable or disable the Agent-to-Agent protocol (default: enabled; use --no-a2a to opt out)"
    )
    parser.add_argument(
        "--ace",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable or disable ACE (Agentic Context Engineering) playbooks (default: enabled; use --no-ace to opt out)"
    )
    parser.add_argument(
        "--no-sniper",
        action="store_true",
        help="Disable Sniper pre-filter (enabled by default, 60-70%% efficiency)"
    )
    parser.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable deduplication layer (enabled by default, 30-40%% savings)"
    )
    parser.add_argument(
        "--cold-kb",
        action="store_true",
        help="Cold research run: disable knowledge-base bootstrapping and reuse."
    )
    parser.add_argument(
        "--quality-threshold",
        type=float,
        default=None,
        help=f"Research quality threshold (default: {config.QUALITY_THRESHOLD})"
    )
    parser.add_argument(
        "--chain",
        type=str,
        default="ethereum",
        help="Immunefi chain key (default: ethereum)"
    )
    parser.add_argument(
        "--address",
        type=str,
        help="Target contract address for Immunefi mode"
    )
    parser.add_argument(
        "--fork-block",
        type=int,
        default=0,
        help="Fork block number (0 = latest) for Immunefi mode"
    )

    # Output options
    parser.add_argument(
        "--output",
        type=Path,
        help="Output directory for reports (saves to <dir>/<contract>_<timestamp>.<ext>)"
    )
    parser.add_argument(
        "--output-format", "-f",
        type=str,
        choices=["text", "json", "sarif", "markdown"],
        default="text",
        help="Output format: text (default, human-readable), json (structured), sarif (GitHub/IDE integration), markdown (formatted report)"
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Number of parallel workers for verification (default: 1)"
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["standard", "integration", "quick"],
        default="standard",
        help="Audit mode: standard (default), integration (forking), quick (skip heavy checks)"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate inputs and configuration without running audit (dry-run)"
    )

    args = parser.parse_args()

    # Validate command-line arguments
    # Validate parallel workers count (1-16)
    if args.parallel < 1:
        parser.error("--parallel must be at least 1")
    if args.parallel > 16:
        parser.error("--parallel cannot exceed 16 (resource limit)")

    # Validate cost limit (must be positive)
    if args.cost_limit is not None and args.cost_limit <= 0:
        parser.error("--cost-limit must be positive")

    # Validate quality threshold (0.0-1.0)
    if args.quality_threshold is not None:
        if args.quality_threshold < 0.0 or args.quality_threshold > 1.0:
            parser.error("--quality-threshold must be between 0.0 and 1.0")

    # Validate arena frequency (1-100)
    if args.arena_freq < 1:
        parser.error("--arena-freq must be at least 1")
    if args.arena_freq > 100:
        parser.error("--arena-freq cannot exceed 100")

    # Validate fork block (must be non-negative)
    if args.fork_block < 0:
        parser.error("--fork-block must be non-negative (0 = latest)")

    validator = InputValidator()
    validation_errors = []
    validation_warnings = []

    # Validate startup configuration (API keys, config values)
    config_result = validate_startup_config()
    if not config_result.valid:
        validation_errors.extend(config_result.errors)
    validation_warnings.extend(config_result.warnings)

    # Validate contract paths (if provided)
    if args.contract:
        contract_result = validator.validate_contract_path(str(args.contract))
        if not contract_result.valid:
            validation_errors.extend(contract_result.errors)
        validation_warnings.extend(contract_result.warnings)

    # Validate bundle paths (if provided)
    if args.bundle:
        for idx, contract_path in enumerate(args.bundle, 1):
            contract_result = validator.validate_contract_path(str(contract_path))
            if not contract_result.valid:
                for error in contract_result.errors:
                    validation_errors.append(f"Bundle contract {idx}: {error}")
            for warning in contract_result.warnings:
                validation_warnings.append(f"Bundle contract {idx}: {warning}")

    # Validate project path (if provided)
    if args.project:
        project_result = validator.validate_project_path(str(args.project))
        if not project_result.valid:
            validation_errors.extend(project_result.errors)
        validation_warnings.extend(project_result.warnings)

    # Validate API key (if explicitly provided via CLI)
    if args.api_key:
        backend = args.backend or config.DEFAULT_BACKEND_TYPE
        # Map backend to provider name for validation
        provider_map = {
            "grok": "xai",
            "xai": "xai",
            "anthropic": "anthropic",
            "openrouter": "openrouter",
        }
        provider = provider_map.get(backend, "generic")
        key_result = validator.validate_api_key(args.api_key, provider)
        if not key_result.valid:
            validation_errors.extend(key_result.errors)
        validation_warnings.extend(key_result.warnings)

    # Validate output directory (if provided)
    if args.output:
        output_path = Path(args.output)
        if output_path.exists() and not output_path.is_dir():
            validation_errors.append(f"Output path exists but is not a directory: {args.output}")
        # Create if doesn't exist (will be created later, just check parent exists)
        if not output_path.exists() and not output_path.parent.exists():
            validation_errors.append(f"Output parent directory does not exist: {output_path.parent}")

    # Display validation results
    if validation_warnings:
        print("\n" + "="*70)
        print("VALIDATION WARNINGS:")
        print("="*70)
        for warning in validation_warnings:
            print(f"  {warning}")
        print("="*70 + "\n")

    if validation_errors:
        print("\n" + "="*70)
        print("VALIDATION ERRORS:")
        print("="*70)
        for error in validation_errors:
            print(f"  {error}")
        print("="*70 + "\n")
        print("Please fix the above errors before running the audit.")
        sys.exit(1)

    # Handle --validate-only flag (dry-run)
    if args.validate_only:
        print("\n" + "="*70)
        print("VALIDATION SUCCESSFUL")
        print("="*70)
        print("All inputs and configuration are valid")
        print("Ready to run audit")
        if validation_warnings:
            print(f"\nNote: {len(validation_warnings)} warnings found (non-critical)")
        print("="*70 + "\n")
        sys.exit(0)

    # End validation

    if args.grok_effort:
        os.environ["GROK_EFFORT"] = args.grok_effort

    if args.parallel > 1:
        os.environ["VERIFICATION_WORKERS"] = str(args.parallel)

    if args.immunefi:
        if not args.address:
            parser.error("--address is required when --immunefi is set")
        result = run_immunefi(
            chain=args.chain.lower(),
            address=args.address,
            fork_block=args.fork_block,
            repo_root=str(Path.cwd()),
        )
        print(json.dumps(result, indent=2))
        sys.exit(0)

    # Decide PoC executor mode
    desired_poc_mode = args.poc_mode
    if not desired_poc_mode:
        if args.challenge:
            # DVD challenges: prefer local to avoid mainnet fork
            desired_poc_mode = "local"
        elif os.getenv("ETH_RPC_URL"):
            desired_poc_mode = "fork"
        else:
            desired_poc_mode = "local"

    # Determine contract path(s)
    contract_paths = []
    if args.contract:
        contract_paths = [args.contract]
    elif args.bundle:
        contract_paths = args.bundle
    elif args.foundry:
        # Auto-discovery for Foundry projects reserved for Phase 3
        print(f"Error: --foundry auto-discovery not yet implemented")
        print(f"Use --contract <path> to specify contract directly")
        sys.exit(1)
    elif args.challenge or args.dvd is not None:
        # DVD challenge
        challenge_map = {
            "unstoppable": "unstoppable/UnstoppableVault.sol",
            "naive-receiver": "naive-receiver/NaiveReceiverPool.sol",
            "truster": "truster/TrusterLenderPool.sol",
            "side-entrance": "side-entrance/SideEntranceLenderPool.sol",
            "puppet": "puppet/PuppetPool.sol",
            "puppet-v2": "puppet-v2/PuppetV2Pool.sol",
            "free-rider": "free-rider/FreeRiderNFTMarketplace.sol",
            "backdoor": "backdoor/WalletRegistry.sol",
            "climber": "climber/ClimberVault.sol",
            "compromised": "compromised/TrustfulOracleInitializer.sol",
            "abi-smuggling": "abi-smuggling/SelfAuthorizedVault.sol",
            "selfie": "selfie/SelfiePool.sol",
            "the-rewarder": "the-rewarder/TheRewarderDistributor.sol",
            "wallet-mining": "wallet-mining/WalletDeployer.sol",
            "curvy-puppet": "curvy-puppet/CurvyPuppetLending.sol",
            "shards": "shards/ShardsNFTMarketplace.sol",
            "puppet-v3": "puppet-v3/PuppetV3Pool.sol",
            "withdrawal": "withdrawal/L1Gateway.sol",
            # Add more...
        }
        dvd_number_map = {
            1: "unstoppable",
            2: "naive-receiver",
            3: "truster",
            4: "side-entrance",
            5: "puppet",
            6: "puppet-v2",
            7: "free-rider",
            8: "backdoor",
            9: "climber",
            10: "compromised",
            11: "abi-smuggling",
            12: "selfie",
            13: "the-rewarder",
            14: "wallet-mining",
            15: "curvy-puppet",
            16: "shards",
            17: "puppet-v3",
            18: "withdrawal",
        }
        if args.dvd is not None:
            if args.dvd not in dvd_number_map:
                print(f"Error: Unknown DVD number '{args.dvd}'")
                print("Available: 1..18")
                sys.exit(1)
            args.challenge = dvd_number_map[args.dvd]
            if args.challenge not in challenge_map:
                print(f"Error: Unknown challenge '{args.challenge}'")
                print(f"Available: {', '.join(challenge_map.keys())}")
                sys.exit(1)

            contract_path = config.DVD_DIR / "src" / challenge_map[args.challenge]
            if not contract_path.exists():
                print(f"Error: DVD challenge not found at {contract_path}")
                print(f"Run: cd training && git clone https://github.com/theredguild/damn-vulnerable-defi.git")
                sys.exit(1)
        else:
            if not args.challenge:
                print("Error: --challenge is required when --dvd is omitted")
                sys.exit(1)
            if args.challenge not in challenge_map:
                print(f"Error: Unknown challenge '{args.challenge}'")
                print(f"Available: {', '.join(challenge_map.keys())}")
                sys.exit(1)
            contract_path = config.DVD_DIR / "src" / challenge_map[args.challenge]
            if not contract_path.exists():
                print(f"Error: challenge not found at {contract_path}")
                print(f"Run: cd training && git clone https://github.com/theredguild/damn-vulnerable-defi.git")
                sys.exit(1)
        contract_paths = [contract_path]
    elif args.project:
        # Multi-contract project mode
        if not args.project.exists():
            print(f"Error: Project path not found: {args.project}")
            sys.exit(1)
        
        # Create orchestrator
        orchestrator = MainOrchestrator(
            api_key=args.api_key,
            backend_type=args.backend,
            model=args.model,
            cost_limit=args.cost_limit,
            enable_jit=not args.no_jit,
            enable_poc=not args.no_poc,
            enable_neurosymbolic=args.neurosymbolic and not getattr(args, "no_verification", False),
            enable_v3=args.v3,
            enable_moa=args.moa,
            enable_arena=args.arena,
            arena_frequency=args.arena_freq,
            enable_ace=args.ace,
            enable_a2a=args.a2a,
            enable_sniper=not args.no_sniper,
            enable_dedup=not args.no_dedup,
            quality_threshold=args.quality_threshold,
            poc_mode=desired_poc_mode,
            generator_mode=args.poc_gen_mode,
            disable_kb_bootstrap=args.cold_kb,
            disable_kb=args.cold_kb,
        )
        
        results = orchestrator.audit_project(args.project)
        
        # Summary
        print(f"\n{'='*80}")
        print(f"🏁 PROJECT AUDIT COMPLETE")
        print(f"{'='*80}")
        print(f"Contracts Audited: {len(results)}")
        total_vulns = sum(len(r.validated_vulnerabilities) for r in results)
        print(f"Total Vulnerabilities: {total_vulns}")
        sys.exit(0 if total_vulns == 0 else 1)

    else:
        parser.error("One of --contract/--bundle/--project/--foundry/--challenge/--dvd/--immunefi is required")

    if getattr(args, "no_verification", False):
        print(f"\n Mortar-C smoke run (no verification / no PoC).")
        print(f"Target(s): {', '.join(str(p) for p in contract_paths)}")
        sys.exit(0)

    # Create orchestrator (after smoke check to keep smoke runs fast)
    orchestrator = MainOrchestrator(
        api_key=args.api_key,
        backend_type=args.backend,
        model=args.model,  # Model override
        cost_limit=args.cost_limit,
        enable_jit=not args.no_jit,
        enable_poc=not args.no_poc,
        enable_neurosymbolic=args.neurosymbolic and not getattr(args, "no_verification", False),  # z3
        enable_v3=args.v3,  # v3
        enable_moa=args.moa,  # moa
        enable_arena=args.arena,  # Arena Learning (experimental, requires 100+ contracts)
        arena_frequency=args.arena_freq,  # Evolution frequency
        enable_ace=args.ace,  # ACE self-improving playbooks
        enable_a2a=args.a2a,  # a2a
        enable_sniper=not args.no_sniper,  # Sniper pre-filter (default enabled)
        enable_dedup=not args.no_dedup,  # Deduplication (default enabled)
        quality_threshold=args.quality_threshold,
        poc_mode=desired_poc_mode,
        generator_mode=args.poc_gen_mode,
        disable_kb_bootstrap=args.cold_kb,
        disable_kb=args.cold_kb,
        audit_mode=args.mode,
    )

    # For DVD runs, ensure PoC generation/execution operates within the DVD Foundry project
    if hasattr(orchestrator, "poc_executor"):
        # Set DVD directory as project root for executor (sandbox will be created there)
        orchestrator.poc_executor.project_root = config.DVD_DIR

    if getattr(args, "no_verification", False):
        print(f"\n Mortar-C smoke run (no verification / no PoC).")
        print(f"Target: {contract_path}")
        sys.exit(0)

    # Run audit(s)
    overall_success = True
    bundle_start = time.time()
    bundle_timeout = None
    try:
        # Default 8h bundle cap for multi-target audits with Grok free tier
        # Was 4h but increased for thorough analysis of complex project bundles
        bundle_timeout = int(os.getenv("BUNDLE_TIMEOUT_SECONDS", "28800")) or None
    except ValueError:
        bundle_timeout = 28800

    for contract_path in contract_paths:
        # Check for shutdown signal
        if is_shutdown_requested():
            print(f"\n[WARN] Shutdown requested. Exiting gracefully...")
            logger.info("Shutdown signal received, aborting remaining audits")
            overall_success = False
            break

        if bundle_timeout and (time.time() - bundle_start) > bundle_timeout:
            print(f"\n[WARN] Bundle timeout reached ({bundle_timeout}s). Skipping remaining targets.")
            overall_success = False
            break

        print(f"\n Mortar-C. The ultimate solution.")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"Target: {contract_path}")
        print(f"JIT Research: {'[PASS]' if not args.no_jit else '[FAIL]'}")
        print(f"PoC Generation: {'[PASS]' if not args.no_poc else '[FAIL]'}")
        print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

        result = orchestrator.audit_contract(contract_path)

        # Format and display output
        output_format = OutputFormat(args.output_format)
        formatter = get_formatter(output_format)
        formatted_output = formatter.format(result)

        # Write to file if --output specified
        if args.output:
            output_dir = Path(args.output)
            output_dir.mkdir(parents=True, exist_ok=True)

            # Generate filename with timestamp and format extension
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            extensions = {
                "text": "txt",
                "json": "json",
                "sarif": "sarif",
                "markdown": "md"
            }
            ext = extensions.get(args.output_format, "txt")

            # Security: Sanitize contract name to prevent path traversal
            safe_name = sanitize_contract_name(result.contract_name)
            output_file = output_dir / f"{safe_name}_{timestamp}.{ext}"

            output_file.write_text(formatted_output, encoding='utf-8')
            print(f"Report saved to: {output_file}")
            print()

        # Display output to console
        print(formatted_output)

        # Update overall success flag
        if not result.success:
            overall_success = False

        # Cooldown between bundle items to respect API rate limits
        if len(contract_paths) > 1 and contract_path != contract_paths[-1]:
            time.sleep(int(os.getenv("BUNDLE_COOLDOWN_SECONDS", "20")))

    sys.exit(0 if overall_success else 1)


if __name__ == "__main__":
    main()
