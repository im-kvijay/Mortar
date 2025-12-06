"""ensemble verifier"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .property_runner import run_foundry_invariants
from .symbolic_quick import run_mythril_quick
from .slither_map import SLITHER_MAP
from config import config as _cfg

logger = logging.getLogger(__name__)

try:
    # Prefer typed import when available
    from agent.poc_executor import ExecutionResult as PoCExecution
    from agent.base_attacker import AttackHypothesis
except (ImportError, ModuleNotFoundError) as exc:  # pragma: no cover - type-only in some contexts
    # These types are only needed at runtime in certain contexts - use Any as fallback
    logger.debug(f"[Ensemble] Type-only imports not available: {exc}")
    PoCExecution = Any  # type: ignore
    AttackHypothesis = Any  # type: ignore

_CRITICAL_IMPACT_TAGS = set(
    getattr(
        _cfg,
        "CRITICAL_IMPACT_TAGS",
        ["AUTHZ_BYPASS", "CONFIG_CAPTURE", "VALUE_EXTRACTED"],
    )
)
_CORROBORATION_REQUIRED = bool(
    getattr(_cfg, "ENSEMBLE_CORROBORATION_REQUIRED", True)
)
_SAT_ACCEPTS = bool(
    getattr(_cfg, "ENSEMBLE_ACCEPT_SAT_NO_TAGS", True)
)


@dataclass
class Verdict:
    forge_ok: bool
    slither_ok: bool
    slither_usable: bool
    property_ok: bool
    symbolic_ok: bool
    impact_vectors: Dict[str, bool]
    details: Dict[str, Any]
    z3_sat: bool = False

    @property
    def reportable(self) -> bool:
        any_impact = any(self.impact_vectors.values())
        bypass = self.impact_vectors.get("PROFIT", False) or any(
            self.impact_vectors.get(tag, False) for tag in _CRITICAL_IMPACT_TAGS
        )
        sat_ok = self.z3_sat
        if not self.forge_ok:
            return False
        if not (any_impact or sat_ok):
            return False
        if not _CORROBORATION_REQUIRED:
            return True
        sat_bonus = sat_ok and _SAT_ACCEPTS
        return self.property_ok or self.symbolic_ok or self.slither_usable or bypass or sat_bonus

    @property
    def failure_reason(self) -> Optional[str]:
        if self.reportable:
            return None
        if not self.forge_ok:
            return "FORGE_FAILED"
        if not any(self.impact_vectors.values()) and not self.z3_sat:
            return "NO_PROFIT_NO_TAG"
        bypass = self.impact_vectors.get("PROFIT", False) or any(
            self.impact_vectors.get(tag, False) for tag in _CRITICAL_IMPACT_TAGS
        )
        if _CORROBORATION_REQUIRED:
            sat_bonus = self.z3_sat and _SAT_ACCEPTS
            if not (self.property_ok or self.symbolic_ok or self.slither_usable or bypass or sat_bonus):
                return "INSUFFICIENT_CORROBORATION"
            if self.slither_ok and not self.slither_usable and not (bypass or sat_bonus):
                return "WEAK_STATIC_NEEDS_TAG"
        return "UNKNOWN"


def _parse_profit_value(execution: PoCExecution) -> Tuple[bool, Optional[float]]:
    """parse profit value from execution result with error handling"""
    try:
        if execution is None or not hasattr(execution, 'profit'):
            return False, None
        raw = execution.profit
        if raw is None:
            return False, None
        raw = str(raw).strip()
        if not raw:
            return False, None
        num = ""
        for i, ch in enumerate(raw):
            if ch.isdigit() or ch in ".-+":
                num += ch
            elif ch.lower() == 'e' and num:
                num += ch
                if i + 1 < len(raw) and raw[i + 1] in "+-":
                    num += raw[i + 1]
            elif num:
                break
        if not num or num in {"-", "+", ".", "e", "E"}:
            return False, None
        val = float(num)
        if not (-1e308 < val < 1e308):
            logger.warning(f"[Ensemble] profit value overflow: {val}")
            return False, None
        if val != val:
            logger.warning("[Ensemble] profit value is nan")
            return False, None
        if val < 0:
            return False, val
        if val == 0:
            return False, 0.0
        return True, val
    except (ValueError, OverflowError) as e:
        logger.warning(f"[Ensemble] failed to parse profit value '{execution.profit}': {e}")
        return False, None
    except Exception as e:
        logger.error(f"[Ensemble] unexpected error parsing profit value: {e}")
        return False, None


def parse_forge_results(execution: PoCExecution) -> Tuple[bool, Dict[str, Any]]:
    forge_ok = bool(execution.success)
    impact_tags = list(getattr(execution, "impact_tags", []) or [])
    has_profit, profit_val = _parse_profit_value(execution)
    price_manip = "PRICE_MANIPULATION" in impact_tags
    vectors = {
        "PROFIT": has_profit,
        "VALUE_EXTRACTED": has_profit,
        "FUNDS_FROZEN": "FUNDS_FROZEN" in impact_tags,
        "LIVENESS_HALT": "LIVENESS_HALT" in impact_tags,
        "AUTHZ_BYPASS": "AUTHZ_BYPASS" in impact_tags,
        "INVARIANT_BREAK": "INVARIANT_BREAK" in impact_tags,
        "MARKET_CORRUPTION": "MARKET_CORRUPTION" in impact_tags or price_manip,
        "CONFIG_CAPTURE": "CONFIG_CAPTURE" in impact_tags,
        "PRICE_MANIPULATION": price_manip,
    }
    meta = {
        "impact_tags": impact_tags,
        "profit_value": profit_val,
        "stdout_head": (execution.stdout or "")[:800],
        "stderr_head": (execution.stderr or "")[:800],
    }
    return forge_ok, {"vectors": vectors, **meta}


def _extract_z3_meta(execution: PoCExecution) -> Tuple[bool, Dict[str, Any]]:
    if execution is None:
        return False, {"raw": None, "source": None}
    determinism = getattr(execution, "determinism", {}) or {}
    raw_value = None
    source = None
    for key in ("Z3_SAT", "Z3_RESULT", "SAT_RESULT", "SAT"):
        if key in determinism:
            raw_value = determinism[key]
            source = key
            break
    sat = False
    if isinstance(raw_value, str):
        sat = raw_value.strip().lower() in {"1", "true", "sat", "yes"}
    elif isinstance(raw_value, (int, bool)):
        sat = bool(raw_value)
    meta = {"raw": raw_value, "source": source}
    return sat, meta


def run_slither_alignment(static_findings: Optional[List[Any]], hypothesis: AttackHypothesis) -> Tuple[bool, Dict[str, Any]]:
    """best-effort alignment: consider ok if any high/critical finding matches attack type keywords"""
    if not static_findings:
        return False, {"reason": "slither_skipped"}
    attack = (getattr(hypothesis, "attack_type", "") or "").lower()
    det_expect = SLITHER_MAP.get(attack, [])
    keywords = {
        "reentrancy": ["reentrancy"],
        "oracle": ["price oracle", "manipulation", "oracle", "price manipulation"],
        "access": ["access control", "arbitrary call", "authorization", "auth", "tx-origin", "incorrect-visibility"],
        "logic": ["business logic", "integer overflow", "underflow", "unchecked"],
        "flash_loan": ["flashloan", "flash loan"],
        "funds_frozen": ["locked-ether"],
        "market_corruption": ["delegatecall", "assembly"],
    }
    want = []
    for key, vals in keywords.items():
        if key in attack:
            want.extend(vals)
    want = [w.lower() for w in want]

    def _field(obj: Any, name: str) -> str:
        if isinstance(obj, dict):
            return str(obj.get(name, ""))
        return str(getattr(obj, name, ""))

    matched = []
    for f in static_findings:
        sev = _field(f, "severity")
        det = _field(f, "detector_name").lower()
        desc = (_field(f, "description") + " " + det).lower()
        # Normalize severity value
        sev_val = str(sev).lower()
        name_hit = any(tag in det for tag in det_expect)
        kw_hit = any(k in desc or k in det for k in want)
        if (name_hit or kw_hit) and any(s in sev_val for s in ("high", "critical")):
            matched.append({"severity": sev, "desc": desc, "detector": det})
    return (len(matched) > 0), {"matched": matched, "keywords": want, "weak": len(matched) == 0}


def run_property_checks(execution: PoCExecution) -> Tuple[bool, Dict[str, Any]]:
    """check property corroboration via tags and foundry invariants"""
    tags = set(getattr(execution, "impact_tags", []) or [])
    tag_break = "INVARIANT_BREAK" in tags
    meta: Dict[str, Any] = {}
    sbx = getattr(execution, "sandbox_root", None)
    if sbx:
        failed, inv_meta = run_foundry_invariants(str(sbx))
        meta.update(inv_meta)
        if inv_meta.get("neutral"):
            return (tag_break), meta
        return (tag_break or failed), meta
    return (tag_break), ({"reason": "properties_skipped"} if not tag_break else {"reason": "invariant_break_tag"})


def run_symbolic_quickcheck(hypothesis: AttackHypothesis, target_contract_path: Optional[str]) -> Tuple[bool, Dict[str, Any]]:
    if not target_contract_path:
        return False, {"reason": "symbolic_skipped_no_target"}
    ok, meta = run_mythril_quick(target_contract_path)
    return ok, meta


def verify_all(
    execution: PoCExecution,
    hypothesis: AttackHypothesis,
    static_findings: Optional[List[Any]] = None,
    target_contract_path: Optional[str] = None,
) -> Verdict:
    forge_ok, forge_meta = parse_forge_results(execution)
    sl_ok, sl_meta = run_slither_alignment(static_findings, hypothesis)
    prop_ok, prop_meta = run_property_checks(execution)
    sym_ok, sym_meta = run_symbolic_quickcheck(hypothesis, target_contract_path)
    z3_sat, z3_meta = _extract_z3_meta(execution)

    details = {
        "forge": forge_meta,
        "slither": sl_meta,
        "property": prop_meta,
        "symbolic": sym_meta,
        "z3": z3_meta,
    }

    impact_vectors = forge_meta.get("vectors", {}) if isinstance(forge_meta, dict) else {}
    tag_impact = any(
        name not in {"PROFIT", "VALUE_EXTRACTED"} and value for name, value in impact_vectors.items()
    )
    sl_usable = sl_ok and (not sl_meta.get("weak") or tag_impact)
    sl_meta["usable"] = sl_usable
    verdict = Verdict(
        forge_ok=forge_ok,
        slither_ok=sl_ok,
        slither_usable=sl_usable,
        property_ok=prop_ok,
        symbolic_ok=sym_ok,
        impact_vectors=impact_vectors,
        details=details,
        z3_sat=z3_sat,
    )
    verdict.details["failure_reason"] = verdict.failure_reason
    return verdict
