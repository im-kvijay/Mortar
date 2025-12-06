# SPDX-License-Identifier: MIT
"""kb feature extraction helpers"""

from __future__ import annotations

from typing import List, Optional, Dict, Any


KEYWORD_MAP = {
    "delegatecall": ["delegatecall", "module", "backdoor"],
    "flashloan": ["flash loan", "flashloan", "flash swap"],
    "oracle": ["oracle", "price", "twap", "spot"],
    "upgrade": ["uups", "upgrade", "implementation"],
}


def _normalize(value: Any) -> str:
    return str(value or "").lower()


def contract_feature_keys(contract_info: Optional[Dict[str, Any]]) -> List[str]:
    if not isinstance(contract_info, dict):
        return []

    feats: set[str] = set()
    name = _normalize(contract_info.get("name"))
    path = _normalize(contract_info.get("path") or contract_info.get("file_path"))
    summary = _normalize(contract_info.get("static_analysis_summary"))

    def add(label: str) -> None:
        if label:
            feats.add(label)

    if "walletregistry" in name or "wallet-registry" in path:
        add("contract:wallet_registry")
    if "walletdeployer" in name or "wallet-mining" in path:
        add("contract:wallet_deployer")
    if "shards" in name or "shards" in path:
        add("contract:shards_marketplace")
    if "safe" in name or "gnosissafe" in path or "safe" in path:
        add("component:gnosis_safe")
    if "factory" in name or "factory" in path:
        add("component:factory")
    if "delegatecall" in summary:
        add("analysis:delegatecall")
    if "fallback manager" in summary:
        add("analysis:fallback_manager")
    if "module" in summary:
        add("analysis:module_system")

    if contract_info.get("flash_loan_capable"):
        add("trait:flashloan")
    if contract_info.get("has_oracle"):
        add("trait:oracle")
    if contract_info.get("has_reentrancy_guard"):
        add("trait:reentrancy_guard")

    for fn in contract_info.get("external_functions", []) or []:
        low = _normalize(fn)
        if "createproxywithcallback" in low:
            add("fn:createproxywithcallback")
        if "proxycreated" in low:
            add("fn:proxycreated")
        if "drop(" in low:
            add("fn:drop")
        if "rule(" in low:
            add("fn:rule")

    for fn in contract_info.get("privileged_functions", []) or []:
        low = _normalize(fn)
        if not low:
            continue
        base = low.split("(")[0]
        add(f"priv:{base}")

    for flow in contract_info.get("token_flows", []) or []:
        token = _normalize(flow.get("token"))
        if token and token not in {"unknown", ""}:
            add(f"token:{token}")
        flow_type = _normalize(flow.get("flow_type"))
        if flow_type:
            add(f"flow:{flow_type}")

    return sorted(feats)


def hypothesis_feature_keys(hypothesis, contract_info: Optional[Dict[str, Any]] = None) -> List[str]:
    feats: List[str] = []
    attack_type = (getattr(hypothesis, "attack_type", "") or "unknown").lower()
    feats.append(f"attack_type:{attack_type}")
    target = (getattr(hypothesis, "target_function", "") or "unknown").lower()
    feats.append(f"target:{target}")
    desc = (getattr(hypothesis, "description", "") or "").lower()
    for label, keywords in KEYWORD_MAP.items():
        if any(k in desc for k in keywords):
            feats.append(f"keyword:{label}")
    feats.extend(contract_feature_keys(contract_info))
    return feats


def execution_feature_keys(execution) -> List[str]:
    feats: List[str] = []
    if getattr(execution, "success", False):
        feats.append("execution:success")
    if getattr(execution, "profit", None):
        feats.append("execution:profit")
    for tag in getattr(execution, "impact_tags", []) or []:
        feats.append(f"impact:{tag}")
    return feats


def poc_feature_keys(poc) -> List[str]:
    feats: List[str] = []
    mode = (getattr(poc, "generation_method", "") or "unknown").lower()
    feats.append(f"poc_mode:{mode}")
    path = getattr(poc, "file_path", None)
    if path:
        suffix = str(path).split(".")[-1]
        feats.append(f"poc_ext:{suffix}")
    return feats
