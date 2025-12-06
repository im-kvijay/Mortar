# spdx-license-identifier: mit
"""module docstring"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

import requests
from urllib.parse import urlencode

from .chain_config import CHAINS, ChainCfg, require_envs, normalize_chain
from .lido_manifest import resolve_lido_entry


def _etherscan_abi(cfg: ChainCfg, address: str) -> Optional[list[dict[str, Any]]]:
    """
    Fetch ABI via Etherscan v2 if available, falling back to v1-style if needed.
    """
    api_key = os.environ.get(cfg.etherscan_api_env, "")
    if not api_key:
        return None

    # prefer v2
    v2_url = cfg.etherscan_base.rstrip("/")
    params = {
        "module": "contract",
        "action": "getabi",
        "address": address,
        "apikey": api_key,
    }
    # some providers require ?chainid=1; others ignore. best-effort.
    response = requests.get(v2_url, params=params, timeout=15)
    if response.status_code == 200:
        try:
            payload = response.json()
            if payload.get("status") == "1":
                return json.loads(payload["result"])
        except Exception:
            pass

    # fallback to legacy
    legacy_params = {"module": "contract", "action": "getabi", "address": address, "apikey": api_key}
    response = requests.get(v2_url, params=legacy_params, timeout=15)
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        return None
    if payload.get("status") != "1":
        return None
    try:
        return json.loads(payload["result"])
    except (ValueError, KeyError):
        return None


def _sourcify_meta(cfg: ChainCfg, address: str) -> Optional[Dict[str, Any]]:
    bases = [
        f"{cfg.sourcify_api}/contracts/full_match/{cfg.chain_id}/{address}/metadata.json",
        f"{cfg.sourcify_api}/contracts/partial_match/{cfg.chain_id}/{address}/metadata.json",
    ]
    for url in bases:
        try:
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                return response.json()
        except Exception:
            continue
    return None


def _cast_call(rpc: str, to: str, data: str) -> str:
    proc = subprocess.run(
        ["cast", "call", to, data, "--rpc-url", rpc],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "cast call failed")
    return proc.stdout.strip()


def _cast_storage(rpc: str, addr: str, slot: str) -> str:
    proc = subprocess.run(
        ["cast", "storage", addr, slot, "--rpc-url", rpc],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "cast storage failed")
    return proc.stdout.strip()


def detect_eip1967(rpc: str, address: str) -> Dict[str, str]:
    impl_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    admin_slot = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
    result: Dict[str, str] = {}
    try:
        implementation = _cast_storage(rpc, address, impl_slot)
        result["implementation"] = "0x" + implementation[-40:]
    except Exception:
        pass
    try:
        admin = _cast_storage(rpc, address, admin_slot)
        result["admin"] = "0x" + admin[-40:]
    except Exception:
        pass
    return result


def supports_erc165(rpc: str, address: str) -> bool:
    interface_sig = "0x01ffc9a7" + "00000000" * 2 + "ffffffff"
    try:
        _ = _cast_call(rpc, address, interface_sig)
        return True
    except Exception:
        return False


def load_target(chain_key: str, address: str) -> Dict[str, Any]:
    # normalize chain name (e.g., "mainnet" -> "ethereum", "bsc" -> "bsc")
    chain_key = normalize_chain(chain_key)
    if chain_key not in CHAINS:
        raise KeyError(f"Unsupported chain '{chain_key}'")

    cfg, rpc = require_envs(chain_key)
    info: Dict[str, Any] = {"address": address, "chain": chain_key, "traits": {}}

    abi = _etherscan_abi(cfg, address)
    if not abi:
        abi = _abi_from_repo(address)
    if not abi:
        meta = _sourcify_meta(cfg, address)
        if meta:
            abi = meta.get("output", {}).get("abi")
    info["abi"] = abi or []

    proxy = detect_eip1967(rpc, address)

    # lido-specific manifest enrichment (offline)
    lido_entry = resolve_lido_entry(address) if chain_key == "ethereum" else None
    if lido_entry:
        # fill proxy/impl if manifest has it
        if "proxy" in lido_entry:
            if isinstance(lido_entry["proxy"], dict):
                # new format: proxy is a dict with address, implementation, admin
                proxy = {
                    "implementation": lido_entry["proxy"].get("implementation") or lido_entry.get("implementation"),
                    "admin": lido_entry["proxy"].get("admin") or "0x0000000000000000000000000000000000000000",
                }
            elif isinstance(lido_entry["proxy"], str):
                # legacy format: proxy is just the address string
                # use implementation from lido_entry if available
                proxy = {
                    "implementation": lido_entry.get("implementation") or "0x0000000000000000000000000000000000000000",
                    "admin": "0x0000000000000000000000000000000000000000",
                }
        info.setdefault("metadata", {})["lido_contract"] = lido_entry.get("contract")

    if proxy:
        info["proxy"] = proxy

    traits = info["traits"]
    traits["erc165"] = supports_erc165(rpc, address)

    sigs = {entry.get("name", ""): entry for entry in info["abi"] if entry.get("type") == "function"}

    def has(name: str) -> bool:
        return name in sigs

    traits.update(
        {
            "access_control": has("hasRole") and has("grantRole"),
            "pausable": has("pause") or has("paused"),
            "uups": has("upgradeTo") or has("proxiableUUID"),
            "erc4626": has("deposit") and has("asset") and has("totalAssets"),
            "permit": has("permit") or has("nonces"),
            "permit2": has("permitTransferFrom"),
            "erc1271": has("isValidSignature"),
            "bridge_finalize": any(
                name in sigs for name in ("finalizeWithdrawal", "relayMessage", "finalize")
            ),
        }
    )

    return info
def _abi_from_repo(address: str) -> Optional[list[dict[str, Any]]]:
    """
    Resolve ABI from locally cloned Lido core artifacts if available.

    Looks for external/lido-core/out/<Contract>.json matching the address via deployed-mainnet.json mapping.
    """
    try:
        from eth_utils import to_checksum_address
    except Exception:
        return None

    repo_root = Path(__file__).resolve().parents[2] / "external" / "lido-core"
    manifest = repo_root / "deployed-mainnet.json"
    out_dir = repo_root / "out"
    if not manifest.exists():
        return None

    try:
        mapping = json.loads(manifest.read_text())
    except Exception:
        return None

    addr_to_artifact: Dict[str, str] = {}
    target = to_checksum_address(address)
    for _, val in mapping.items():
        if isinstance(val, dict):
            if "proxy" in val and isinstance(val["proxy"], dict):
                pa = val["proxy"].get("address")
                if pa:
                    addr_to_artifact[to_checksum_address(pa)] = val["proxy"].get("contract") or val.get("implementation", {}).get("contract")
            if "implementation" in val and isinstance(val["implementation"], dict):
                ia = val["implementation"].get("address")
                if ia:
                    addr_to_artifact[to_checksum_address(ia)] = val["implementation"].get("contract")
            if val.get("address"):
                ia = val["address"]
                addr_to_artifact[to_checksum_address(ia)] = val.get("contract")

    artifact_rel = addr_to_artifact.get(target)
    if not artifact_rel:
        return None

    # contract path like contracts/0.8.9/oracle/accountingoracle.sol -> accountingoracle.json
    contract_name = Path(artifact_rel).stem if isinstance(artifact_rel, str) else None
    if not contract_name:
        return None

    candidate = out_dir / f"{contract_name}.sol" / f"{contract_name}.json"
    if not candidate.exists():
        return None
    try:
        payload = json.loads(candidate.read_text())
        return payload.get("abi")
    except Exception:
        return None
