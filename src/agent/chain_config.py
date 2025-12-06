# spdx-license-identifier: mit
"""module docstring"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ChainCfg:
    chain_id: int
    rpc_env: str
    etherscan_api_env: str
    etherscan_base: str
    sourcify_api: str


CHAINS = {
    "ethereum": ChainCfg(
        1,
        "MAINNET_RPC_URL",
        "ETHERSCAN_API_KEY",
        "https://api.etherscan.io/api",
        "https://repo.sourcify.dev",
    ),
    "arbitrum": ChainCfg(
        42161,
        "ARBITRUM_RPC_URL",
        "ARBISCAN_API_KEY",
        "https://api.arbiscan.io/api",
        "https://repo.sourcify.dev",
    ),
    "optimism": ChainCfg(
        10,
        "OPTIMISM_RPC_URL",
        "OPSCAN_API_KEY",
        "https://api-optimistic.etherscan.io/api",
        "https://repo.sourcify.dev",
    ),
    "base": ChainCfg(
        8453,
        "BASE_RPC_URL",
        "BASESCAN_API_KEY",
        "https://api.basescan.org/api",
        "https://repo.sourcify.dev",
    ),
    "polygon": ChainCfg(
        137,
        "POLYGON_RPC_URL",
        "POLYGONSCAN_API_KEY",
        "https://api.polygonscan.com/api",
        "https://repo.sourcify.dev",
    ),
    "bsc": ChainCfg(
        56,
        "BSC_RPC_URL",
        "BSCSCAN_API_KEY",
        "https://api.bscscan.com/api",
        "https://repo.sourcify.dev",
    ),
}

# chain name aliases (for defihacklabs compatibility)
CHAIN_ALIASES = {
    "mainnet": "ethereum",
    "eth": "ethereum",
    "arb": "arbitrum",
    "op": "optimism",
    "bnb": "bsc",
    "binance": "bsc",
}


def normalize_chain(chain_key: str) -> str:
    """Normalize chain name using aliases."""
    return CHAIN_ALIASES.get(chain_key.lower(), chain_key.lower())


def require_envs(chain_key: str) -> tuple[ChainCfg, str]:
    """Return chain configuration and ensure RPC env is set."""
    cfg = CHAINS[chain_key]
    rpc = os.environ.get(cfg.rpc_env, "")
    if not rpc:
        raise RuntimeError(f"Missing RPC endpoint: set ${cfg.rpc_env}")
    return cfg, rpc
