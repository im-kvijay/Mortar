"""
enriches contract analysis prompts with on-chain metadata.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import subprocess

logger = logging.getLogger(__name__)


@dataclass
class TokenBalance:
    """Token balance held by a contract"""
    token_address: str
    token_symbol: str
    balance: float
    balance_wei: int
    usd_value: Optional[float] = None


@dataclass
class DEXInfo:
    """DEX liquidity information"""
    dex_name: str
    pair_address: str
    token0: str
    token1: str
    reserve0: float
    reserve1: float
    price: float
    liquidity_usd: Optional[float] = None


@dataclass
class ContractMetadata:
    """Complete metadata for a contract"""
    address: str
    chain: str
    block_number: int
    eth_balance: float
    token_balances: List[TokenBalance]
    dex_pools: List[DEXInfo]
    is_proxy: bool
    implementation_address: Optional[str] = None
    owner: Optional[str] = None
    admin: Optional[str] = None


class MetadataInjector:
    """
    Fetches and injects on-chain metadata into analysis prompts.

    Uses cast (Foundry) for RPC calls and can optionally use
    APIs like Etherscan, Alchemy for enriched data.
    """

    # Common token addresses
    COMMON_TOKENS = {
        "mainnet": {
            "WETH": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            "USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "DAI": "0x6B175474E89094C44Da98b954EescdeCB5 EE2dc55",
            "WBTC": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
        },
        "bsc": {
            "WBNB": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
            "USDC": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
            "USDT": "0x55d398326f99059fF775485246999027B3197955",
            "BUSD": "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56",
        }
    }

    # DEX factory addresses
    DEX_FACTORIES = {
        "mainnet": {
            "uniswap_v2": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
            "uniswap_v3": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
            "sushiswap": "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac",
        },
        "bsc": {
            "pancakeswap_v2": "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
        }
    }

    def __init__(self, rpc_url: Optional[str] = None):
        """
        Initialize metadata injector.

        Args:
            rpc_url: RPC URL for chain queries. Uses env var if not provided.
        """
        self.rpc_url = rpc_url or os.getenv("ETH_RPC_URL", "http://localhost:8545")

    def _cast_call(self, target: str, sig: str, args: List[str] = None, block: Optional[int] = None) -> Optional[str]:
        """Execute a cast call command"""
        cmd = ["cast", "call", target, sig]
        if args:
            cmd.extend(args)
        if block:
            cmd.extend(["--block", str(block)])
        cmd.extend(["--rpc-url", self.rpc_url])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.warning(f"Failed to call cast: {e}")
        return None

    def get_eth_balance(self, address: str, block: Optional[int] = None) -> float:
        """Get ETH/native token balance"""
        cmd = ["cast", "balance", address, "--rpc-url", self.rpc_url]
        if block:
            cmd.extend(["--block", str(block)])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                # Result is in wei, convert to ether
                wei = int(result.stdout.strip())
                return wei / 1e18
        except Exception as e:
            logger.warning(f"Failed to get ETH balance: {e}")
        return 0.0

    def get_token_balance(self, token: str, holder: str, block: Optional[int] = None) -> int:
        """Get ERC20 token balance"""
        result = self._cast_call(token, "balanceOf(address)(uint256)", [holder], block)
        if result:
            try:
                return int(result, 16) if result.startswith("0x") else int(result)
            except ValueError as e:
                logger.warning(f"Failed to parse token balance: {e}")
        return 0

    def get_token_symbol(self, token: str) -> str:
        """Get token symbol"""
        result = self._cast_call(token, "symbol()(string)")
        return result.strip('"') if result else "UNKNOWN"

    def get_token_decimals(self, token: str) -> int:
        """Get token decimals"""
        result = self._cast_call(token, "decimals()(uint8)")
        if result:
            try:
                return int(result, 16) if result.startswith("0x") else int(result)
            except ValueError as e:
                logger.warning(f"Failed to parse token decimals: {e}")
        return 18

    def check_proxy(self, address: str) -> tuple[bool, Optional[str]]:
        """Check if address is a proxy and get implementation"""
        # Check EIP-1967 implementation slot
        impl_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

        cmd = ["cast", "storage", address, impl_slot, "--rpc-url", self.rpc_url]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                impl = result.stdout.strip()
                if impl and impl != "0x" + "0" * 64:
                    impl_address = "0x" + impl[-40:]
                    if impl_address != "0x" + "0" * 40:
                        return True, impl_address
        except Exception as e:
            logger.warning(f"Failed to check proxy: {e}")
        return False, None

    def get_owner(self, address: str) -> Optional[str]:
        """Try to get contract owner via common patterns"""
        for sig in ["owner()(address)", "getOwner()(address)", "admin()(address)"]:
            result = self._cast_call(address, sig)
            if result and len(result) == 42:
                return result
        return None

    def fetch_metadata(
        self,
        address: str,
        chain: str = "mainnet",
        block: Optional[int] = None
    ) -> ContractMetadata:
        """
        Fetch complete metadata for a contract.

        Args:
            address: Contract address
            chain: Chain name (mainnet, bsc, etc.)
            block: Optional block number for historical state

        Returns:
            ContractMetadata with all available information
        """
        # Get ETH balance
        eth_balance = self.get_eth_balance(address, block)

        # Check token balances for common tokens
        token_balances = []
        tokens = self.COMMON_TOKENS.get(chain, {})
        for symbol, token_addr in tokens.items():
            balance_wei = self.get_token_balance(token_addr, address, block)
            if balance_wei > 0:
                decimals = self.get_token_decimals(token_addr)
                balance = balance_wei / (10 ** decimals)
                token_balances.append(TokenBalance(
                    token_address=token_addr,
                    token_symbol=symbol,
                    balance=balance,
                    balance_wei=balance_wei
                ))

        # Check if proxy
        is_proxy, impl_address = self.check_proxy(address)

        # Get owner
        owner = self.get_owner(address)

        return ContractMetadata(
            address=address,
            chain=chain,
            block_number=block or 0,
            eth_balance=eth_balance,
            token_balances=token_balances,
            dex_pools=[],  # TODO: Fetch DEX pools
            is_proxy=is_proxy,
            implementation_address=impl_address,
            owner=owner
        )

    def format_for_prompt(self, metadata: ContractMetadata) -> str:
        """
        Format metadata for injection into analysis prompts.

        Returns a structured string that can be prepended to the contract
        source code or system prompt.
        """
        lines = [
            "## ON-CHAIN CONTEXT",
            "",
            f"**Contract Address:** `{metadata.address}`",
            f"**Chain:** {metadata.chain}",
            f"**Block:** {metadata.block_number or 'latest'}",
            "",
        ]

        # ETH balance
        lines.append(f"**Native Balance:** {metadata.eth_balance:.4f} ETH")

        # Token balances
        if metadata.token_balances:
            lines.append("")
            lines.append("**Token Balances:**")
            for tb in metadata.token_balances:
                lines.append(f"  - {tb.token_symbol}: {tb.balance:,.4f}")

        # Proxy info
        if metadata.is_proxy:
            lines.append("")
            lines.append(f"**PROXY CONTRACT** → Implementation: `{metadata.implementation_address}`")

        # Owner
        if metadata.owner:
            lines.append(f"**Owner/Admin:** `{metadata.owner}`")

        # DEX pools
        if metadata.dex_pools:
            lines.append("")
            lines.append("**DEX Liquidity:**")
            for pool in metadata.dex_pools:
                lines.append(f"  - {pool.dex_name}: {pool.token0}/{pool.token1}")
                lines.append(f"    Reserves: {pool.reserve0:,.2f} / {pool.reserve1:,.2f}")
                lines.append(f"    Price: {pool.price:.6f}")

        lines.append("")
        lines.append("---")
        lines.append("")

        return "\n".join(lines)


def inject_metadata_into_prompt(
    contract_source: str,
    contract_address: str,
    chain: str = "mainnet",
    block: Optional[int] = None,
    rpc_url: Optional[str] = None
) -> str:
    """
    Convenience function to inject metadata into a contract analysis prompt.

    Args:
        contract_source: Solidity source code
        contract_address: Address of deployed contract
        chain: Chain name
        block: Optional block number
        rpc_url: Optional RPC URL

    Returns:
        Enhanced prompt with metadata prepended
    """
    injector = MetadataInjector(rpc_url)
    metadata = injector.fetch_metadata(contract_address, chain, block)
    context = injector.format_for_prompt(metadata)

    return context + contract_source


# Example usage
if __name__ == "__main__":
    # Test with a known contract
    injector = MetadataInjector()

    # Uniswap V2 Router (has ETH and token balances)
    test_address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"

    print("Fetching metadata for Uniswap V2 Router...")
    metadata = injector.fetch_metadata(test_address, "mainnet")

    print("\nFormatted for prompt:")
    print(injector.format_for_prompt(metadata))
