"""project scanner (layer 1.5)"""

import networkx as nx
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.cal.contract_discovery import ContractDiscoverySystem
from src.models.findings import ContractInfo, ContractInterfaceSummary
from src.kb.project_graph import ProjectKnowledgeGraph
from utils.llm_backend import create_backend
from config import config

logger = logging.getLogger(__name__)

class ProjectScanner:
    """
    Scans a project to build a dependency graph and context summaries.
    """

    def __init__(self, project_root: Path, model: str = None):
        self.project_root = project_root
        self.discovery = ContractDiscoverySystem(project_root)
        self.backend = create_backend(model=model or config.DEFAULT_MODEL)
        self.graph = nx.DiGraph()

    def scan(self) -> Tuple[List[str], Dict[str, ContractInterfaceSummary], ProjectKnowledgeGraph]:
        """perform full project scan."""
        print(f"\n[ProjectScanner] Scanning project: {self.project_root.name}")

        # 1. Discover Contracts
        project_structure = self.discovery.discover()
        contracts_map = {c.name: c for c in project_structure.contracts}

        # Initialize Project Knowledge Graph
        self.pkg = ProjectKnowledgeGraph(self.project_root.name)

        # Add contract nodes to PKG
        for contract_name, contract_info in contracts_map.items():
            self.pkg.add_contract_node(contract_name, contract_info)

        # 2. Build Dependency Graph (and populate PKG edges)
        self._build_dependency_graph(project_structure.contracts)

        # 3. Topological Sort
        try:
            execution_order = list(nx.topological_sort(self.graph))
        except nx.NetworkXUnfeasible:
            print("[ProjectScanner] Warning: Cycle detected in dependency graph. Using approximate order.")
            # Fallback: Sort by in-degree (least dependencies first)
            execution_order = sorted(self.graph.nodes, key=lambda n: self.graph.in_degree(n))
        
        # Filter out contracts that weren't discovered (e.g. external imports)
        execution_order = [name for name in execution_order if name in contracts_map]
        
        print(f"[ProjectScanner] Execution Order: {', '.join(execution_order)}")

        # 4. Generate Summaries (PARALLELIZED for 4-8x speedup)
        summaries = {}
        print("[ProjectScanner] Generating interface summaries (parallel)...")

        # Parallel summary generation with ThreadPoolExecutor
        # max_workers=8 for llm throughput without rate limiting
        with ThreadPoolExecutor(max_workers=8) as executor:
            # Submit all summary generation tasks
            future_to_name = {
                executor.submit(self._generate_summary, contracts_map[name]): name
                for name in execution_order
            }

            # Collect results as they complete
            completed = 0
            total = len(execution_order)
            for future in as_completed(future_to_name):
                contract_name = future_to_name[future]
                try:
                    summary = future.result()
                    summaries[contract_name] = summary
                    completed += 1
                    print(f"  [Summary {completed}/{total}] {contract_name}: {summary.purpose[:60]}...")
                except Exception as e:
                    logger.error(f"Failed to generate summary for {contract_name}: {e}")

                    contract = contracts_map[contract_name]
                    summaries[contract_name] = ContractInterfaceSummary(
                        name=contract_name,
                        file_path=str(contract.file_path),
                        purpose=f"Summary generation failed: {str(e)[:100]}"
                    )

        return execution_order, summaries, self.pkg

    def _build_dependency_graph(self, contracts: List[ContractInfo]):
        """builds a directed graph where edge(a, b) means a depends on b."""

        # 1. Map contract names to ContractInfo
        contracts_by_name = {c.name: c for c in contracts}

        # 2. Map file paths to list of contracts defined in that file
        contracts_by_file = {}
        for c in contracts:
            if c.file_path not in contracts_by_file:
                contracts_by_file[c.file_path] = []
            contracts_by_file[c.file_path].append(c)

        # 3. INVERTED INDEX: Map path suffixes to file paths for fast import resolution
        # This eliminates the O(N) scan in the import resolution loop
        # Example: "interfaces/IERC20.sol" -> Path("src/interfaces/IERC20.sol")
        path_suffix_index: Dict[str, Path] = {}
        for file_path in contracts_by_file.keys():
            # Index by full path
            path_suffix_index[str(file_path)] = file_path

            # Also index by various suffixes for flexible matching
            # e.g., "IERC20.sol", "interfaces/IERC20.sol", etc.
            path_parts = file_path.parts
            for i in range(len(path_parts)):
                suffix = "/".join(path_parts[i:])
                # Store shortest path for each suffix (prefer more specific)
                if suffix not in path_suffix_index or len(path_parts[i:]) < len(path_suffix_index[suffix].parts):
                    path_suffix_index[suffix] = file_path

        for contract in contracts:
            self.graph.add_node(contract.name)
            
            dependencies = set()
            
            # 1. Inheritance (Explicit)
            for parent_name in contract.inherits:
                if parent_name in contracts_by_name:
                    dependencies.add(parent_name)
            
            # 2. Imports (Resolved)
            # contract.imports contains raw strings like "./interfaces/IERC20.sol" or "@openzeppelin/..."
            current_file_path = self.project_root / contract.file_path
            current_dir = current_file_path.parent

            for import_path in contract.imports:
                resolved_path = None

                if import_path.startswith("."):
                    try:
                        resolved = (current_dir / import_path).resolve()

                        if self.project_root in resolved.parents or resolved == self.project_root:
                            resolved_path = resolved.relative_to(self.project_root)
                    except (ValueError, RuntimeError):
                        # Path resolution failed - likely invalid relative import
                        pass

                # OPTIMIZATION: Replaced O(N) scan with O(1) dict lookup
                elif "/" in import_path:
                    # Try exact match first
                    if import_path in path_suffix_index:
                        resolved_path = path_suffix_index[import_path]
                    else:
                        # Try suffix match (e.g., "interfaces/IERC20.sol")

                        parts = import_path.split("/")
                        for i in range(len(parts)):
                            suffix = "/".join(parts[i:])
                            if suffix in path_suffix_index:
                                resolved_path = path_suffix_index[suffix]
                                break

                if resolved_path and resolved_path in contracts_by_file:
                    # The import points to a file. That file may contain multiple contracts.
                    # We depend on ALL contracts in that file? 
                    # Technically only the ones we use, but for a coarse graph, depending on the file is safe.
                    # However, we need to link Contract -> Contract.
                    # If we import "Types.sol", and it has "struct Params", we depend on it.
                    # If we import "ISwap.sol", and it has "interface ISwap", we depend on it.
                    # Let's add edges to ALL contracts in the imported file.
                    for imported_contract in contracts_by_file[resolved_path]:
                        if imported_contract.name != contract.name:
                            dependencies.add(imported_contract.name)

            for dep in dependencies:
                # Edge: Contract -> Dependency (Contract depends on Dependency)
                # For topological sort (dependencies first), we want Edge(Dependency, Contract)
                # Add edge to NetworkX graph for topological sort
                self.graph.add_edge(dep, contract.name)

                # Add high-level dependency edge to Project Knowledge Graph
                self.pkg.add_cross_contract_edge(
                    source_contract=contract.name, source_node="contract_def",
                    target_contract=dep, target_node="contract_def",
                    relation="depends_on"
                )

            # 3. External Calls Detection (CROSS-CONTRACT WIRING)

            self._detect_and_add_external_calls(contract, contracts_by_name)

    def _detect_and_add_external_calls(self, contract: ContractInfo, contracts_by_name: Dict[str, ContractInfo]):
        """detect external calls in contract source code and populate pkg with call edges."""
        import re

        # Use lazy-loading method to get source code
        source = contract.get_source_code()
        if not source:
            return

        # Pattern 1: Interface calls - ContractName(address).functionName(args)
        # Captures: ContractName and functionName
        interface_call_pattern = r'(\w+)\s*\([^)]*\)\s*\.\s*(\w+)\s*\('

        for match in re.finditer(interface_call_pattern, source):
            target_contract = match.group(1)
            target_function = match.group(2)

            if target_contract in contracts_by_name:
                # Add cross-contract call edge to PKG
                self.pkg.add_cross_contract_edge(
                    source_contract=contract.name,
                    source_node="contract_def",  # Could be refined to specific function
                    target_contract=target_contract,
                    target_node=f"fn::{target_function}",
                    relation="external_call",
                    metadata={
                        "call_type": "interface",
                        "target_function": target_function
                    }
                )

        # Pattern 2: Low-level calls - address.call(...), delegatecall(...), staticcall(...)
        low_level_patterns = [
            (r'\.call\s*\(', "call"),
            (r'\.delegatecall\s*\(', "delegatecall"),
            (r'\.staticcall\s*\(', "staticcall"),
        ]

        for pattern, call_type in low_level_patterns:
            for match in re.finditer(pattern, source):
                # Add generic external call node to PKG
                # We don't know the target, but we know there's an external call
                call_location = source[:match.start()].count('\n') + 1
                self.pkg.add_cross_contract_edge(
                    source_contract=contract.name,
                    source_node="contract_def",
                    target_contract="external",  # Unknown target
                    target_node=f"unknown_call_line_{call_location}",
                    relation="external_call",
                    metadata={
                        "call_type": call_type,
                        "line": call_location
                    }
                )

    def _generate_summary(self, contract: ContractInfo) -> ContractInterfaceSummary:
        """
        Generates a summary using LLM.
        """
        # Use lazy-loading method to get source code
        source_code = contract.get_source_code()
        if not source_code.strip():
            logger.warning(f"Empty source code for contract {contract.name}, returning default summary")
            return ContractInterfaceSummary(
                name=contract.name,
                file_path=str(contract.file_path),
                purpose="No source code available",
                external_api=[],
                state_variables=[],
                dependencies=[],
                trust_assumptions=[]
            )

        prompt = f"""you are a smart contract architect. analyze this contract and provide a structured summary."""
        try:
            response = self.backend.generate(
                prompt=prompt,
                max_tokens=1000,
                temperature=0.1
            )
            import json
            # Clean response
            text = response.text.strip()
            if text.startswith("```json"):
                text = text[7:-3]
            elif text.startswith("```"):
                text = text[3:-3]
            
            data = json.loads(text)
            
            return ContractInterfaceSummary(
                name=contract.name,
                file_path=str(contract.file_path),
                purpose=data.get("purpose", "No description"),
                external_api=data.get("external_api", []),
                state_variables=data.get("state_variables", []),
                dependencies=data.get("dependencies", []),
                trust_assumptions=data.get("trust_assumptions", [])
            )
        except Exception as e:
            logger.error(f"Failed to generate summary for {contract.name}: {e}")
            return ContractInterfaceSummary(
                name=contract.name,
                file_path=str(contract.file_path),
                purpose="Summary generation failed"
            )
