"""contract discovery system (layer 1.1)"""
import json
import logging
import os
import re
from pathlib import Path
from typing import List, Union

from src.models.findings import (
    ContractInfo,
    ProjectStructure,
    ContractType
)
from src.cal.foundry_parser import FoundryConfigParser

logger = logging.getLogger(__name__)

class ContractDiscoverySystem:
    """discovers and analyzes all contracts in a foundry project"""

    def __init__(self, project_root: Union[str, Path]):
        self.project_root = Path(project_root).resolve()

        self.parser = FoundryConfigParser(self.project_root)
        
        self.src_dir = self.parser.src_dir
        self.test_dir = self.parser.test_dir
        self.out_dir = self.parser.out_dir

        # fallback for out_dir if not found (foundry default)
        if not self.out_dir.exists():
             foundry_out = self.project_root / "foundry" / "out"
             if foundry_out.exists():
                 self.out_dir = foundry_out
             else:
                 logger.warning(f"Output directory not found: {self.out_dir}")
                 logger.warning("Compilation artifacts may be unavailable")

        # validate out_dir is writable (if it exists)
        if self.out_dir.exists():
            if not os.access(self.out_dir, os.W_OK):
                logger.warning(f"Output directory not writable: {self.out_dir}")

        # validate project structure
        if not self.project_root.exists():
            raise ValueError(f"Project root does not exist: {self.project_root}")

        if not (self.project_root / "foundry.toml").exists():
            raise ValueError(f"Not a Foundry project (missing foundry.toml): {self.project_root}")

    def discover(self, target_file: Union[str, Path, None] = None) -> ProjectStructure:
        logger.info(f"Discovering contracts in: {self.project_root}",
                   extra={"project_root": str(self.project_root), "project_name": self.project_root.name})
        logger.info(f"Project: {self.project_root.name}")

        # find all solidity files
        src_files = self._find_solidity_files(self.src_dir)

        # also check 'contracts' dir if it exists and isn't the src dir
        contracts_dir = self.project_root / "contracts"
        if contracts_dir.exists() and contracts_dir != self.src_dir:
            src_files.extend(self._find_solidity_files(contracts_dir))
        test_files = self._find_solidity_files(self.test_dir)

        # include target file if specified and exists
        if target_file:
            target_path = Path(target_file).resolve()
            if target_path.exists() and target_path.suffix == '.sol':
                if target_path not in src_files and target_path not in test_files:
                    logger.info(f"Including external target: {target_path}", extra={"target_file": str(target_path)})
                    src_files.append(target_path)

        logger.info(f"Found {len(src_files)} source files", extra={"source_files": len(src_files)})
        logger.info(f"Found {len(test_files)} test files", extra={"test_files": len(test_files)})

        contracts = []
        for file_path in src_files:
            contract_infos = self._parse_contract_file(file_path)
            contracts.extend(contract_infos)

        test_contracts = []
        for file_path in test_files:
            contract_infos = self._parse_contract_file(file_path)
            test_contracts.extend(contract_infos)

        logger.info(f"Parsed {len(contracts)} contracts", extra={"contracts": len(contracts)})
        logger.info(f"Parsed {len(test_contracts)} test contracts", extra={"test_contracts": len(test_contracts)})

        for contract in contracts:
            self._load_artifacts(contract)

        # classify contract types
        for contract in contracts:
            self._classify_contract_type(contract)
            # clear cache after classification to free memory (lazy-load optimization)
            contract._source_cache = None

        solidity_versions = list(set(c.solidity_version for c in contracts if c.solidity_version))

        project = ProjectStructure(
            project_root=self.project_root,
            project_name=self.project_root.name,
            contracts=contracts,
            test_contracts=test_contracts,
            solidity_versions=sorted(solidity_versions),
            total_contracts=len(contracts),
            total_lines_of_code=sum(c.lines_of_code for c in contracts)
        )

        logger.info("[OK] Discovery complete", extra={
            "contracts": project.total_contracts,
            "loc": project.total_lines_of_code,
            "solidity_versions": ', '.join(project.solidity_versions)
        })
        logger.info(f"   Contracts: {project.total_contracts}")
        logger.info(f"   LOC: {project.total_lines_of_code}")
        logger.info(f"   Solidity versions: {', '.join(project.solidity_versions)}")

        return project

    def _find_solidity_files(self, directory: Path) -> List[Path]:
        if not directory.exists():
            return []

        return list(directory.rglob("*.sol"))

    def _strip_comments(self, source: str) -> str:
        # remove multi-line comments
        source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
        # remove single-line comments
        source = re.sub(r'//.*', '', source)
        return source

    def _parse_contract_file(self, file_path: Path) -> List[ContractInfo]:
        try:
            source_code = file_path.read_text(encoding='utf-8')
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}", extra={"file_path": str(file_path)})
            return []

        contracts = []

        # strip comments to avoid false positives in regex
        clean_source = self._strip_comments(source_code)

        contract_pattern = r'\b(contract|interface|library|abstract\s+contract)\s+(\w+)'
        matches = re.finditer(contract_pattern, clean_source)

        for match in matches:
            contract_type = match.group(1)
            contract_name = match.group(2)

            is_abstract = 'abstract' in contract_type
            is_interface = 'interface' in contract_type

            version_match = re.search(r'pragma\s+solidity\s+([^;]+);', source_code)
            solidity_version = version_match.group(1).strip() if version_match else "unknown"

            imports = self._extract_imports(source_code)

            inherits = self._extract_inheritance(source_code, contract_name)

            # count functions (rough estimate)
            function_count = len(re.findall(r'\bfunction\s+\w+', source_code))
            external_count = len(re.findall(r'\bfunction\s+\w+[^;{]*\bexternal\b', source_code))
            public_count = len(re.findall(r'\bfunction\s+\w+[^;{]*\bpublic\b', source_code))

            # lines of code (excluding comments/blank lines)
            loc = self._count_lines_of_code(source_code)

            contract_info = ContractInfo(
                name=contract_name,
                file_path=file_path.relative_to(self.project_root),
                solidity_version=solidity_version,
                is_abstract=is_abstract,
                is_interface=is_interface,
                imports=imports,
                inherits=inherits,
                lines_of_code=loc,
                function_count=function_count,
                external_function_count=external_count,
                public_function_count=public_count,
                # lazy-load source on demand to save memory
                source_code=None
            )

            # set project root for lazy loading
            contract_info.set_project_root(self.project_root)

            # store source code temporarily in cache for _classify_contract_type
            # (avoids immediate re-read from disk)
            contract_info._source_cache = source_code

            contracts.append(contract_info)

        return contracts

    def _extract_imports(self, source_code: str) -> List[str]:
        import_pattern = r'import\s+(?:\"([^\"]+)\"|\'([^\']+)\')'
        matches = re.findall(import_pattern, source_code)
        # flatten tuples from regex groups
        return [match[0] or match[1] for match in matches]

    def _extract_inheritance(self, source_code: str, contract_name: str) -> List[str]:
        # find "contract X is Y, Z" pattern
        pattern = rf'\b(?:contract|abstract\s+contract)\s+{re.escape(contract_name)}\s+is\s+([^{{]+)'
        match = re.search(pattern, source_code)

        if not match:
            return []

        parents_str = match.group(1)
        # remove whitespace and split by comma
        parents = [p.strip() for p in parents_str.split(',')]

        parents = [re.sub(r'\(.*\)', '', p).strip() for p in parents]

        return parents

    def _count_lines_of_code(self, source_code: str) -> int:
        # remove multi-line comments
        code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)

        # remove single-line comments
        code = re.sub(r'//.*', '', code)

        # count non-empty lines
        lines = [line.strip() for line in code.split('\n') if line.strip()]

        return len(lines)

    def _load_artifacts(self, contract: ContractInfo) -> None:
        # construct artifact path
        contract_file = contract.file_path.name
        artifact_path = self.out_dir / contract_file / f"{contract.name}.json"

        if not artifact_path.exists():
            return  # no artifacts (not compiled or interface)

        try:
            with open(artifact_path, 'r') as f:
                artifact = json.load(f)

            contract.abi = artifact.get('abi', [])

            bytecode_obj = artifact.get('bytecode', {})
            if isinstance(bytecode_obj, dict):
                contract.bytecode = bytecode_obj.get('object', '')
            else:
                contract.bytecode = bytecode_obj

        except Exception as e:
            logger.warning(f"Failed to load artifacts for {contract.name}: {e}",
                         extra={"contract": contract.name})

    def _classify_contract_type(self, contract: ContractInfo) -> None:
        name_lower = contract.name.lower()
        inherits_lower = [p.lower() for p in contract.inherits]
        # use lazy-loading method to get source code
        source_lower = contract.get_source_code().lower()

        # token detection
        if 'erc20' in inherits_lower or 'token' in name_lower:
            contract.contract_type = ContractType.TOKEN
        elif 'erc721' in inherits_lower or 'nft' in name_lower:
            contract.contract_type = ContractType.NFT

        # proxy detection
        elif 'proxy' in name_lower or 'upgradeable' in name_lower:
            contract.contract_type = ContractType.PROXY
            contract.is_upgradeable = True

        # defi protocols
        elif 'vault' in name_lower:
            contract.contract_type = ContractType.VAULT
        elif 'pool' in name_lower:
            contract.contract_type = ContractType.POOL
        elif 'lend' in name_lower or 'borrow' in name_lower:
            contract.contract_type = ContractType.LENDING
        elif 'swap' in name_lower or 'exchange' in name_lower or 'dex' in name_lower:
            contract.contract_type = ContractType.EXCHANGE
        elif 'oracle' in name_lower or 'price' in name_lower:
            contract.contract_type = ContractType.ORACLE
        elif 'govern' in name_lower or 'voting' in name_lower:
            contract.contract_type = ContractType.GOVERNANCE
        elif 'factory' in name_lower:
            contract.contract_type = ContractType.FACTORY
        elif 'router' in name_lower:
            contract.contract_type = ContractType.ROUTER
        elif 'bridge' in name_lower:
            contract.contract_type = ContractType.BRIDGE
        elif 'stak' in name_lower:
            contract.contract_type = ContractType.STAKING

        # source_lower already contains the loaded source
        if source_lower:
            if 'uups' in source_lower or 'upgradeable' in source_lower:
                contract.is_upgradeable = True

if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

    from models.findings import ContractInfo, ProjectStructure

    if len(sys.argv) > 1:
        project_path = sys.argv[1]
    else:
        from config import config as cfg
        project_path = str(cfg.DVD_DIR)

    discovery = ContractDiscoverySystem(project_path)
    project = discovery.discover()

    print("\n" + "="*80)
    print("DISCOVERED CONTRACTS")
    print("="*80)

    for contract in project.contracts[:10]:
        print(f"\n{contract.name}")
        print(f"   Type: {contract.contract_type.value}")
        print(f"   File: {contract.file_path}")
        print(f"   LOC: {contract.lines_of_code}")
        print(f"   Functions: {contract.function_count} ({contract.external_function_count} external)")
        if contract.inherits:
            print(f"   Inherits: {', '.join(contract.inherits)}")
        if contract.is_upgradeable:
            print("   upgradeable")

    print(f"\n... and {len(project.contracts) - 10} more contracts")

