"""foundry config parser"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Union, Any

class FoundryConfigParser:
    """parses foundry config files"""

    def __init__(self, project_root: Union[str, Path]):
        self.project_root = Path(project_root).resolve()
        self.config = self._parse_foundry_toml()
        self.remappings = self._load_remappings()

    @property
    def src_dir(self) -> Path:
        return self.project_root / self.config.get("src", "src")

    @property
    def test_dir(self) -> Path:
        return self.project_root / self.config.get("test", "test")

    @property
    def out_dir(self) -> Path:
        return self.project_root / self.config.get("out", "out")

    @property
    def libs(self) -> List[Path]:
        libs = self.config.get("libs", ["lib"])
        if isinstance(libs, str):
            libs = [libs]
        return [self.project_root / lib for lib in libs]

    def resolve_import(self, import_path: str, current_file: Path) -> Optional[Path]:
        """resolve import to absolute path"""
        if import_path.startswith("."):
            try:
                resolved = (current_file.parent / import_path).resolve()
                if resolved.exists():
                    return resolved
            except Exception:
                pass
            return None

        for prefix, target in self.remappings.items():
            if import_path.startswith(prefix):
                remainder = import_path[len(prefix):]
                candidate = self.project_root / target / remainder
                if candidate.exists():
                    return candidate.resolve()

        for lib_dir in self.libs:
            candidate = lib_dir / import_path
            if candidate.exists():
                return candidate.resolve()

        return None

    def _parse_foundry_toml(self) -> Dict[str, Any]:
        config = {}
        toml_path = self.project_root / "foundry.toml"
        
        if not toml_path.exists():
            return config

        try:
            content = toml_path.read_text()
            in_default_profile = False
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("["):
                    in_default_profile = line == "[profile.default]"
                    continue

                if in_default_profile or line.startswith("src") or line.startswith("test") or line.startswith("out"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if value.startswith("[") and value.endswith("]"):
                            value = [v.strip().strip('"').strip("'") for v in value[1:-1].split(",")]
                        config[key] = value
        except Exception as e:
            print(f"[FoundryConfigParser] Warning: Failed to parse foundry.toml: {e}")
            
        return config

    def _load_remappings(self) -> Dict[str, str]:
        remappings = {}
        remap_file = self.project_root / "remappings.txt"
        if remap_file.exists():
            for line in remap_file.read_text().splitlines():
                if "=" in line:
                    prefix, target = line.split("=", 1)
                    remappings[prefix.strip()] = target.strip()
            return remappings
        return remappings
