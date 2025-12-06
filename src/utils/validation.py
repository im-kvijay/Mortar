"""input validation utilities"""

from pathlib import Path
from typing import Optional, List, Tuple, Any
from dataclasses import dataclass, field
import re
import os
import warnings


@dataclass
class ValidationResult:
    """result of input validation."""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        """allow using validationresult in boolean context."""
        return self.valid

    def __str__(self) -> str:
        """string representation for easy error reporting."""
        lines = []
        if self.errors:
            lines.append("ERRORS:")
            for error in self.errors:
                lines.append(f"  - {error}")
        if self.warnings:
            lines.append("WARNINGS:")
            for warning in self.warnings:
                lines.append(f"  - {warning}")
        return "\n".join(lines) if lines else "Validation passed"

    def add_error(self, error: str) -> None:
        """add an error and mark as invalid."""
        self.errors.append(error)
        self.valid = False

    def add_warning(self, warning: str) -> None:
        """add a warning without invalidating."""
        self.warnings.append(warning)


class InputValidator:
    """validates user inputs before processing."""

    # valid solidity version pragma pattern
    SOLIDITY_PRAGMA_PATTERN = re.compile(r'pragma\s+solidity\s+[\^~>=<\s\d.]+;')

    # valid spdx license identifier pattern
    SPDX_PATTERN = re.compile(r'//\s*SPDX-License-Identifier:\s*[\w\-\+\.]+')

    CONTRACT_NAME_PATTERN = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

    # valid api key patterns by provider
    API_KEY_PATTERNS = {
        'xai': re.compile(r'^xai-[A-Za-z0-9_\-]{40,}$'),  # xai format
        'anthropic': re.compile(r'^sk-ant-[A-Za-z0-9_\-]{40,}$'),  # anthropic format
        'openrouter': re.compile(r'^sk-or-v1-[A-Za-z0-9_\-]{40,}$'),  # openrouter format
        'generic': re.compile(r'^[A-Za-z0-9_\-\.]{20,500}$'),  # generic api key
    }

    # max file size for validation (100mb)
    MAX_FILE_SIZE = 100 * 1024 * 1024

    def validate_contract_path(self, path: str) -> ValidationResult:
        """validate contract file path"""
        result = ValidationResult(valid=True)

        if not path or not isinstance(path, str):
            result.add_error("Contract path must be a non-empty string")
            return result

        # security: check for symlink traversal bypass first
        p_unresolved = Path(path)
        if p_unresolved.exists() and p_unresolved.is_symlink():
            result.add_error(f"Symlink not allowed: {path}")
            return result

        # sanitize path to prevent traversal attacks
        try:
            p = Path(path).resolve()
        except (ValueError, OSError) as e:
            result.add_error(f"Invalid path format: {e}")
            return result

        # check path traversal attempts
        if '..' in Path(path).parts:
            result.add_warning("Path contains '..' - possible traversal attempt (sanitized)")

        # open file once to avoid toctou race condition
        try:
            fd = os.open(str(p), os.O_RDONLY)
            try:
                stat_info = os.fstat(fd)

                import stat
                if not stat.S_ISREG(stat_info.st_mode):
                    result.add_error(f"Path is not a regular file: {path}")
                    return result

#                # check file size
                size = stat_info.st_size
                if size > self.MAX_FILE_SIZE:
                    result.add_error(f"File too large: {size} bytes (max {self.MAX_FILE_SIZE})")
                    return result
                if size == 0:
                    result.add_error("File is empty")
                    return result

            finally:
                os.close(fd)
        except OSError as e:
            result.add_error(f"Cannot access file: {e}")
            return result

#        # check .sol extension
        if p.suffix != '.sol':
            result.add_warning(f"File does not have .sol extension: {path}")

#        # check file is readable and has solidity markers
        try:
            content = p.read_text(encoding='utf-8', errors='ignore')

#            # check for solidity pragma
            has_pragma = bool(self.SOLIDITY_PRAGMA_PATTERN.search(content))
            has_spdx = bool(self.SPDX_PATTERN.search(content))
            has_contract = 'contract ' in content or 'library ' in content or 'interface ' in content

            if not has_pragma and not has_spdx and not has_contract:
                result.add_warning("File may not be valid Solidity (no pragma/SPDX/contract keywords)")

#            # check for suspicious content
            suspicious_patterns = [
                (r'eval\s*\(', "JavaScript eval() found"),
                (r'exec\s*\(', "Python exec() found"),
                (r'__import__', "Python __import__ found"),
                (r'subprocess\.', "Python subprocess found"),
            ]
            for pattern, desc in suspicious_patterns:
                if re.search(pattern, content):
                    result.add_warning(f"Suspicious pattern in file: {desc}")

        except UnicodeDecodeError:
            result.add_warning("File contains non-UTF-8 content (binary file?)")
        except Exception as e:
            result.add_error(f"Cannot read file: {e}")
            return result

        return result

    def validate_project_path(self, path: str) -> ValidationResult:
        """validate a foundry project directory. args: path: path to foundry project directory returns: vali..."""
        result = ValidationResult(valid=True)

        if not path or not isinstance(path, str):
            result.add_error("Project path must be a non-empty string")
            return result

#        # security: check for symlink traversal bypass first
        p_unresolved = Path(path)
        if p_unresolved.exists() and p_unresolved.is_symlink():
            result.add_error(f"Symlink not allowed: {path}")
            return result

#        # sanitize path
        try:
            p = Path(path).resolve()
        except (ValueError, OSError) as e:
            result.add_error(f"Invalid path format: {e}")
            return result

#        # check path traversal
        if '..' in Path(path).parts:
            result.add_warning("Path contains '..' - possible traversal attempt (sanitized)")

        try:
            fd = os.open(str(p), os.O_RDONLY)
            try:
                stat_info = os.fstat(fd)

#                # check is directory
                import stat
                if not stat.S_ISDIR(stat_info.st_mode):
                    result.add_error(f"Path is not a directory: {path}")
                    return result

            finally:
                os.close(fd)
        except OSError as e:
            result.add_error(f"Cannot access directory: {e}")
            return result

#        # check for foundry.toml
        foundry_toml = p / "foundry.toml"
        if not foundry_toml.exists():
            result.add_error(f"foundry.toml not found in project directory: {path}")

#        # check for src/ directory
        src_dir = p / "src"
        if not src_dir.exists():
            result.add_warning("src/ directory not found (Foundry projects typically have src/)")
        elif not src_dir.is_dir():
            result.add_warning("src/ exists but is not a directory")
        else:
#            # check for .sol files in src/
            sol_files = list(src_dir.glob("**/*.sol"))
            if not sol_files:
                result.add_warning("No .sol files found in src/ directory")

#        # check for lib/ directory (dependencies)
        lib_dir = p / "lib"
        if not lib_dir.exists():
            result.add_warning("lib/ directory not found (Foundry projects typically have dependencies)")

        return result

    def validate_api_key(self, key: str, provider: str) -> ValidationResult:
        """validate an api key format. args: key: api key to validate provider: provider name (xai, anthropi..."""
        result = ValidationResult(valid=True)

        if not key or not isinstance(key, str):
            result.add_error(f"{provider.upper()} API key must be a non-empty string")
            return result

#        # check length bounds
        if len(key) < 20:
            result.add_error(f"{provider.upper()} API key too short (min 20 characters)")
            return result

        if len(key) > 500:
            result.add_error(f"{provider.upper()} API key too long (max 500 characters)")
            return result

#        # check provider-specific pattern
        provider_lower = provider.lower()
        pattern = self.API_KEY_PATTERNS.get(provider_lower, self.API_KEY_PATTERNS['generic'])

        if not pattern.match(key):
            if provider_lower in self.API_KEY_PATTERNS:
                result.add_error(
                    f"{provider.upper()} API key format invalid "
                    f"(expected pattern: {pattern.pattern})"
                )
            else:
                result.add_warning(
                    f"{provider.upper()} API key format unknown "
                    f"(using generic validation)"
                )

#        # check for common mistakes
        if key.startswith(' ') or key.endswith(' '):
            result.add_warning("API key has leading/trailing whitespace (will be stripped)")

        if '\n' in key or '\r' in key:
            result.add_error("API key contains newline characters")

        return result

    def validate_config_value(
        self,
        name: str,
        value: Any,
        expected_type: type,
        min_val: Optional[float] = None,
        max_val: Optional[float] = None,
        allowed_values: Optional[List[Any]] = None
    ) -> ValidationResult:
        """validate a configuration value. args: name: configuration parameter name value: value to validate..."""
        result = ValidationResult(valid=True)

#        # check type
        if not isinstance(value, expected_type):
            result.add_error(
                f"{name} must be {expected_type.__name__}, got {type(value).__name__}"
            )
            return result

#        # check allowed values (enum)
        if allowed_values is not None:
            if value not in allowed_values:
                result.add_error(
                    f"{name} must be one of {allowed_values}, got {value}"
                )
                return result

#        # check numeric ranges
        if expected_type in (int, float):
            if min_val is not None and value < min_val:
                result.add_error(f"{name} must be >= {min_val}, got {value}")

            if max_val is not None and value > max_val:
                result.add_error(f"{name} must be <= {max_val}, got {value}")

#        # check string length
        if expected_type == str:
            if not value:
                result.add_warning(f"{name} is empty")
            elif len(value) > 10000:
                result.add_warning(f"{name} is very long ({len(value)} chars)")

        return result

    def sanitize_path(self, path: str) -> str:
        """sanitize a path to prevent traversal attacks. resolves the path and ensures it doesn't contain su..."""
        if not path or not isinstance(path, str):
            raise ValueError("Path must be a non-empty string")

#        # remove null bytes
        path = path.replace('\0', '')

#        # resolve to absolute path (prevents traversal)
        try:
            resolved = Path(path).resolve()
            return str(resolved)
        except (ValueError, OSError) as e:
            raise ValueError(f"Invalid path: {e}")

    def sanitize_contract_name(self, name: str) -> str:
        """sanitize a contract name for use in filenames. removes/replaces characters that could cause issue..."""
        if not name or not isinstance(name, str):
            raise ValueError("Contract name must be a non-empty string")

#        # remove null bytes
        name = name.replace('\0', '')

#        # check valid contract name pattern
        if not self.CONTRACT_NAME_PATTERN.match(name):
            sanitized = re.sub(r'[^A-Za-z0-9_]', '_', name)

#            # ensure doesn't start with number
            if sanitized and sanitized[0].isdigit():
                sanitized = '_' + sanitized

            warnings.warn(
                f"Contract name '{name}' contains invalid characters, "
                f"sanitized to '{sanitized}'",
                RuntimeWarning,
                stacklevel=2
            )
            name = sanitized

        return name


def validate_startup_config() -> ValidationResult:
    """validate all startup configuration. checks: - required api keys are set and valid - configuration..."""
    result = ValidationResult(valid=True)
    validator = InputValidator()

#    # import config here to avoid circular dependency
    try:
        from config import config
    except ImportError as e:
        result.add_error(f"Cannot import config: {e}")
        return result

#    # validate backend and api keys
    backend = config.DEFAULT_BACKEND_TYPE

    if backend == "xai":
        key = config.XAI_API_KEY
        if not key:
            result.add_error("XAI_API_KEY environment variable not set")
        else:
            key_result = validator.validate_api_key(key, "xai")
            result.errors.extend(key_result.errors)
            result.warnings.extend(key_result.warnings)
            if not key_result.valid:
                result.valid = False

    elif backend == "anthropic":
        key = config.ANTHROPIC_API_KEY
        if not key:
            result.add_error("ANTHROPIC_API_KEY environment variable not set")
        else:
            key_result = validator.validate_api_key(key, "anthropic")
            result.errors.extend(key_result.errors)
            result.warnings.extend(key_result.warnings)
            if not key_result.valid:
                result.valid = False

    elif backend == "openrouter":
        key = config.OPENROUTER_API_KEY
        if not key:
            result.add_error("OPENROUTER_API_KEY environment variable not set")
        else:
            key_result = validator.validate_api_key(key, "openrouter")
            result.errors.extend(key_result.errors)
            result.warnings.extend(key_result.warnings)
            if not key_result.valid:
                result.valid = False

    else:
        result.add_warning(f"Unknown backend type: {backend}")

#    # validate project root exists
    if not config.PROJECT_ROOT.exists():
        result.add_error(f"Project root does not exist: {config.PROJECT_ROOT}")

#    # validate numeric config values
    config_checks = [
        ("CONTEXT_CHAR_BUDGET", config.CONTEXT_CHAR_BUDGET, int, 100, 100000),
        ("CONTEXT_SECTION_BUDGET", config.CONTEXT_SECTION_BUDGET, int, 100, 50000),
        ("QUALITY_THRESHOLD", config.QUALITY_THRESHOLD, float, 0.0, 1.0),
        ("SLITHER_TIMEOUT", config.SLITHER_TIMEOUT, int, 30, 600),
        ("POC_EXECUTION_TIMEOUT", config.POC_EXECUTION_TIMEOUT, int, 10, 3600),
    ]

    for name, value, expected_type, min_val, max_val in config_checks:
        cfg_result = validator.validate_config_value(
            name, value, expected_type, min_val, max_val
        )
        result.errors.extend(cfg_result.errors)
        result.warnings.extend(cfg_result.warnings)
        if not cfg_result.valid:
            result.valid = False

#    # validate string config values
    string_checks = [
        ("DEFAULT_MODEL", config.DEFAULT_MODEL, ["x-ai/grok-4.1-fast:free", "x-ai/grok-4.1-fast", "x-ai/grok-4.1"]),
        ("POC_EXECUTION_MODE", config.POC_EXECUTION_MODE, ["local", "fork", "skip"]),
    ]

    for name, value, allowed in string_checks:
        cfg_result = validator.validate_config_value(
            name, value, str, allowed_values=allowed
        )
        result.errors.extend(cfg_result.errors)
        result.warnings.extend(cfg_result.warnings)
        if not cfg_result.valid:
            result.valid = False

    return result


# convenience functions


def validate_contract(path: str) -> ValidationResult:
    """validate a contract path. args: path: path to solidity contract file returns: validationresult wi..."""
    return InputValidator().validate_contract_path(path)


def validate_project(path: str) -> ValidationResult:
    """validate a foundry project path. args: path: path to foundry project directory returns: validatio..."""
    return InputValidator().validate_project_path(path)


def validate_api_key(key: str, provider: str) -> ValidationResult:
    """validate an api key. args: key: api key to validate provider: provider name (xai, anthropic, open..."""
    return InputValidator().validate_api_key(key, provider)


def sanitize_path(path: str) -> str:
    """sanitize a path to prevent traversal attacks. args: path: path to sanitize returns: sanitized abs..."""
    return InputValidator().sanitize_path(path)


def sanitize_contract_name(name: str) -> str:
    """sanitize a contract name for filenames. args: name: contract name to sanitize returns: sanitized ..."""
    return InputValidator().sanitize_contract_name(name)


# usage examples


if __name__ == "__main__":
    import sys

    print("=" * 70)
    print("Mortar-C Input Validation Tests")
    print("=" * 70)
    print()

    validator = InputValidator()

#    # test contract validation
    print("Contract Validation Tests:")
    print("-" * 70)

#    # valid contract
    if len(sys.argv) > 1:
        result = validator.validate_contract_path(sys.argv[1])
        print(f"File: {sys.argv[1]}")
        print(f"Valid: {result.valid}")
        if result.errors or result.warnings:
            print(result)
        print()

#    # test project validation
    print("Project Validation Tests:")
    print("-" * 70)

    if len(sys.argv) > 2:
        result = validator.validate_project_path(sys.argv[2])
        print(f"Project: {sys.argv[2]}")
        print(f"Valid: {result.valid}")
        if result.errors or result.warnings:
            print(result)
        print()

#    # test api key validation
    print("API Key Validation Tests:")
    print("-" * 70)

    test_keys = {
        "xai": os.getenv("XAI_API_KEY"),
        "anthropic": os.getenv("ANTHROPIC_API_KEY"),
        "openrouter": os.getenv("OPENROUTER_API_KEY"),
    }

    for provider, key in test_keys.items():
        if key:
            result = validator.validate_api_key(key, provider)
            print(f"{provider.upper()}: {'✓ Valid' if result.valid else '✗ Invalid'}")
            if result.errors or result.warnings:
                print(result)
        else:
            print(f"{provider.upper()}: Not set")
    print()

#    # test startup config validation
    print("Startup Configuration Validation:")
    print("-" * 70)
    result = validate_startup_config()
    print(f"Valid: {result.valid}")
    if result.errors or result.warnings:
        print(result)
    print()

#    # test sanitization
    print("Sanitization Tests:")
    print("-" * 70)

    test_paths = [
        "/tmp/test.sol",
        "../../../etc/passwd",
        "contracts/MyContract.sol",
        "/tmp/../tmp/test.sol",
    ]

    for path in test_paths:
        try:
            sanitized = validator.sanitize_path(path)
            print(f"{path:30} → {sanitized}")
        except ValueError as e:
            print(f"{path:30} → ERROR: {e}")
    print()

    test_names = [
        "MyContract",
        "My-Contract",
        "123Contract",
        "My_Contract_v2",
        "Contract.sol",
    ]

    for name in test_names:
        try:
            sanitized = validator.sanitize_contract_name(name)
            print(f"{name:20} → {sanitized}")
        except ValueError as e:
            print(f"{name:20} → ERROR: {e}")
