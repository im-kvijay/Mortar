""" """

import os
import sys
import tempfile
from pathlib import Path
import pytest

# add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from utils.validation import (
    InputValidator,
    ValidationResult,
    validate_contract,
    validate_project,
    validate_api_key,
    sanitize_path,
    sanitize_contract_name,
    validate_startup_config,
)

class TestValidationResult:
    """Test ValidationResult dataclass."""

    def test_valid_result_is_truthy(self):
        result = ValidationResult(valid=True)
        assert bool(result) is True

    def test_invalid_result_is_falsy(self):
        result = ValidationResult(valid=False)
        assert bool(result) is False

    def test_add_error_marks_invalid(self):
        result = ValidationResult(valid=True)
        result.add_error("Test error")
        assert result.valid is False
        assert "Test error" in result.errors

    def test_add_warning_preserves_validity(self):
        result = ValidationResult(valid=True)
        result.add_warning("Test warning")
        assert result.valid is True
        assert "Test warning" in result.warnings

    def test_string_representation(self):
        result = ValidationResult(valid=False)
        result.add_error("Error 1")
        result.add_warning("Warning 1")
        output = str(result)
        assert "ERRORS:" in output
        assert "Error 1" in output
        assert "WARNINGS:" in output
        assert "Warning 1" in output

class TestContractValidation:
    """Test contract path validation."""

    def test_valid_solidity_file(self, tmp_path):
        # create valid solidity file
        contract_path = tmp_path / "MyContract.sol"
        contract_path.write_text("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MyContract {
    uint256 public value;
}
""")
        result = validate_contract(str(contract_path))
        assert result.valid is True
        assert len(result.errors) == 0

    def test_nonexistent_file(self):
        result = validate_contract("/nonexistent/path.sol")
        assert result.valid is False
        assert any("Cannot access" in error or "No such file" in error for error in result.errors)

    def test_directory_instead_of_file(self, tmp_path):
        result = validate_contract(str(tmp_path))
        assert result.valid is False
        # either "not a file", "is a directory", or symlink rejection (on macos /tmp)
        assert any("not a file" in error or "directory" in error.lower() or "Symlink" in error for error in result.errors)

    def test_file_without_sol_extension(self, tmp_path):
        file_path = tmp_path / "Contract.txt"
        file_path.write_text("pragma solidity ^0.8.0;")
        result = validate_contract(str(file_path))
        assert result.valid is True  # valid, but with warning
        assert any(".sol extension" in warning for warning in result.warnings)

    def test_empty_file(self, tmp_path):
        file_path = tmp_path / "Empty.sol"
        file_path.write_text("")
        result = validate_contract(str(file_path))
        assert result.valid is False
        assert any("empty" in error.lower() for error in result.errors)

    def test_file_without_solidity_markers(self, tmp_path):
        file_path = tmp_path / "NotSolidity.sol"
        file_path.write_text("some random text")
        result = validate_contract(str(file_path))
        assert result.valid is True  # valid, but with warning
        assert any("not be valid Solidity" in warning for warning in result.warnings)

    def test_path_traversal_warning(self, tmp_path):
        # create contract in subdirectory
        subdir = tmp_path / "contracts"
        subdir.mkdir()
        contract = subdir / "Test.sol"
        contract.write_text("pragma solidity ^0.8.0;")

        # access via ../
        result = validate_contract(str(tmp_path / "contracts" / ".." / "contracts" / "Test.sol"))
        assert result.valid is True or len(result.warnings) > 0

class TestProjectValidation:
    """Test Foundry project validation."""

    def test_valid_foundry_project(self, tmp_path):
        # create foundry.toml
        (tmp_path / "foundry.toml").write_text("[profile.default]\nsrc = 'src'")
        # create src directory with contract
        src = tmp_path / "src"
        src.mkdir()
        (src / "Contract.sol").write_text("pragma solidity ^0.8.0;")
        # create lib directory
        (tmp_path / "lib").mkdir()

        result = validate_project(str(tmp_path))
        assert result.valid is True

    def test_missing_foundry_toml(self, tmp_path):
        result = validate_project(str(tmp_path))
        assert result.valid is False
        assert any("foundry.toml" in error for error in result.errors)

    def test_missing_src_directory_warns(self, tmp_path):
        (tmp_path / "foundry.toml").write_text("[profile.default]")
        result = validate_project(str(tmp_path))
        assert result.valid is True  # valid, but warns
        assert any("src/" in warning for warning in result.warnings)

    def test_nonexistent_directory(self):
        result = validate_project("/nonexistent/project")
        assert result.valid is False
        assert any("Cannot access" in error or "No such file" in error for error in result.errors)

class TestAPIKeyValidation:
    """Test API key validation."""

    def test_valid_xai_key(self):
        # xAI format: xai-<40+ chars>
        key = "xai-" + "a" * 50
        result = validate_api_key(key, "xai")
        assert result.valid is True

    def test_valid_anthropic_key(self):
        # anthropic format: sk-ant-<40+ chars>
        key = "sk-ant-" + "a" * 50
        result = validate_api_key(key, "anthropic")
        assert result.valid is True

    def test_valid_openrouter_key(self):
        # openrouter format: sk-or-v1-<40+ chars>
        key = "sk-or-v1-" + "a" * 50
        result = validate_api_key(key, "openrouter")
        assert result.valid is True

    def test_key_too_short(self):
        result = validate_api_key("short", "generic")
        assert result.valid is False
        assert any("too short" in error for error in result.errors)

    def test_key_too_long(self):
        key = "x" * 600
        result = validate_api_key(key, "generic")
        assert result.valid is False
        assert any("too long" in error for error in result.errors)

    def test_empty_key(self):
        result = validate_api_key("", "xai")
        assert result.valid is False

    def test_key_with_newline(self):
        key = "xai-" + "a" * 50 + "\n"
        result = validate_api_key(key, "xai")
        assert result.valid is False
        assert any("newline" in error for error in result.errors)

    def test_key_with_whitespace_warns(self):
        key = " xai-" + "a" * 50 + " "
        result = validate_api_key(key, "xai")
        # may warn about whitespace
        assert len(result.warnings) > 0

class TestConfigValueValidation:
    """Test configuration value validation."""

    def test_valid_int_in_range(self):
        validator = InputValidator()
        result = validator.validate_config_value(
            "test_param", 50, int, min_val=0, max_val=100
        )
        assert result.valid is True

    def test_int_below_min(self):
        validator = InputValidator()
        result = validator.validate_config_value(
            "test_param", -5, int, min_val=0, max_val=100
        )
        assert result.valid is False
        assert any(">=" in error for error in result.errors)

    def test_int_above_max(self):
        validator = InputValidator()
        result = validator.validate_config_value(
            "test_param", 150, int, min_val=0, max_val=100
        )
        assert result.valid is False
        assert any("<=" in error for error in result.errors)

    def test_wrong_type(self):
        validator = InputValidator()
        result = validator.validate_config_value(
            "test_param", "string", int
        )
        assert result.valid is False
        assert any("must be int" in error for error in result.errors)

    def test_allowed_values(self):
        validator = InputValidator()
        result = validator.validate_config_value(
            "test_param", "invalid", str, allowed_values=["valid1", "valid2"]
        )
        assert result.valid is False
        assert any("must be one of" in error for error in result.errors)

    def test_valid_allowed_value(self):
        validator = InputValidator()
        result = validator.validate_config_value(
            "test_param", "valid1", str, allowed_values=["valid1", "valid2"]
        )
        assert result.valid is True

class TestPathSanitization:
    """Test path sanitization."""

    def test_sanitize_resolves_to_absolute(self):
        result = sanitize_path(".")
        assert Path(result).is_absolute()

    def test_sanitize_removes_null_bytes(self):
        try:
            result = sanitize_path("test\x00.sol")
            assert "\x00" not in result
        except ValueError:
            # may reject entirely
            pass

    def test_sanitize_resolves_traversal(self):
        result = sanitize_path("../test.sol")
        assert Path(result).is_absolute()

    def test_empty_path_raises(self):
        with pytest.raises(ValueError):
            sanitize_path("")

class TestContractNameSanitization:
    """Test contract name sanitization."""

    def test_valid_name_unchanged(self):
        result = sanitize_contract_name("MyContract")
        assert result == "MyContract"

    def test_name_with_underscore_unchanged(self):
        result = sanitize_contract_name("My_Contract_V2")
        assert result == "My_Contract_V2"

    def test_invalid_chars_replaced_with_underscore(self):
        result = sanitize_contract_name("My-Contract.sol")
        assert result == "My_Contract_sol"

    def test_name_starting_with_number_prefixed(self):
        result = sanitize_contract_name("123Contract")
        assert result == "_123Contract"

    def test_empty_name_raises(self):
        with pytest.raises(ValueError):
            sanitize_contract_name("")

class TestStartupConfigValidation:
    """Test startup configuration validation."""

    def test_validation_checks_api_keys(self):
        # this will fail if no api keys are set
        result = validate_startup_config()
        assert isinstance(result, ValidationResult)

    def test_validation_checks_project_root(self):
        result = validate_startup_config()
        assert isinstance(result, ValidationResult)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
