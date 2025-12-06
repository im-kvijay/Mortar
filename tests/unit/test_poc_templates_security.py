""" """

import pytest
import re
import sys
from pathlib import Path

# add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# import directly from the module file to avoid importing the whole agent package
import importlib.util

spec = importlib.util.spec_from_file_location(
    "poc_templates",
    project_root / "src" / "agent" / "poc_templates.py"
)
poc_templates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(poc_templates)

PoCTemplateLibrary = poc_templates.PoCTemplateLibrary
PoCTemplate = poc_templates.PoCTemplate
VulnType = poc_templates.VulnType
get_template_library = poc_templates.get_template_library
reset_library = poc_templates.reset_library

class TestPoCTemplatesSecurity:
    """Security tests for PoC template library."""

    def test_missing_placeholders_raises_error(self):
        library = PoCTemplateLibrary()

        template = PoCTemplate(
            vuln_type=VulnType.REENTRANCY,
            name="test_template",
            description="Test template",
            test_template="Contract: {CONTRACT_NAME}, Function: {FUNCTION_NAME}",
            placeholders={
                "CONTRACT_NAME": "Contract name",
                "FUNCTION_NAME": "Function name",
            },
        )

        # missing function_name placeholder
        context = {"CONTRACT_NAME": "TestContract"}

        with pytest.raises(ValueError, match="Missing required placeholders"):
            library.fill_template(template, context)

    def test_invalid_placeholder_name_raises_error(self):
        library = PoCTemplateLibrary()

        template = PoCTemplate(
            vuln_type=VulnType.REENTRANCY,
            name="test_template",
            description="Test template",
            test_template="Contract: {CONTRACT_NAME}",
            placeholders={"CONTRACT_NAME": "Contract name"},
        )

        # invalid placeholder name with lowercase (also provide correct one to bypass missing check)
        context = {"CONTRACT_NAME": "TestContract", "invalid-name": "value"}

        with pytest.raises(ValueError, match="Invalid placeholder name"):
            library.fill_template(template, context)

    def test_unfilled_placeholders_detected(self):
        library = PoCTemplateLibrary()

        template = PoCTemplate(
            vuln_type=VulnType.REENTRANCY,
            name="test_template",
            description="Test template",
            test_template="Contract: {CONTRACT_NAME}, Unused: {UNUSED}",
            placeholders={
                "CONTRACT_NAME": "Contract name",
                "UNUSED": "Unused placeholder",
            },
        )

        # only provide contract_name, unused will remain unfilled
        context = {"CONTRACT_NAME": "TestContract"}

        with pytest.raises(ValueError, match="Missing required placeholders"):
            library.fill_template(template, context)

    def test_type_check_hypothesis_category(self):
        library = PoCTemplateLibrary()

        # create mock hypothesis with non-string category
        class MockHypothesis:
            category = 123  # invalid type
            description = "Test description"

        result = library.match_hypothesis(MockHypothesis())
        assert result is None

    def test_type_check_hypothesis_description(self):
        library = PoCTemplateLibrary()

        # create mock hypothesis with non-string description
        class MockHypothesis:
            category = "reentrancy"
            description = None  # invalid type

        result = library.match_hypothesis(MockHypothesis())
        assert result is None

    def test_empty_templates_list_get_template(self):
        library = PoCTemplateLibrary()

        # clear templates for a type
        library.templates[VulnType.CUSTOM] = []
        result = library.get_template(VulnType.CUSTOM, variant="default")
        assert result is None

    def test_empty_templates_list_match_hypothesis(self):
        library = PoCTemplateLibrary()

        # clear templates for a type
        library.templates[VulnType.REENTRANCY] = []

        # create mock hypothesis
        class MockHypothesis:
            category = "reentrancy"
            description = "Test reentrancy vulnerability"

        result = library.match_hypothesis(MockHypothesis())
        assert result is None

    def test_regex_pattern_does_not_cause_redos(self):
        library = PoCTemplateLibrary()

        # create template with many consecutive braces (potential redos trigger)
        malicious_template = PoCTemplate(
            vuln_type=VulnType.REENTRANCY,
            name="test_template",
            description="Test template",
            test_template="{{{{{{{{{{{{{{{{{{{{CONTRACT}}}}}}}}}}}}}}}}}}}}",
            placeholders={"CONTRACT": "Contract name"},
        )

        # this should complete quickly without redos
        import time

        start = time.time()
        placeholders = library.get_unfilled_placeholders(malicious_template)
        elapsed = time.time() - start
        assert elapsed < 1.0
        assert "CONTRACT" in placeholders

    def test_valid_template_filling_succeeds(self):
        library = PoCTemplateLibrary()

        template = PoCTemplate(
            vuln_type=VulnType.REENTRANCY,
            name="test_template",
            description="Test template",
            test_template="Contract: {CONTRACT_NAME}, Function: {FUNCTION_NAME}",
            placeholders={
                "CONTRACT_NAME": "Contract name",
                "FUNCTION_NAME": "Function name",
            },
        )

        context = {"CONTRACT_NAME": "TestContract", "FUNCTION_NAME": "withdraw"}

        result = library.fill_template(template, context)

        assert "Contract: TestContract" in result
        assert "Function: withdraw" in result
        assert "{" not in result or "}" not in result or "{CONTRACT" not in result

    def test_escape_template_syntax_characters(self):
        library = PoCTemplateLibrary()

        template = PoCTemplate(
            vuln_type=VulnType.REENTRANCY,
            name="test_template",
            description="Test template",
            test_template="Value: {VALUE}",
            placeholders={"VALUE": "Some value"},
        )

        # context with escaped braces (edge case)
        context = {"VALUE": "Test\\{value\\}"}

        result = library.fill_template(template, context)
        assert "Value: Test" in result

    def test_singleton_library(self):
        # reset library first to ensure clean state
        reset_library()

        lib1 = get_template_library()
        lib2 = get_template_library()

        assert lib1 is lib2

    def test_builtin_templates_registered(self):
        library = get_template_library()
        assert len(library.templates[VulnType.REENTRANCY]) > 0
        assert len(library.templates[VulnType.FLASH_LOAN]) > 0
        assert len(library.templates[VulnType.ORACLE_MANIPULATION]) > 0
        assert len(library.templates[VulnType.ACCESS_CONTROL]) > 0
        assert len(library.templates[VulnType.INTEGER_OVERFLOW]) > 0
        assert len(library.templates[VulnType.UNCHECKED_RETURN]) > 0

    def test_hypothesis_matching_with_keywords(self):
        library = get_template_library()

        # create hypothesis with reentrancy keywords
        class MockHypothesis:
            category = "reentrancy"
            description = "State update after external call allows reentrancy via fallback"

        template = library.match_hypothesis(MockHypothesis())

        assert template is not None
        assert template.vuln_type == VulnType.REENTRANCY

    def test_non_string_context_values_converted(self):
        library = PoCTemplateLibrary()

        template = PoCTemplate(
            vuln_type=VulnType.REENTRANCY,
            name="test_template",
            description="Test template",
            test_template="Amount: {AMOUNT}",
            placeholders={"AMOUNT": "Amount value"},
        )

        # provide integer instead of string
        context = {"AMOUNT": 1000000}

        result = library.fill_template(template, context)

        assert "Amount: 1000000" in result
