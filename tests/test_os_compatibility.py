"""
Tests for OS Compatibility Enhancements in VulnGuard.

This module tests:
- OS detection functions (_parse_os_release, _get_os_family, _is_os_compatible)
- OS family mapping (AlmaLinux → rhel, Rocky → rhel, etc.)
- Compatibility checking scenarios
- ScanResult status field behavior
- EvaluationResult status field behavior
- Summary calculation with skipped rules
- Backward compatibility with legacy code
"""

import unittest
import os
import sys
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

# Allow importing from parent directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnguard.pkg.scanner.scanner import (
    _parse_os_release,
    _get_os_family,
    _is_os_compatible,
    ScanResult,
    OS_FAMILY_MAP,
)
from vulnguard.pkg.engine.engine import (
    ComplianceEngine,
    EvaluationResult,
)


class TestParseOsRelease(unittest.TestCase):
    """Tests for the _parse_os_release() function."""

    def test_parse_alma_linux(self):
        """Test parsing AlmaLinux /etc/os-release."""
        os_release_content = '''NAME="AlmaLinux"
VERSION="8.8"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="8.8"
PLATFORM_ID="platform:el8"
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        self.assertEqual(result[0], "almalinux")
        self.assertEqual(result[1], "rhel")

    def test_parse_rocky_linux(self):
        """Test parsing Rocky Linux /etc/os-release."""
        os_release_content = '''NAME="Rocky Linux"
VERSION="9.2"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.2"
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        self.assertEqual(result[0], "rocky")
        self.assertEqual(result[1], "rhel")

    def test_parse_ubuntu(self):
        """Test parsing Ubuntu /etc/os-release."""
        os_release_content = '''NAME="Ubuntu"
VERSION="22.04 LTS (Jammy Jellyfish)"
ID="ubuntu"
ID_LIKE="debian"
VERSION_ID="22.04"
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        self.assertEqual(result[0], "ubuntu")
        self.assertEqual(result[1], "debian")

    def test_parse_debian(self):
        """Test parsing Debian /etc/os-release."""
        os_release_content = '''NAME="Debian"
VERSION="11 (bullseye)"
ID="debian"
ID_LIKE="debian"
VERSION_ID="11"
PRETTY_NAME="Debian 11 (bullseye)"
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        self.assertEqual(result[0], "debian")
        self.assertEqual(result[1], "debian")

    def test_parse_rhel(self):
        """Test parsing RHEL /etc/os-release."""
        os_release_content = '''NAME="Red Hat Enterprise Linux"
VERSION="8.6"
ID="rhel"
ID_LIKE="rhel fedora"
VERSION_ID="8.6"
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        self.assertEqual(result[0], "rhel")
        self.assertEqual(result[1], "rhel")

    def test_parse_centos(self):
        """Test parsing CentOS /etc/os-release."""
        os_release_content = '''NAME="CentOS Stream"
VERSION="8"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="8"
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        self.assertEqual(result[0], "centos")
        self.assertEqual(result[1], "rhel")

    def test_parse_file_not_found(self):
        """Test parsing when /etc/os-release doesn't exist."""
        with patch("builtins.open", side_effect=FileNotFoundError("/etc/os-release")):
            result = _parse_os_release()
        self.assertIsNone(result[0])
        self.assertIsNone(result[1])

    def test_parse_empty_id_like(self):
        """Test parsing with empty ID_LIKE field."""
        os_release_content = '''NAME="TestOS"
ID="testos"
ID_LIKE=""
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        self.assertEqual(result[0], "testos")
        self.assertIsNone(result[1])  # Empty ID_LIKE should return None

    def test_parse_quoted_values(self):
        """Test parsing with quoted values in /etc/os-release."""
        os_release_content = '''NAME="AlmaLinux"
ID="almalinux"
ID_LIKE="rhel centos"
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        self.assertEqual(result[0], "almalinux")
        self.assertEqual(result[1], "rhel")

    def test_parse_case_insensitivity(self):
        """Test that parsing is case-insensitive for ID_LIKE values."""
        os_release_content = '''NAME="TestOS"
ID="TestOS"
ID_LIKE="RHEL Centos"
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        self.assertEqual(result[0], "testos")  # Lowercase
        self.assertEqual(result[1], "rhel")  # Lowercase

    def test_parse_single_word_id_like(self):
        """Test parsing with single word ID_LIKE."""
        os_release_content = '''NAME="TestOS"
ID="testos"
ID_LIKE="rhel"
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        self.assertEqual(result[0], "testos")
        self.assertEqual(result[1], "rhel")


class TestGetOsFamily(unittest.TestCase):
    """Tests for the _get_os_family() function."""

    def test_almalinux_to_rhel(self):
        """Test AlmaLinux maps to RHEL family."""
        self.assertEqual(_get_os_family("almalinux"), "rhel")

    def test_rocky_to_rhel(self):
        """Test Rocky Linux maps to RHEL family."""
        self.assertEqual(_get_os_family("rocky"), "rhel")

    def test_centos_to_rhel(self):
        """Test CentOS maps to RHEL family."""
        self.assertEqual(_get_os_family("centos"), "rhel")

    def test_rhel_to_rhel(self):
        """Test RHEL maps to RHEL family."""
        self.assertEqual(_get_os_family("rhel"), "rhel")

    def test_ubuntu_to_debian(self):
        """Test Ubuntu maps to Debian family."""
        self.assertEqual(_get_os_family("ubuntu"), "debian")

    def test_debian_to_debian(self):
        """Test Debian maps to Debian family."""
        self.assertEqual(_get_os_family("debian"), "debian")

    def test_unknown_os_returns_self(self):
        """Test unknown OS returns itself as family."""
        self.assertEqual(_get_os_family("unknownos"), "unknownos")
        self.assertEqual(_get_os_family("solaris"), "solaris")

    def test_none_input(self):
        """Test None input returns None."""
        self.assertIsNone(_get_os_family(None))

    def test_case_insensitive(self):
        """Test family lookup handles lowercase inputs in map."""
        # The map contains lowercase values, so we test that the function works
        self.assertEqual(_get_os_family("almalinux"), "rhel")
        self.assertEqual(_get_os_family("centos"), "rhel")
        self.assertEqual(_get_os_family("ubuntu"), "debian")

    def test_fedora_not_in_map(self):
        """Test Fedora is not in OS_FAMILY_MAP and returns itself."""
        # Fedora is not in the map, so it should return itself
        self.assertEqual(_get_os_family("fedora"), "fedora")

    def test_red_hat_variant(self):
        """Test 'red hat' variant maps to RHEL."""
        self.assertEqual(_get_os_family("red hat"), "rhel")


class TestIsOsCompatible(unittest.TestCase):
    """Tests for the _is_os_compatible() function."""

    def test_direct_match_ubuntu(self):
        """Test direct OS match for Ubuntu."""
        self.assertTrue(_is_os_compatible("ubuntu", "debian", ["ubuntu"]))
        self.assertTrue(_is_os_compatible("ubuntu", "debian", ["ubuntu", "debian"]))

    def test_family_match_almalinux(self):
        """Test family-based match for AlmaLinux."""
        # AlmaLinux (detected_os=almalinux, family=rhel) should match "rhel"
        self.assertTrue(_is_os_compatible("almalinux", "rhel", ["rhel"]))
        self.assertTrue(_is_os_compatible("almalinux", "rhel", ["centos", "rhel"]))

    def test_family_match_rocky(self):
        """Test family-based match for Rocky Linux."""
        self.assertTrue(_is_os_compatible("rocky", "rhel", ["rhel"]))
        self.assertTrue(_is_os_compatible("rocky", "rhel", ["centos", "almalinux", "rhel"]))

    def test_no_match_scenario(self):
        """Test incompatibility scenario."""
        # Fedora is not compatible with RHEL rules
        self.assertFalse(_is_os_compatible("fedora", "fedora", ["rhel"]))
        # Ubuntu is not compatible with RHEL rules
        self.assertFalse(_is_os_compatible("ubuntu", "debian", ["rhel"]))

    def test_empty_compatible_list(self):
        """Test empty compatible list means compatible with all."""
        self.assertTrue(_is_os_compatible("anyos", "anyfamily", []))
        self.assertTrue(_is_os_compatible("fedora", "fedora", []))

    def test_case_insensitive_matching(self):
        """Test case-insensitive matching for rule OS list."""
        self.assertTrue(_is_os_compatible("ubuntu", "debian", ["UBUNTU"]))
        self.assertTrue(_is_os_compatible("almalinux", "rhel", ["RHEL"]))
        self.assertTrue(_is_os_compatible("ubuntu", "debian", ["Ubuntu"]))

    def test_mixed_direct_and_family_match(self):
        """Test rule with multiple OS options."""
        # Rule supports both Ubuntu and Debian family
        self.assertTrue(_is_os_compatible("ubuntu", "debian", ["ubuntu", "debian"]))
        self.assertTrue(_is_os_compatible("debian", "debian", ["ubuntu", "debian"]))

    def test_none_os_family(self):
        """Test behavior when os_family is None."""
        # Should still work with direct match
        self.assertTrue(_is_os_compatible("ubuntu", None, ["ubuntu"]))
        # Should fail family match when family is None
        self.assertFalse(_is_os_compatible("customos", None, ["rhel"]))

    def test_debian_compatibility(self):
        """Test Debian family compatibility."""
        self.assertTrue(_is_os_compatible("debian", "debian", ["debian"]))
        self.assertTrue(_is_os_compatible("ubuntu", "debian", ["debian"]))

    def test_rhel_compatibility(self):
        """Test RHEL family compatibility."""
        self.assertTrue(_is_os_compatible("rhel", "rhel", ["rhel"]))
        self.assertTrue(_is_os_compatible("centos", "rhel", ["rhel"]))
        self.assertTrue(_is_os_compatible("almalinux", "rhel", ["rhel"]))
        self.assertTrue(_is_os_compatible("rocky", "rhel", ["rhel"]))


class TestOsFamilyMapping(unittest.TestCase):
    """Tests for OS_FAMILY_MAP structure."""

    def test_rhel_family_contains_all_variants(self):
        """Test RHEL family contains all expected variants."""
        variants = OS_FAMILY_MAP["rhel"]
        self.assertIn("rhel", variants)
        self.assertIn("red hat", variants)
        self.assertIn("centos", variants)
        self.assertIn("almalinux", variants)
        self.assertIn("rocky", variants)

    def test_debian_family_contains_all_variants(self):
        """Test Debian family contains all expected variants."""
        variants = OS_FAMILY_MAP["debian"]
        self.assertIn("debian", variants)
        self.assertIn("ubuntu", variants)

    def test_families_are_lowercase(self):
        """Test all family names and variants are lowercase."""
        for family, variants in OS_FAMILY_MAP.items():
            self.assertEqual(family, family.lower())
            for variant in variants:
                self.assertEqual(variant, variant.lower())


class TestScanResultStatusField(unittest.TestCase):
    """Tests for ScanResult status field behavior."""

    def test_skipped_os_status(self):
        """Test OS-incompatible rules get status='skipped_os'."""
        result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=None,
            expected_state="N/A",
            actual_state="not_applicable",
            check_output="Rule skipped due to OS incompatibility",
            status="skipped_os"
        )
        self.assertEqual(result.status, "skipped_os")
        self.assertIsNone(result.compliant)
        self.assertEqual(result.actual_state, "not_applicable")

    def test_checked_status(self):
        """Test compatible rules get default status='checked'."""
        result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=True,
            expected_state="enabled",
            actual_state="enabled",
            check_output="output"
        )
        self.assertEqual(result.status, "checked")

    def test_default_status_value(self):
        """Test that default status is 'checked'."""
        result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=True,
            expected_state="enabled",
            actual_state="enabled",
            check_output="output"
        )
        self.assertEqual(result.status, "checked")

    def test_skipped_manual_status(self):
        """Test manually disabled rules get status='skipped_manual'."""
        result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=None,
            expected_state="N/A",
            actual_state="not_applicable",
            check_output="Rule manually disabled",
            status="skipped_manual"
        )
        self.assertEqual(result.status, "skipped_manual")

    def test_not_applicable_status(self):
        """Test not applicable rules get status='not_applicable'."""
        result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=None,
            expected_state="N/A",
            actual_state="not_applicable",
            check_output="Rule not applicable",
            status="not_applicable"
        )
        self.assertEqual(result.status, "not_applicable")

    def test_to_dict_includes_status(self):
        """Test that to_dict() includes status field."""
        result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=True,
            expected_state="enabled",
            actual_state="enabled",
            check_output="output",
            status="checked"
        )
        result_dict = result.to_dict()
        self.assertIn("status", result_dict)
        self.assertEqual(result_dict["status"], "checked")

    def test_skipped_rules_have_none_compliant(self):
        """Test that skipped rules have compliant=None."""
        result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=None,
            expected_state="N/A",
            actual_state="not_applicable",
            check_output="Skipped",
            status="skipped_os"
        )
        self.assertIsNone(result.compliant)


class TestEvaluationResultStatusField(unittest.TestCase):
    """Tests for EvaluationResult status field behavior."""

    def test_not_applicable_status_for_skipped(self):
        """Test skipped rules get status='not_applicable'."""
        result = EvaluationResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=None,
            severity="high",
            risk_level="low",
            ai_assist_required=False,
            approval_required=False,
            exception_allowed=False,
            status="not_applicable"
        )
        self.assertEqual(result.status, "not_applicable")

    def test_evaluated_status_default(self):
        """Test evaluated rules get default status='evaluated'."""
        result = EvaluationResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=True,
            severity="high",
            risk_level="low",
            ai_assist_required=False,
            approval_required=False,
            exception_allowed=False
        )
        self.assertEqual(result.status, "evaluated")

    def test_skipped_rules_have_low_risk(self):
        """Test skipped rules have risk_level='low'."""
        result = EvaluationResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=None,
            severity="high",
            risk_level="low",
            ai_assist_required=False,
            approval_required=False,
            exception_allowed=False,
            status="not_applicable"
        )
        self.assertEqual(result.risk_level, "low")

    def test_to_dict_includes_status(self):
        """Test that to_dict() includes status field."""
        result = EvaluationResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=True,
            severity="high",
            risk_level="low",
            ai_assist_required=False,
            approval_required=False,
            exception_allowed=False,
            status="evaluated"
        )
        result_dict = result.to_dict()
        self.assertIn("status", result_dict)
        self.assertEqual(result_dict["status"], "evaluated")


class TestComplianceEngineSkippedRules(unittest.TestCase):
    """Tests for ComplianceEngine handling of skipped rules."""

    def setUp(self):
        self.logger = MagicMock()
        self.engine = ComplianceEngine(logger=self.logger)

    def test_skipped_rule_gets_not_applicable_status(self):
        """Test that skipped rules get status='not_applicable' in evaluation."""
        scan_result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=None,
            expected_state="N/A",
            actual_state="not_applicable",
            check_output="Skipped",
            status="skipped_os",
            applicability="not_applicable"  # NEW: Mark as not applicable
        )
        
        # Create mock rule data
        rule_data = {
            "id": "test_rule",
            "benchmark": "CIS",
            "severity": "high",
            "original_severity": "Level1"
        }
        
        result = self.engine.evaluate(scan_result, rule_data)
        
        self.assertEqual(result.status, "not_applicable")
        self.assertIsNone(result.compliant)
        self.assertEqual(result.applicability, "not_applicable")  # NEW: Check applicability
        self.assertEqual(result.risk_level, "N/A")  # Changed from "low" to "N/A"

    def test_skipped_manual_gets_not_applicable_status(self):
        """Test that manually skipped rules get status='not_applicable'."""
        scan_result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=None,
            expected_state="N/A",
            actual_state="not_applicable",
            check_output="Manually disabled",
            status="skipped_manual",
            applicability="not_applicable"  # NEW: Mark as not applicable
        )
        
        rule_data = {
            "id": "test_rule",
            "benchmark": "CIS",
            "severity": "high",
            "original_severity": "Level1"
        }
        
        result = self.engine.evaluate(scan_result, rule_data)
        self.assertEqual(result.status, "not_applicable")
        self.assertEqual(result.applicability, "not_applicable")  # NEW: Check applicability
        self.assertEqual(result.risk_level, "N/A")  # NEW: Check risk level is N/A

    def test_evaluated_rule_gets_evaluated_status(self):
        """Test that evaluated rules get status='evaluated'."""
        scan_result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=False,
            expected_state="enabled",
            actual_state="disabled",
            check_output="disabled",
            status="checked"
        )
        
        rule_data = {
            "id": "test_rule",
            "benchmark": "CIS",
            "severity": "high",
            "original_severity": "Level1",
            "ai_assist": False,
            "approval_required": False,
            "exception_allowed": False
        }
        
        result = self.engine.evaluate(scan_result, rule_data)
        self.assertEqual(result.status, "evaluated")

    def test_skipped_no_ai_assist_required(self):
        """Test skipped rules don't require AI assist."""
        scan_result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=None,
            expected_state="N/A",
            actual_state="not_applicable",
            check_output="Skipped",
            status="skipped_os"
        )
        
        rule_data = {
            "id": "test_rule",
            "benchmark": "CIS",
            "severity": "high",
            "original_severity": "Level1"
        }
        
        result = self.engine.evaluate(scan_result, rule_data)
        self.assertFalse(result.ai_assist_required)

    def test_skipped_no_approval_required(self):
        """Test skipped rules don't require approval."""
        scan_result = ScanResult(
            rule_id="test_rule",
            benchmark="STIG",
            compliant=None,
            expected_state="N/A",
            actual_state="not_applicable",
            check_output="Skipped",
            status="skipped_os"
        )
        
        rule_data = {
            "id": "test_rule",
            "benchmark": "STIG",
            "severity": "high",
            "original_severity": "CAT_I"
        }
        
        result = self.engine.evaluate(scan_result, rule_data)
        self.assertFalse(result.approval_required)


class TestSummaryCalculation(unittest.TestCase):
    """Tests for summary calculation with skipped rules."""

    def setUp(self):
        self.logger = MagicMock()
        self.engine = ComplianceEngine(logger=self.logger)

    def test_skipped_rules_excluded_from_compliance_percentage(self):
        """Test that skipped rules don't affect compliance percentage."""
        # Create evaluation results with mixed statuses
        results = [
            EvaluationResult(
                rule_id="rule_1",
                benchmark="CIS",
                compliant=True,
                severity="high",
                risk_level="low",
                ai_assist_required=False,
                approval_required=False,
                exception_allowed=False,
                status="evaluated"
            ),
            EvaluationResult(
                rule_id="rule_2",
                benchmark="CIS",
                compliant=False,
                severity="high",
                risk_level="high",
                ai_assist_required=False,
                approval_required=False,
                exception_allowed=False,
                status="evaluated"
            ),
            EvaluationResult(
                rule_id="rule_3",
                benchmark="CIS",
                compliant=None,
                severity="high",
                risk_level="N/A",  # Changed from "low" to "N/A"
                ai_assist_required=False,
                approval_required=False,
                exception_allowed=False,
                status="not_applicable",
                applicability="not_applicable"  # NEW: Add applicability field
            ),
        ]
        
        summary = self.engine.generate_summary(results)
        
        # Total: 3, Evaluated: 2, Not applicable: 1
        self.assertEqual(summary["total_rules"], 3)
        self.assertEqual(summary["evaluated_rules"], 2)
        self.assertEqual(summary["not_applicable_rules"], 1)
        # Compliance: 1 compliant out of 2 evaluated = 50%
        self.assertEqual(summary["compliant_count"], 1)
        self.assertEqual(summary["non_compliant_count"], 1)
        self.assertEqual(summary["compliance_percentage"], 50.0)

    def test_all_rules_skipped_zero_compliance(self):
        """Test 0% compliance when all rules are skipped."""
        results = [
            EvaluationResult(
                rule_id="rule_1",
                benchmark="CIS",
                compliant=None,
                severity="high",
                risk_level="N/A",  # Changed from "low" to "N/A"
                ai_assist_required=False,
                approval_required=False,
                exception_allowed=False,
                status="not_applicable",
                applicability="not_applicable"  # NEW: Add applicability field
            ),
            EvaluationResult(
                rule_id="rule_2",
                benchmark="CIS",
                compliant=None,
                severity="medium",
                risk_level="N/A",  # Changed from "low" to "N/A"
                ai_assist_required=False,
                approval_required=False,
                exception_allowed=False,
                status="not_applicable",
                applicability="not_applicable"  # NEW: Add applicability field
            ),
        ]
        
        summary = self.engine.generate_summary(results)
        
        # All rules skipped
        self.assertEqual(summary["total_rules"], 2)
        self.assertEqual(summary["evaluated_rules"], 0)
        self.assertEqual(summary["not_applicable_rules"], 2)
        self.assertEqual(summary["compliance_percentage"], 0.0)
        self.assertEqual(summary["compliant_count"], 0)
        self.assertEqual(summary["non_compliant_count"], 0)

    def test_status_distribution_count(self):
        """Test status distribution in summary."""
        results = [
            EvaluationResult(
                rule_id="rule_1",
                benchmark="CIS",
                compliant=True,
                severity="high",
                risk_level="low",
                ai_assist_required=False,
                approval_required=False,
                exception_allowed=False,
                status="evaluated"
            ),
            EvaluationResult(
                rule_id="rule_2",
                benchmark="CIS",
                compliant=None,
                severity="high",
                risk_level="low",
                ai_assist_required=False,
                approval_required=False,
                exception_allowed=False,
                status="not_applicable"
            ),
        ]
        
        summary = self.engine.generate_summary(results)
        
        self.assertEqual(summary["status_distribution"]["evaluated"], 1)
        self.assertEqual(summary["status_distribution"]["not_applicable"], 1)

    def test_risk_distribution_includes_skipped(self):
        """Test that skipped rules contribute to risk distribution."""
        results = [
            EvaluationResult(
                rule_id="rule_1",
                benchmark="CIS",
                compliant=False,
                severity="high",
                risk_level="high",
                ai_assist_required=False,
                approval_required=False,
                exception_allowed=False,
                status="evaluated"
            ),
            EvaluationResult(
                rule_id="rule_2",
                benchmark="CIS",
                compliant=None,
                severity="high",
                risk_level="low",
                ai_assist_required=False,
                approval_required=False,
                exception_allowed=False,
                status="not_applicable"
            ),
        ]
        
        summary = self.engine.generate_summary(results)
        
        # Risk distribution should include skipped rules (all rules)
        self.assertEqual(summary["risk_distribution"]["high"], 1)
        self.assertEqual(summary["risk_distribution"]["low"], 1)


class TestBackwardCompatibility(unittest.TestCase):
    """Tests for backward compatibility with legacy code."""

    def test_scanresult_without_status_field(self):
        """Test ScanResult works without explicit status field."""
        result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=True,
            expected_state="enabled",
            actual_state="enabled",
            check_output="output"
        )
        # Should default to "checked"
        self.assertEqual(result.status, "checked")

    def test_scanresult_to_dict_without_status(self):
        """Test to_dict() works for legacy ScanResult objects."""
        result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=True,
            expected_state="enabled",
            actual_state="enabled",
            check_output="output"
        )
        result_dict = result.to_dict()
        
        self.assertEqual(result_dict["rule_id"], "test_rule")
        self.assertEqual(result_dict["compliant"], True)
        self.assertEqual(result_dict["status"], "checked")

    def test_evaluationresult_without_status_field(self):
        """Test EvaluationResult works without explicit status field."""
        result = EvaluationResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=True,
            severity="high",
            risk_level="low",
            ai_assist_required=False,
            approval_required=False,
            exception_allowed=False
        )
        # Should default to "evaluated"
        self.assertEqual(result.status, "evaluated")

    def test_legacy_code_with_old_result_format(self):
        """Test that old code creating results without status still works."""
        # Simulate old code that only passes required fields
        result = ScanResult(
            rule_id="test_rule",
            benchmark="CIS",
            compliant=False,
            expected_state="enabled",
            actual_state="disabled",
            check_output="disabled"
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_id, "test_rule")
        self.assertFalse(result.compliant)
        self.assertEqual(result.status, "checked")  # Default value

    def test_determine_risk_level_with_none_compliant(self):
        """Test _determine_risk_level handles None compliant."""
        engine = ComplianceEngine()
        
        risk_level = engine._determine_risk_level("high", None)
        self.assertEqual(risk_level, "low")

    def test_determine_risk_level_with_compliant_true(self):
        """Test _determine_risk_level handles compliant=True."""
        engine = ComplianceEngine()
        
        risk_level = engine._determine_risk_level("high", True)
        self.assertEqual(risk_level, "low")

    def test_determine_risk_level_with_non_compliant(self):
        """Test _determine_risk_level handles non-compliant."""
        engine = ComplianceEngine()
        
        risk_level = engine._determine_risk_level("high", False)
        self.assertEqual(risk_level, "high")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases for OS compatibility functions."""

    def test_empty_os_release_file(self):
        """Test parsing empty /etc/os-release file."""
        with patch("builtins.open", mock_open(read_data="")):
            result = _parse_os_release()
        # Should return (None, None) for empty file
        self.assertIsNone(result[0])
        self.assertIsNone(result[1])

    def test_os_release_without_id_field(self):
        """Test parsing /etc/os-release without ID field."""
        os_release_content = '''NAME="TestOS"
VERSION="1.0"
ID_LIKE="rhel"
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        # Should return (None, first_family) since ID_LIKE exists
        self.assertIsNone(result[0])
        self.assertEqual(result[1], "rhel")

    def test_malformed_os_release(self):
        """Test parsing malformed /etc/os-release."""
        os_release_content = '''This is not valid
ID=invalid
ID_LIKE=rhel centos fedora
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        # Should return (invalid, rhel) since it still parses
        self.assertEqual(result[0], "invalid")
        self.assertEqual(result[1], "rhel")

    def test_get_os_family_empty_string(self):
        """Test _get_os_family with empty string."""
        result = _get_os_family("")
        self.assertIsNone(result)

    def test_is_os_compatible_with_empty_rule_list(self):
        """Test _is_os_compatible with empty rule list."""
        self.assertTrue(_is_os_compatible("anyos", "anyfamily", []))

    def test_is_os_compatible_with_whitespace_in_id_like(self):
        """Test parsing with extra whitespace in ID_LIKE."""
        os_release_content = '''NAME="TestOS"
ID="testos"
ID_LIKE="rhel   centos   fedora"
'''
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            result = _parse_os_release()
        self.assertEqual(result[0], "testos")
        self.assertEqual(result[1], "rhel")  # First word only


if __name__ == '__main__':
    unittest.main()
