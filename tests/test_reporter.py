"""Tests for the SARIFReporter module."""

import json

import pytest

from logicgate.models import AuditResult, Finding, Remediation, Severity, VulnType
from logicgate.reporter import SARIFReporter


@pytest.fixture
def sample_findings():
    return [
        Finding(
            vuln_type=VulnType.IDOR,
            severity=Severity.HIGH,
            title="IDOR in booking retrieval",
            description="Route fetches booking by ID without ownership check",
            affected_route="GET /api/bookings/:id",
            file_path="/tmp/test/server.js",
            start_line=105,
            end_line=114,
            recommendation="Add ownership verification",
            confidence=0.9,
            evidence="bookings.find(b => b.id === req.params.id) with no user check",
        ),
        Finding(
            vuln_type=VulnType.BFLA,
            severity=Severity.CRITICAL,
            title="No auth on admin panel",
            description="Admin route has no authentication middleware",
            affected_route="GET /admin",
            file_path="/tmp/test/server.js",
            start_line=179,
            end_line=181,
            recommendation="Add authentication middleware",
            confidence=1.0,
            evidence='app.get("/admin", ...) with no middleware',
        ),
    ]


@pytest.fixture
def sample_result(sample_findings):
    return AuditResult(
        route="GET /api/bookings/:id",
        findings=sample_findings,
        reasoning="Multiple authorization gaps found",
    )


class TestSARIFGeneration:
    def test_version(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        assert sarif["version"] == "2.1.0"

    def test_schema_present(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        assert "$schema" in sarif

    def test_single_run(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        assert len(sarif["runs"]) == 1

    def test_tool_name(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "LogicGate"
        assert driver["version"] == "0.1.0"

    def test_rules_defined(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 5  # LG001-LG005
        rule_ids = [r["id"] for r in rules]
        assert "LG001" in rule_ids
        assert "LG002" in rule_ids

    def test_result_count(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_result_rule_ids(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        results = sarif["runs"][0]["results"]
        assert results[0]["ruleId"] == "LG001"  # IDOR
        assert results[1]["ruleId"] == "LG002"  # BFLA

    def test_severity_mapping(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        results = sarif["runs"][0]["results"]
        # HIGH -> error, CRITICAL -> error
        assert results[0]["level"] == "error"
        assert results[1]["level"] == "error"

    def test_relative_paths(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        results = sarif["runs"][0]["results"]
        uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "server.js"  # relative to /tmp/test

    def test_confidence_in_properties(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        results = sarif["runs"][0]["results"]
        assert results[0]["properties"]["confidence"] == 0.9

    def test_serializable(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        # Must be JSON-serializable
        json_str = json.dumps(sarif, indent=2)
        assert len(json_str) > 0

    def test_empty_findings(self):
        reporter = SARIFReporter()
        result = AuditResult(route="GET /test", findings=[], reasoning="No issues")
        sarif = reporter.generate([result], "/tmp/test")
        assert len(sarif["runs"][0]["results"]) == 0

    def test_write(self, sample_result, tmp_path):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        output_path = tmp_path / "report.sarif.json"
        reporter.write(sarif, output_path)
        assert output_path.exists()
        loaded = json.loads(output_path.read_text())
        assert loaded["version"] == "2.1.0"


class TestSARIFWithFixes:
    @pytest.fixture
    def remediation(self):
        return Remediation(
            finding_title="IDOR in booking retrieval",
            file_path="/tmp/test/server.js",
            diff="--- a/server.js\n+++ b/server.js\n@@ -105,3 +105,5 @@\n-old\n+new",
            explanation="Added ownership check to booking lookup",
            confidence=0.85,
        )

    def test_fixes_present(self, sample_result, remediation):
        reporter = SARIFReporter()
        sarif = reporter.generate(
            [sample_result], "/tmp/test", remediations=[remediation]
        )
        results = sarif["runs"][0]["results"]
        # First finding matches the remediation title
        matched = [r for r in results if "fixes" in r]
        assert len(matched) == 1

    def test_fix_description(self, sample_result, remediation):
        reporter = SARIFReporter()
        sarif = reporter.generate(
            [sample_result], "/tmp/test", remediations=[remediation]
        )
        results = sarif["runs"][0]["results"]
        matched = [r for r in results if "fixes" in r]
        fix = matched[0]["fixes"][0]
        assert fix["description"]["text"] == "Added ownership check to booking lookup"

    def test_fix_artifact_changes(self, sample_result, remediation):
        reporter = SARIFReporter()
        sarif = reporter.generate(
            [sample_result], "/tmp/test", remediations=[remediation]
        )
        results = sarif["runs"][0]["results"]
        matched = [r for r in results if "fixes" in r]
        changes = matched[0]["fixes"][0]["artifactChanges"]
        assert len(changes) == 1
        assert changes[0]["artifactLocation"]["uri"] == "server.js"

    def test_no_fixes_without_remediation(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test")
        results = sarif["runs"][0]["results"]
        for r in results:
            assert "fixes" not in r

    def test_no_fixes_with_empty_list(self, sample_result):
        reporter = SARIFReporter()
        sarif = reporter.generate([sample_result], "/tmp/test", remediations=[])
        results = sarif["runs"][0]["results"]
        for r in results:
            assert "fixes" not in r

    def test_serializable_with_fixes(self, sample_result, remediation):
        reporter = SARIFReporter()
        sarif = reporter.generate(
            [sample_result], "/tmp/test", remediations=[remediation]
        )
        json_str = json.dumps(sarif, indent=2)
        assert len(json_str) > 0
