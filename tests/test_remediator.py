"""Tests for the Remediator module."""

import pytest

from logicgate.models import (
    Finding,
    Remediation,
    RouteInfo,
    Severity,
    VulnType,
)
from logicgate.remediator import Remediator


@pytest.fixture
def sample_finding():
    return Finding(
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
    )


@pytest.fixture
def sample_route():
    return RouteInfo(
        file_path="/tmp/test/server.js",
        http_method="GET",
        route_pattern="/api/bookings/:id",
        handler_start_line=105,
        handler_end_line=114,
        handler_source='(req, res) => { const bookings = readBookings(); }',
        middleware=[],
    )


@pytest.fixture
def sample_file_content():
    return (
        "const express = require('express');\n"
        "const app = express();\n"
        "\n"
        "app.get('/api/bookings/:id', (req, res) => {\n"
        "    const bookings = readBookings();\n"
        "    const booking = bookings.find(b => b.id === req.params.id);\n"
        "    if (!booking) {\n"
        "        return res.status(404).json({ error: 'Not found' });\n"
        "    }\n"
        "    res.json(booking);\n"
        "});\n"
    )


class TestRemediatorInit:
    def test_default_model(self):
        rem = Remediator(api_key="test-key")
        assert rem.model == "claude-opus-4-6"

    def test_custom_model(self):
        rem = Remediator(api_key="test-key", model="claude-sonnet-4-5-20250929")
        assert rem.model == "claude-sonnet-4-5-20250929"


class TestBuildUserPrompt:
    def test_contains_vuln_type(self, sample_finding, sample_file_content):
        rem = Remediator(api_key="test-key")
        prompt = rem._build_user_prompt(
            sample_file_content, sample_finding, "// context"
        )
        assert "IDOR" in prompt

    def test_contains_file_content(self, sample_finding, sample_file_content):
        rem = Remediator(api_key="test-key")
        prompt = rem._build_user_prompt(
            sample_file_content, sample_finding, "// context"
        )
        assert "readBookings" in prompt

    def test_contains_evidence(self, sample_finding, sample_file_content):
        rem = Remediator(api_key="test-key")
        prompt = rem._build_user_prompt(
            sample_file_content, sample_finding, "// context"
        )
        assert "no user check" in prompt

    def test_contains_route_context(self, sample_finding, sample_file_content):
        rem = Remediator(api_key="test-key")
        context = "function readBookings() { return []; }"
        prompt = rem._build_user_prompt(
            sample_file_content, sample_finding, context
        )
        assert "readBookings" in prompt
        assert "Route Context" in prompt

    def test_contains_recommendation(self, sample_finding, sample_file_content):
        rem = Remediator(api_key="test-key")
        prompt = rem._build_user_prompt(
            sample_file_content, sample_finding, "// context"
        )
        assert "ownership verification" in prompt


class TestRemediationModel:
    def test_valid_remediation(self):
        rem = Remediation(
            finding_title="IDOR in booking",
            file_path="/tmp/server.js",
            diff="--- a/server.js\n+++ b/server.js\n@@ -1 +1 @@\n-old\n+new",
            explanation="Added ownership check",
            confidence=0.85,
        )
        assert rem.finding_title == "IDOR in booking"
        assert rem.confidence == 0.85

    def test_confidence_bounds(self):
        with pytest.raises(Exception):
            Remediation(
                finding_title="test",
                file_path="test.js",
                diff="diff",
                explanation="test",
                confidence=1.5,
            )

    def test_confidence_lower_bound(self):
        with pytest.raises(Exception):
            Remediation(
                finding_title="test",
                file_path="test.js",
                diff="diff",
                explanation="test",
                confidence=-0.1,
            )
