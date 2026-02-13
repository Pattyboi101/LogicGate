"""SARIF 2.1.0 reporter for LogicGate audit results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typing import Optional

from logicgate.models import AuditResult, Finding, Remediation, Severity, VulnType

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

_OWASP_API_SECURITY = "https://owasp.org/API-Security/"


class _RuleDef:
    """Internal descriptor for a predefined LogicGate rule."""

    __slots__ = (
        "id",
        "vuln_type",
        "short_name",
        "full_name",
        "description",
        "default_level",
        "help_uri",
    )

    def __init__(
        self,
        id: str,
        vuln_type: VulnType,
        short_name: str,
        full_name: str,
        description: str,
        default_level: str,
        help_uri: str,
    ) -> None:
        self.id = id
        self.vuln_type = vuln_type
        self.short_name = short_name
        self.full_name = full_name
        self.description = description
        self.default_level = default_level
        self.help_uri = help_uri


_RULES: list[_RuleDef] = [
    _RuleDef(
        id="LG001",
        vuln_type=VulnType.IDOR,
        short_name="IDOR",
        full_name="Insecure Direct Object Reference",
        description=(
            "A route accesses a resource by a user-supplied identifier without "
            "verifying that the authenticated user owns or is authorized to "
            "access that resource."
        ),
        default_level="error",
        help_uri=f"{_OWASP_API_SECURITY}top10/",
    ),
    _RuleDef(
        id="LG002",
        vuln_type=VulnType.BFLA,
        short_name="BFLA",
        full_name="Broken Function-Level Authorization",
        description=(
            "An API endpoint exposes a sensitive action (e.g. admin, delete, "
            "modify) without adequate function-level authorization checks."
        ),
        default_level="error",
        help_uri=f"{_OWASP_API_SECURITY}top10/",
    ),
    _RuleDef(
        id="LG003",
        vuln_type=VulnType.STATE_MANIPULATION,
        short_name="StateMachineManipulation",
        full_name="State Machine Manipulation",
        description=(
            "A business-logic state transition can be forced into an invalid or "
            "skipped state because the server does not enforce the expected "
            "state machine."
        ),
        default_level="warning",
        help_uri=f"{_OWASP_API_SECURITY}top10/",
    ),
    _RuleDef(
        id="LG004",
        vuln_type=VulnType.MULTI_TENANT_LEAK,
        short_name="MultiTenantDataLeakage",
        full_name="Multi-Tenant Data Leakage",
        description=(
            "A multi-tenant application leaks data belonging to one tenant to "
            "another because queries or access controls do not scope results "
            "to the requesting tenant."
        ),
        default_level="error",
        help_uri=f"{_OWASP_API_SECURITY}top10/",
    ),
    _RuleDef(
        id="LG005",
        vuln_type=VulnType.IMPLICIT_PERMISSION,
        short_name="ImplicitPermissionBypass",
        full_name="Implicit Permission Bypass",
        description=(
            "Authorization relies on implicit assumptions (e.g. hidden routes, "
            "client-side checks) rather than explicit server-side permission "
            "verification."
        ),
        default_level="warning",
        help_uri=f"{_OWASP_API_SECURITY}top10/",
    ),
]

# Fast lookup: VulnType -> index into _RULES
_VULN_TO_RULE_INDEX: dict[VulnType, int] = {
    r.vuln_type: i for i, r in enumerate(_RULES)
}


def _severity_to_level(severity: Severity) -> str:
    """Map LogicGate severity to SARIF result level."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    # LOW and INFO
    return "note"


class SARIFReporter:
    """Converts LogicGate audit results into a SARIF 2.1.0 document."""

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def generate(
        self,
        results: list[AuditResult],
        target_dir: str,
        remediations: Optional[list[Remediation]] = None,
    ) -> dict[str, Any]:
        """Convert a list of *AuditResult* objects to a SARIF 2.1.0 dict.

        Parameters
        ----------
        results:
            Audit results produced by the LogicGate analysis engine.
        target_dir:
            Absolute path to the scanned project root.  File paths inside
            findings will be made relative to this directory.
        remediations:
            Optional list of Remediation objects to attach as SARIF fixes.
        """
        target = Path(target_dir)

        # Build remediation lookup: (file_path, finding_title) -> Remediation
        rem_map: dict[tuple[str, str], Remediation] = {}
        if remediations:
            for rem in remediations:
                rem_map[(rem.file_path, rem.finding_title)] = rem

        # Collect every finding across all results.
        all_findings: list[Finding] = []
        for audit in results:
            all_findings.extend(audit.findings)

        # Deduplicate artifact URIs while preserving order.
        artifact_uris: dict[str, int] = {}
        for f in all_findings:
            rel = self._relative_uri(f.file_path, target)
            if rel not in artifact_uris:
                artifact_uris[rel] = len(artifact_uris)

        sarif_results: list[dict[str, Any]] = []
        for finding in all_findings:
            rem = rem_map.get((finding.file_path, finding.title))
            sarif_results.append(
                self._finding_to_result(finding, target, artifact_uris, rem)
            )

        rules = self._build_rules_array()

        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": "LogicGate",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/logicgate",
                    "rules": rules,
                },
            },
            "artifacts": [
                {"location": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
                for uri in artifact_uris
            ],
            "results": sarif_results,
        }

        return {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [run],
        }

    def write(self, sarif: dict[str, Any], output_path: Path) -> None:
        """Serialize *sarif* to a JSON file at *output_path*."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(sarif, indent=2) + "\n", encoding="utf-8"
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _relative_uri(file_path: str, target: Path) -> str:
        """Return a POSIX-style path relative to *target*."""
        try:
            return str(Path(file_path).relative_to(target).as_posix())
        except ValueError:
            # file_path is not under target_dir -- use as-is.
            return str(Path(file_path).as_posix())

    @staticmethod
    def _build_rules_array() -> list[dict[str, Any]]:
        """Build the tool.driver.rules array from predefined rules."""
        rules: list[dict[str, Any]] = []
        for rule in _RULES:
            rules.append(
                {
                    "id": rule.id,
                    "shortDescription": {"text": rule.full_name},
                    "fullDescription": {"text": rule.description},
                    "defaultConfiguration": {"level": rule.default_level},
                    "helpUri": rule.help_uri,
                    "properties": {"tags": [rule.short_name]},
                }
            )
        return rules

    @staticmethod
    def _finding_to_result(
        finding: Finding,
        target: Path,
        artifact_uris: dict[str, int],
        remediation: Optional[Remediation] = None,
    ) -> dict[str, Any]:
        """Convert a single *Finding* to a SARIF result object."""
        rule_index = _VULN_TO_RULE_INDEX[finding.vuln_type]
        rule = _RULES[rule_index]
        rel_uri = SARIFReporter._relative_uri(finding.file_path, target)

        result_obj: dict[str, Any] = {
            "ruleId": rule.id,
            "ruleIndex": rule_index,
            "level": _severity_to_level(finding.severity),
            "message": {
                "text": f"{finding.title}: {finding.description}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": rel_uri,
                            "uriBaseId": "%SRCROOT%",
                            "index": artifact_uris[rel_uri],
                        },
                        "region": {
                            "startLine": finding.start_line,
                            "endLine": finding.end_line,
                        },
                    },
                },
            ],
            "properties": {
                "confidence": finding.confidence,
                "recommendation": finding.recommendation,
            },
        }

        if remediation:
            result_obj["fixes"] = [
                {
                    "description": {"text": remediation.explanation},
                    "artifactChanges": [
                        {
                            "artifactLocation": {
                                "uri": rel_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "replacements": [
                                {
                                    "deletedRegion": {
                                        "startLine": finding.start_line,
                                        "endLine": finding.end_line,
                                    },
                                    "insertedContent": {
                                        "text": remediation.diff,
                                    },
                                }
                            ],
                        }
                    ],
                }
            ]

        return result_obj
