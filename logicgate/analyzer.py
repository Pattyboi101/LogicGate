"""Claude LLM analyzer module for LogicGate security audits."""

from __future__ import annotations

import json
import logging
from typing import Any

import anthropic
from pydantic import ValidationError

from logicgate.models import AuditResult, RouteInfo

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are an expert application-security auditor specializing in Express.js \
back-end APIs. Your task is to analyze a single route handler and its \
dependency context (the full call chain of helper functions it invokes) for \
business-logic vulnerabilities.

Focus exclusively on these five vulnerability categories:

1. **IDOR (Insecure Direct Object Reference)**
   A user-supplied identifier (path param, query param, or body field) is \
used to look up or mutate a resource without verifying that the \
authenticated user owns or is authorized to access that resource.

2. **BFLA (Broken Function-Level Authorization)**
   A privileged action (admin panel, user management, billing mutation, etc.) \
is exposed without verifying the caller's role or permission set. Middleware \
that only checks "is authenticated" does NOT count as role verification.

3. **State Machine Manipulation**
   An entity with a defined lifecycle (order status, account state, approval \
workflow) can be moved to an invalid or skipped state because the handler \
does not validate the current state before applying the transition.

4. **Multi-Tenant Data Leakage**
   Data is queried or returned without filtering by the current tenant or \
organization ID, meaning one tenant could retrieve another tenant's records.

5. **Implicit Permission Bypass**
   The code assumes authorization has been enforced elsewhere (e.g., by \
middleware or a gateway) but no actual check exists in the handler or its \
call chain. Look for comments like "// auth handled by middleware" where \
the middleware list does not actually include an authorization middleware.

## Rules
- Only report findings for which you have concrete evidence in the provided \
source code. Do NOT speculate or invent issues.
- Cite the specific lines and code fragments that constitute the vulnerability.
- Consider the FULL call chain: if a helper function called by the handler \
performs the required check, the handler is NOT vulnerable.
- Evaluate whether middleware listed on the route actually enforces \
authorization (e.g., `isAuthenticated` only proves identity, not permission).
- Rate your confidence for each finding from 0.0 to 1.0.

## Response Format
Return your analysis as a single JSON object (no markdown fences, no extra \
text before or after the JSON). The JSON object MUST conform to this schema:

{
  "route": "<HTTP_METHOD> <ROUTE_PATTERN>",
  "findings": [
    {
      "vuln_type": "IDOR | BFLA | STATE_MANIPULATION | MULTI_TENANT_LEAK | IMPLICIT_PERMISSION",
      "severity": "critical | high | medium | low | info",
      "title": "Short title of the finding",
      "description": "Detailed explanation of the vulnerability",
      "affected_route": "<HTTP_METHOD> <ROUTE_PATTERN>",
      "file_path": "path/to/file.js",
      "start_line": 10,
      "end_line": 25,
      "recommendation": "How to remediate",
      "confidence": 0.85,
      "evidence": "The specific code snippet or logic that proves the issue"
    }
  ],
  "reasoning": "Step-by-step explanation of your analysis, including why you ruled out certain categories if applicable."
}

If the handler has no vulnerabilities in these categories, return the JSON \
with an empty "findings" array and explain in "reasoning" why it is safe.\
"""


class Analyzer:
    """Sends route handlers to Claude for security analysis."""

    def __init__(self, api_key: str, model: str = "claude-opus-4-6") -> None:
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def _build_user_prompt(self, route: RouteInfo, context: str) -> str:
        """Build the user-facing prompt for a single route audit."""
        middleware_str = ", ".join(route.middleware) if route.middleware else "(none)"

        return (
            f"## Route Under Audit\n"
            f"- **Method:** {route.http_method}\n"
            f"- **Path:** {route.route_pattern}\n"
            f"- **File:** {route.file_path}\n"
            f"- **Lines:** {route.handler_start_line}-{route.handler_end_line}\n"
            f"- **Middleware:** {middleware_str}\n"
            f"\n"
            f"### Handler Source Code\n"
            f"```js\n"
            f"{route.handler_source}\n"
            f"```\n"
            f"\n"
            f"### Dependency Context (Call Chain)\n"
            f"```js\n"
            f"{context}\n"
            f"```\n"
            f"\n"
            f"Analyze the handler AND its full call chain for the five "
            f"vulnerability categories. Return your findings as the specified "
            f"JSON object."
        )

    def audit_route(self, route: RouteInfo, context: str) -> AuditResult:
        """Audit a single route by calling Claude and parsing the response."""
        route_label = f"{route.http_method} {route.route_pattern}"
        user_prompt = self._build_user_prompt(route, context)

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )

            # Find the text block (skip thinking blocks if present)
            raw_text = ""
            for block in response.content:
                if block.type == "text":
                    raw_text = block.text
                    break

            # Strip markdown code fences if Claude wrapped the JSON
            stripped = raw_text.strip()
            if stripped.startswith("```"):
                # Remove opening fence (```json or ```)
                first_newline = stripped.index("\n")
                stripped = stripped[first_newline + 1:]
                # Remove closing fence
                if stripped.endswith("```"):
                    stripped = stripped[:-3].strip()
                raw_text = stripped

            raw: dict[str, Any] = json.loads(raw_text)
            result = AuditResult(**raw)
            return result

        except anthropic.APIError as exc:
            logger.error("Anthropic API error for route %s: %s", route_label, exc)
            return AuditResult(
                route=route_label,
                findings=[],
                reasoning=f"API error: {exc}",
            )

        except json.JSONDecodeError as exc:
            logger.warning(
                "JSON parse error for route %s: %s", route_label, exc
            )
            return AuditResult(
                route=route_label,
                findings=[],
                reasoning=f"Failed to parse LLM response as JSON: {exc}",
            )

        except ValidationError as exc:
            logger.warning(
                "Pydantic validation error for route %s: %s", route_label, exc
            )
            return AuditResult(
                route=route_label,
                findings=[],
                reasoning=f"LLM response did not match expected schema: {exc}",
            )

    def audit_all_routes(
        self, routes: list[RouteInfo], contexts: dict[str, str]
    ) -> list[AuditResult]:
        """Audit all routes sequentially, returning a list of results."""
        results: list[AuditResult] = []
        for route in routes:
            key = f"{route.http_method} {route.route_pattern}"
            context = contexts.get(key, "")
            result = self.audit_route(route, context)
            results.append(result)
        return results
