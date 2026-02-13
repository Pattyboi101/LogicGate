"""LLM-powered code remediation for LogicGate vulnerabilities."""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import anthropic
from pydantic import BaseModel, ValidationError

from logicgate.models import Finding, Remediation, RouteInfo

logger = logging.getLogger(__name__)

REMEDIATION_SYSTEM_PROMPT = """\
You are an expert security engineer specializing in remediating business-logic \
vulnerabilities in Express.js applications. Your task is to generate a minimal, \
surgical code fix for a specific vulnerability.

## Input
You will receive:
1. The full source file containing the vulnerable code
2. A specific security finding with evidence and recommendation
3. The route context showing the call chain

## Task
Generate a unified diff patch that fixes ONLY the identified vulnerability. \
The patch must be applicable with `git apply` or `patch -p1`.

## Remediation Patterns by Vulnerability Type

### IDOR (Insecure Direct Object Reference)
Add ownership/authorization check before resource access:
```javascript
// Add ownership filter to lookup
const booking = bookings.find(b =>
  b.id === req.params.id && b.userId === req.user.id
);
```

### BFLA (Broken Function-Level Authorization)
Add role-based middleware or inline role check:
```javascript
// Add auth middleware to route
app.get('/admin', requireAuth, requireRole('admin'), (req, res) => { ... });
```

### STATE_MANIPULATION
Add current state validation before transition:
```javascript
const validTransitions = {
  'pending': ['confirmed', 'cancelled'],
  'confirmed': ['completed', 'cancelled'],
  'completed': [],
  'cancelled': []
};
const currentStatus = bookings[index].status;
if (!validTransitions[currentStatus]?.includes(req.body.status)) {
  return res.status(400).json({
    error: `Cannot transition from ${currentStatus} to ${req.body.status}`
  });
}
```

### MULTI_TENANT_LEAK
Add tenant scoping to queries:
```javascript
const bookings = allBookings.filter(b => b.tenantId === req.user.tenantId);
```

### IMPLICIT_PERMISSION
Add explicit authentication middleware:
```javascript
const requireAuth = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};
app.get('/admin', requireAuth, (req, res) => { ... });
```

## Important Constraints
- Fix ONLY the identified vulnerability — do NOT refactor unrelated code
- Keep line changes minimal to reduce merge conflicts
- Assume req.user is populated by upstream auth middleware
- Do NOT add heavy dependencies
- The diff must use the correct file path in --- and +++ headers

## Response Format
Return a single JSON object (no markdown fences, no extra text):
{
  "diff": "--- a/server.js\\n+++ b/server.js\\n@@ -105,7 +105,10 @@\\n...",
  "explanation": "Added ownership check by filtering bookings to match req.user.id.",
  "confidence": 0.85
}

The "diff" field must be a valid unified diff.\
"""


class _RemediationResponse(BaseModel):
    """Internal model for parsing LLM remediation response."""

    diff: str
    explanation: str
    confidence: float


class Remediator:
    """Generates code fixes for security findings using Claude."""

    def __init__(self, api_key: str, model: str = "claude-opus-4-6") -> None:
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def _build_user_prompt(
        self, file_content: str, finding: Finding, route_context: str
    ) -> str:
        """Build the remediation prompt for a single finding."""
        return (
            f"## Vulnerability to Fix\n"
            f"- **Type:** {finding.vuln_type.value}\n"
            f"- **Severity:** {finding.severity.value}\n"
            f"- **Title:** {finding.title}\n"
            f"- **File:** {finding.file_path}\n"
            f"- **Lines:** {finding.start_line}-{finding.end_line}\n"
            f"- **Description:** {finding.description}\n"
            f"- **Evidence:** {finding.evidence}\n"
            f"- **Recommendation:** {finding.recommendation}\n"
            f"\n"
            f"## Full File Content\n"
            f"```javascript\n"
            f"{file_content}\n"
            f"```\n"
            f"\n"
            f"## Route Context (Call Chain)\n"
            f"```javascript\n"
            f"{route_context}\n"
            f"```\n"
            f"\n"
            f"Generate a unified diff patch to fix this vulnerability. "
            f"Return ONLY the JSON object."
        )

    def remediate(
        self,
        finding: Finding,
        route: RouteInfo,
        file_content: str,
        route_context: str,
    ) -> Optional[Remediation]:
        """Generate a remediation for a single finding.

        Returns a Remediation object with a unified diff patch,
        or None if generation failed.
        """
        try:
            user_prompt = self._build_user_prompt(
                file_content, finding, route_context
            )

            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=REMEDIATION_SYSTEM_PROMPT,
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
                first_newline = stripped.index("\n")
                stripped = stripped[first_newline + 1:]
                if stripped.endswith("```"):
                    stripped = stripped[:-3].strip()
                raw_text = stripped

            raw: dict[str, Any] = json.loads(raw_text)
            parsed = _RemediationResponse(**raw)

            return Remediation(
                finding_title=finding.title,
                file_path=finding.file_path,
                diff=parsed.diff,
                explanation=parsed.explanation,
                confidence=parsed.confidence,
            )

        except anthropic.APIError as exc:
            logger.error(
                "API error generating fix for %s: %s", finding.title, exc
            )
            return None

        except json.JSONDecodeError as exc:
            logger.warning(
                "JSON parse error for fix %s: %s", finding.title, exc
            )
            return None

        except ValidationError as exc:
            logger.warning(
                "Validation error for fix %s: %s", finding.title, exc
            )
            return None
