"""Shared Pydantic data models for LogicGate."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnType(str, Enum):
    IDOR = "IDOR"
    BFLA = "BFLA"
    STATE_MANIPULATION = "STATE_MANIPULATION"
    MULTI_TENANT_LEAK = "MULTI_TENANT_LEAK"
    IMPLICIT_PERMISSION = "IMPLICIT_PERMISSION"


class RouteInfo(BaseModel):
    """An Express.js route definition discovered by the parser."""

    file_path: str
    http_method: str
    route_pattern: str
    handler_start_line: int
    handler_end_line: int
    handler_source: str
    middleware: list[str] = Field(default_factory=list)


class ImportInfo(BaseModel):
    """A require() or import statement."""

    name: str
    path: str
    file_path: str
    line: int


class FunctionDef(BaseModel):
    """A named function definition."""

    name: str
    file_path: str
    start_line: int
    end_line: int
    source: str


class FunctionCall(BaseModel):
    """A function call site."""

    name: str
    file_path: str
    line: int
    object_name: Optional[str] = None


class FunctionNode(BaseModel):
    """A function node in the dependency graph."""

    name: str
    file_path: str
    start_line: int
    end_line: int
    source: str
    calls: list[str] = Field(default_factory=list)
    called_by: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A single vulnerability finding from the LLM."""

    vuln_type: VulnType
    severity: Severity
    title: str
    description: str
    affected_route: str
    file_path: str
    start_line: int
    end_line: int
    recommendation: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str


class AuditResult(BaseModel):
    """Complete LLM response for a single route audit."""

    route: str
    findings: list[Finding]
    reasoning: str


class Remediation(BaseModel):
    """A code fix generated for a specific finding."""

    finding_title: str
    file_path: str
    diff: str
    explanation: str
    confidence: float = Field(ge=0.0, le=1.0)
