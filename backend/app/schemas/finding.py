"""Security finding Pydantic model for VibeCheck."""

from typing import List, Optional
from pydantic import BaseModel, Field


class FindingLocation(BaseModel):
    """File and line coordinates identifying where a vulnerability occurs."""

    file_path: str = Field(
        ...,
        description="Relative path of the source file where the issue was located",
    )
    line_start: Optional[int] = Field(
        default=None,
        description="Starting line number of the finding (1-indexed)",
    )
    line_end: Optional[int] = Field(
        default=None,
        description="Ending line number of the finding (1-indexed)",
    )
    snippet: Optional[str] = Field(
        default=None,
        description="Source code snippet illustrating the context",
    )


class Finding(BaseModel):
    """Individual security finding identified during analysis."""

    id: str = Field(
        ...,
        description="Unique identifier for the finding instance",
    )
    rule_id: str = Field(
        ...,
        description="Security rule identifier (e.g., 'SEC-AUTH-001', 'VIBE-CORS-WILDCARD')",
    )
    category: str = Field(
        ...,
        description="Security category (e.g., 'hardcoded-secret', 'injection', 'insecure-config')",
    )
    title: str = Field(
        ...,
        description="Concise, human-readable summary of the vulnerability",
    )
    severity: str = Field(
        ...,
        description="Severity level (e.g., 'critical', 'high', 'medium', 'low', 'info')",
    )
    confidence: str = Field(
        ...,
        description="Detection confidence level (e.g., 'high', 'medium', 'low')",
    )
    status: str = Field(
        default="open",
        description="Finding status (e.g., 'open', 'resolved', 'unresolved', 'suppressed')",
    )
    location: FindingLocation = Field(
        ...,
        description="Code location where the vulnerability was detected",
    )
    evidence: str = Field(
        ...,
        description="Concrete evidence from source code, AST, or config demonstrating the vulnerability",
    )
    impact: str = Field(
        ...,
        description="Security impact and potential exploit scenarios",
    )
    recommendation: str = Field(
        ...,
        description="Specific instructions for fixing the vulnerability",
    )
    verification_steps: List[str] = Field(
        default_factory=list,
        description="Actionable verification steps to confirm the vulnerability is resolved",
    )
