"""Comparison Pydantic schemas for VibeCheck Phase 5 Rescan Verification."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.schemas.finding import Finding, FindingLocation
from backend.app.schemas.scan import ScanCoverage, ScanResponse


class FindingDisposition(str, Enum):
    """Status disposition of a finding after rescan comparison."""

    RESOLVED = "resolved"
    STILL_PRESENT = "still_present"
    NEW = "new"
    NOT_VERIFIABLE = "not_verifiable"


class ComparisonFindingItem(BaseModel):
    """Detailed comparison item representing a single evaluated finding."""

    finding_id: str = Field(
        ...,
        description="Identifier of the finding (current finding ID or baseline ID if resolved)",
    )
    disposition: FindingDisposition = Field(
        ...,
        description="Outcome of comparison: resolved, still_present, new, or not_verifiable",
    )
    rule_id: str = Field(
        ...,
        description="Security rule identifier",
    )
    category: str = Field(
        ...,
        description="Security category",
    )
    title: str = Field(
        ...,
        description="Summary title of the vulnerability",
    )
    severity_before: Optional[str] = Field(
        default=None,
        description="Baseline severity if finding existed in baseline scan",
    )
    severity_after: Optional[str] = Field(
        default=None,
        description="Current severity if finding exists in post-remediation scan",
    )
    location_before: Optional[FindingLocation] = Field(
        default=None,
        description="Baseline code location coordinates",
    )
    location_after: Optional[FindingLocation] = Field(
        default=None,
        description="Current code location coordinates",
    )
    snippet_before: Optional[str] = Field(
        default=None,
        description="Code snippet from baseline finding",
    )
    snippet_after: Optional[str] = Field(
        default=None,
        description="Code snippet from current finding",
    )
    evidence_before: Optional[str] = Field(
        default=None,
        description="Concrete evidence from baseline finding",
    )
    evidence_after: Optional[str] = Field(
        default=None,
        description="Concrete evidence from current finding",
    )
    match_rationale: Optional[str] = Field(
        default=None,
        description="Deterministic justification for how the finding was correlated",
    )
    unverifiable_reason: Optional[str] = Field(
        default=None,
        description="Structured explanation if disposition is not_verifiable",
    )
    baseline_id: Optional[str] = Field(
        default=None,
        description="Baseline finding ID if applicable",
    )
    current_id: Optional[str] = Field(
        default=None,
        description="Current finding ID if applicable",
    )


class ComparisonSummary(BaseModel):
    """Aggregated metrics and disposition counts for the rescan comparison."""

    baseline_total: int = Field(
        default=0,
        description="Total number of findings in the baseline scan",
    )
    current_total: int = Field(
        default=0,
        description="Total number of findings in the current rescan",
    )
    resolved_count: int = Field(
        default=0,
        description="Baseline findings conclusively verified as resolved",
    )
    still_present_count: int = Field(
        default=0,
        description="Baseline findings that remain present in the current rescan",
    )
    new_count: int = Field(
        default=0,
        description="New findings introduced in the current rescan",
    )
    not_verifiable_count: int = Field(
        default=0,
        description="Baseline findings that cannot be verified due to coverage gaps or scan failures",
    )
    is_scan_complete: bool = Field(
        default=True,
        description="Whether both scans executed completely without failure",
    )
    verification_limitations: List[str] = Field(
        default_factory=list,
        description="Honest disclosures of coverage limitations affecting verification",
    )


class ComparisonResult(BaseModel):
    """Complete structured comparison response payload."""

    comparison_id: str = Field(
        ...,
        description="Unique identifier for this comparison session",
    )
    baseline_scan_id: str = Field(
        ...,
        description="Identifier of the baseline scan",
    )
    current_scan_id: str = Field(
        ...,
        description="Identifier of the post-remediation rescan",
    )
    project: str = Field(
        ...,
        description="Project identifier",
    )
    status: str = Field(
        default="completed",
        description="Comparison status: completed, inconclusive, or failed",
    )
    summary: ComparisonSummary = Field(
        ...,
        description="Summary metrics and counts",
    )
    findings: List[ComparisonFindingItem] = Field(
        default_factory=list,
        description="Dispositions and detailed comparison for all evaluated findings",
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Scanner or comparison limitations",
    )


class CompareRequest(BaseModel):
    """Request model for initiating a scan comparison."""

    baseline_scan_id: Optional[str] = Field(
        default=None,
        description="Identifier of stored baseline scan",
    )
    current_scan_id: Optional[str] = Field(
        default=None,
        description="Identifier of stored rescan",
    )
    baseline_scan: Optional[ScanResponse] = Field(
        default=None,
        description="Direct baseline scan response object if not referencing stored ID",
    )
    current_scan: Optional[ScanResponse] = Field(
        default=None,
        description="Direct rescan response object if not referencing stored ID",
    )
