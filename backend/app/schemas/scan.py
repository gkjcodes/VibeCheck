"""Scan response Pydantic model for VibeShield."""

from typing import List, Optional
from pydantic import BaseModel, Field

from backend.app.schemas.finding import Finding


class ScanCoverage(BaseModel):
    """Coverage metrics indicating what was inspected during the scan."""

    files_scanned: int = Field(
        default=0,
        description="Number of files analyzed during the scan",
    )
    total_lines: Optional[int] = Field(
        default=None,
        description="Approximate number of code lines evaluated",
    )
    rules_evaluated: Optional[int] = Field(
        default=None,
        description="Number of security rules applied during analysis",
    )
    skipped_files: List[str] = Field(
        default_factory=list,
        description="List of files skipped (e.g., binary, minified, or unsupported types)",
    )

    model_config = {"extra": "allow"}


class ScanResponse(BaseModel):
    """Consolidated scan response payload returned by VibeShield."""

    scan_id: str = Field(
        ...,
        description="Unique identifier for the scan session",
    )
    status: str = Field(
        ...,
        description="Scan execution status (e.g., 'completed', 'in_progress', 'failed', 'pending')",
    )
    project: str = Field(
        ...,
        description="Name or identifier of the submitted project",
    )
    coverage: ScanCoverage = Field(
        default_factory=ScanCoverage,
        description="Coverage metadata describing what was evaluated",
    )
    findings: List[Finding] = Field(
        default_factory=list,
        description="Security findings discovered during the scan",
    )
    repair_prompt: Optional[str] = Field(
        default=None,
        description="Consolidated prompt for AI coding assistants to remediate the identified findings",
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Known scanner limitations or scope boundaries for this scan",
    )
