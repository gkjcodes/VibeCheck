"""Pydantic schemas for remediation review, proposals, and approved changes."""

from typing import List, Optional
from pydantic import BaseModel, Field


class RemediationProposal(BaseModel):
    """Proposal for remediating an identified security vulnerability."""

    proposal_id: str = Field(..., description="Unique proposal identifier.")
    finding_id: str = Field(..., description="Correlated finding identifier.")
    rule_id: str = Field(..., description="Security rule identifier.")
    file_path: str = Field(..., description="Target file path (relative POSIX).")
    title: str = Field(..., description="Finding title.")
    severity: str = Field(..., description="Severity level.")
    proposed_action: str = Field(..., description="Proposed safe remediation instructions.")
    status: str = Field("pending_review", description="Status: pending_review, approved, or rejected.")
    requires_human_approval: bool = Field(True, description="Strict requirement for explicit human approval.")


class RemediationReviewResponse(BaseModel):
    """Collection of remediation proposals for human review."""

    scan_id: str = Field(..., description="Scan identifier.")
    project: str = Field(..., description="Project name.")
    proposals: List[RemediationProposal] = Field(default_factory=list, description="Remediation proposals.")
    total_proposals: int = Field(..., description="Total proposals count.")
    requires_approval: bool = Field(True, description="Human approval flag.")
    advisory_notice: str = Field(
        "Remediation proposals are advisory-only. Source code cannot be modified without explicit human approval.",
        description="Safety notice.",
    )


class RemediationApplyRequest(BaseModel):
    """Request to apply approved remediation proposals."""

    approved_proposal_ids: List[str] = Field(
        default_factory=list,
        description="Explicit list of approved proposal IDs.",
    )
    confirm_approval: bool = Field(
        False,
        description="Explicit confirmation flag for human approval.",
    )


class RemediationApplyResponse(BaseModel):
    """Result of applying approved remediations to an isolated sandbox."""

    scan_id: str = Field(..., description="Scan identifier.")
    applied_count: int = Field(..., description="Count of successfully applied proposals.")
    rejected_count: int = Field(..., description="Count of rejected/unapproved proposals.")
    status: str = Field(..., description="Execution status.")
    isolated_workspace: str = Field(
        ...,
        description="Path to isolated sandbox copy where changes were applied.",
    )
    audit_note: str = Field(
        "Changes applied strictly to an isolated working copy. Original source directory and git repository remain untouched.",
        description="Audit verification notice.",
    )
