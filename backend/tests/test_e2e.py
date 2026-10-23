"""Comprehensive end-to-end (E2E) integration tests for VibeCheck Phase 6.

Validates the full user journey:
1. Initial project ZIP upload & baseline scan execution.
2. Retrieval of evidence-backed findings and remediation prompt.
3. Human review of remediation proposals & strict rejection of unapproved changes.
4. Application of approved changes strictly to an isolated sandbox copy.
5. Corrected archive rescan & verification diffing.
6. Honest resolution enforcement (unverifiable findings when files are skipped or scans fail).
7. Error conditions: malformed archives, path traversal, unknown scan IDs.
8. API response schema integrity and frontend dashboard connectivity.
"""

import io
from pathlib import Path
import tempfile
import zipfile
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.comparison import ComparisonResult, FindingDisposition
from backend.app.schemas.finding import Finding
from backend.app.schemas.remediation import (
    RemediationApplyRequest,
    RemediationApplyResponse,
    RemediationReviewResponse,
)
from backend.app.schemas.scan import ScanResponse

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def build_zip_from_dir(directory_path: Path) -> bytes:
    """Helper to build an in-memory zip archive from a filesystem directory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in directory_path.rglob("*"):
            if p.is_file():
                rel_path = p.relative_to(directory_path).as_posix()
                zf.write(p, arcname=rel_path)
    return buf.getvalue()


def build_custom_zip(files_dict: dict) -> bytes:
    """Helper to build an in-memory zip archive from a filename -> content dict."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files_dict.items():
            zf.writestr(fname, content)
    return buf.getvalue()


@pytest.fixture
def client():
    return TestClient(app)


# --- 1. Core End-to-End User Journey Tests ---

def test_e2e_full_journey_vulnerable_to_corrected(client):
    """Test full user journey: baseline intake -> report -> review -> rescan -> verification."""
    vuln_dir = REPO_ROOT / "samples" / "vulnerable"
    corr_dir = REPO_ROOT / "samples" / "corrected"
    assert vuln_dir.exists(), "vulnerable samples directory missing"
    assert corr_dir.exists(), "corrected samples directory missing"

    # Step 1: Submit vulnerable project archive
    vuln_zip = build_zip_from_dir(vuln_dir)
    res_base = client.post(
        "/api/v1/scans",
        files={"file": ("vulnerable_app.zip", vuln_zip, "application/zip")},
    )
    assert res_base.status_code in (200, 201), res_base.text
    base_data = res_base.json()
    assert base_data["status"] == "completed"
    scan_id = base_data["scan_id"]
    assert scan_id.startswith("scan_")
    findings = base_data["findings"]
    assert len(findings) > 0
    assert base_data["repair_prompt"] is not None

    # Step 2: Retrieve scan report by ID
    res_get = client.get(f"/api/v1/scans/{scan_id}")
    assert res_get.status_code == 200
    retrieved = res_get.json()
    assert retrieved["scan_id"] == scan_id
    assert len(retrieved["findings"]) == len(findings)

    # Step 3: Human review of remediation proposals
    res_prop = client.get(f"/api/v1/scans/{scan_id}/remediation/proposals")
    assert res_prop.status_code == 200
    prop_data = res_prop.json()
    assert prop_data["requires_approval"] is True
    assert prop_data["total_proposals"] == len(findings)
    first_prop_id = prop_data["proposals"][0]["proposal_id"]

    # Step 4: Human approval enforcement (unapproved changes strictly rejected)
    res_unapproved = client.post(
        f"/api/v1/scans/{scan_id}/remediation/apply",
        json={"approved_proposal_ids": [first_prop_id], "confirm_approval": False},
    )
    assert res_unapproved.status_code == 400
    assert "Explicit human approval is required" in res_unapproved.json()["detail"]

    # Step 5: Approved changes applied to an isolated sandbox copy (never original repo)
    res_approved = client.post(
        f"/api/v1/scans/{scan_id}/remediation/apply",
        json={"approved_proposal_ids": [first_prop_id], "confirm_approval": True},
    )
    assert res_approved.status_code == 200
    applied_data = res_approved.json()
    assert applied_data["applied_count"] == 1
    assert "isolated_workspace" in applied_data
    assert "Original source directory and git repository remain untouched" in applied_data["audit_note"]

    # Step 6: Submit corrected archive for rescan & comparison
    corr_zip = build_zip_from_dir(corr_dir)
    res_rescan = client.post(
        f"/api/v1/scans/{scan_id}/rescan",
        files={"file": ("corrected_app.zip", corr_zip, "application/zip")},
    )
    assert res_rescan.status_code == 200
    comp_data = res_rescan.json()
    assert comp_data["baseline_scan_id"] == scan_id
    summary = comp_data["summary"]
    assert summary["baseline_total"] == len(findings)
    assert summary["resolved_count"] > 0
    assert summary["resolved_count"] <= summary["baseline_total"]

    # Verify individual resolved items
    resolved_items = [f for f in comp_data["findings"] if f["disposition"] == "resolved"]
    assert len(resolved_items) == summary["resolved_count"]


def test_e2e_remediation_proposal_empty_selection_rejected(client):
    """Verify that applying remediation with empty approved list is rejected."""
    # Create baseline scan
    app_code = {"app.js": "const secret = 'sk_live_12345678901234567890';"}
    zip_bytes = build_custom_zip(app_code)
    res = client.post(
        "/api/v1/scans",
        files={"file": ("test.zip", zip_bytes, "application/zip")},
    )
    assert res.status_code in (200, 201)
    scan_id = res.json()["scan_id"]

    # Attempt to apply with empty proposal list
    res_empty = client.post(
        f"/api/v1/scans/{scan_id}/remediation/apply",
        json={"approved_proposal_ids": [], "confirm_approval": True},
    )
    assert res_empty.status_code == 400
    assert "No approved proposals specified" in res_empty.json()["detail"]


# --- 2. Error and Adversarial Boundary Tests ---

def test_e2e_invalid_upload_types_rejected(client):
    """Verify that non-ZIP files are rejected with HTTP 415."""
    res = client.post(
        "/api/v1/scans",
        files={"file": ("script.py", b"print('hello')", "text/x-python")},
    )
    assert res.status_code == 415


def test_e2e_path_traversal_zip_rejected(client):
    """Verify that archives with Zip Slip traversal paths are rejected."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0:")
    traversal_zip = buf.getvalue()

    res = client.post(
        "/api/v1/scans",
        files={"file": ("exploit.zip", traversal_zip, "application/zip")},
    )
    assert res.status_code in (400, 422)


def test_e2e_unknown_scan_id_404(client):
    """Verify that querying or rescanning against an unknown scan ID returns 404."""
    res_get = client.get("/api/v1/scans/non_existent_scan_id_999")
    assert res_get.status_code == 404

    res_rescan = client.post(
        "/api/v1/scans/non_existent_scan_id_999/rescan",
        files={"file": ("corr.zip", build_custom_zip({"index.html": "<h1>clean</h1>"}), "application/zip")},
    )
    assert res_rescan.status_code == 404

    res_props = client.get("/api/v1/scans/non_existent_scan_id_999/remediation/proposals")
    assert res_props.status_code == 404

    res_apply = client.post(
        "/api/v1/scans/non_existent_scan_id_999/remediation/apply",
        json={"approved_proposal_ids": ["prop-1"], "confirm_approval": True},
    )
    assert res_apply.status_code == 404


def test_e2e_malformed_scan_id_rejected(client):
    """Verify that directory traversal in scan ID is rejected with 400."""
    res = client.get("/api/v1/scans/..%2F..%2Fetc%2Fpasswd")
    assert res.status_code in (400, 404)


# --- 3. Honest Resolution & Verification Invariants ---

def test_e2e_skipped_file_prevents_false_resolution(client):
    """Verify that a baseline finding in a file skipped during rescan produces NOT_VERIFIABLE."""
    from backend.comparison import default_scan_store
    from backend.app.schemas.finding import Finding, FindingLocation
    from backend.app.schemas.scan import ScanCoverage

    # Baseline scan with finding in big_file.py
    f = Finding(
        id="f-big",
        rule_id="VIBE-SEC-KEY",
        category="hardcoded-secret",
        title="Exposed API Key",
        severity="critical",
        confidence="high",
        status="open",
        location=FindingLocation(file_path="big_file.py", line_start=5, line_end=5, snippet="KEY"),
        evidence="KEY",
        impact="Compromise",
        recommendation="Remove",
        verification_steps=["Check"],
    )
    base_scan = ScanResponse(
        scan_id="scan-base-e2e-skip",
        status="completed",
        project="skip-test",
        coverage=ScanCoverage(files_scanned=2, skipped_files=[], rules_evaluated=5),
        findings=[f],
        repair_prompt="",
        limitations=[],
    )
    default_scan_store.save_scan(base_scan)

    # Current scan where big_file.py was skipped
    curr_scan = ScanResponse(
        scan_id="scan-curr-e2e-skip",
        status="completed",
        project="skip-test",
        coverage=ScanCoverage(files_scanned=1, skipped_files=["big_file.py"], rules_evaluated=5),
        findings=[],  # 0 findings reported because file was skipped
        repair_prompt="",
        limitations=[],
    )
    default_scan_store.save_scan(curr_scan)

    # Compare via API
    res = client.post(
        "/api/v1/scans/compare",
        json={"baseline_scan_id": "scan-base-e2e-skip", "current_scan_id": "scan-curr-e2e-skip"},
    )
    assert res.status_code == 200
    comp = res.json()
    assert comp["summary"]["resolved_count"] == 0
    assert comp["summary"]["not_verifiable_count"] == 1
    item = comp["findings"][0]
    assert item["disposition"] == "not_verifiable"
    assert "was skipped during rescan" in item["unverifiable_reason"]


def test_e2e_failed_rescan_prevents_false_resolution(client):
    """Verify that a failed rescan cannot falsely claim all vulnerabilities were resolved."""
    from backend.comparison import default_scan_store
    from backend.app.schemas.finding import Finding, FindingLocation
    from backend.app.schemas.scan import ScanCoverage

    f = Finding(
        id="f-crit",
        rule_id="VIBE-INJ-SQL",
        category="injection",
        title="SQL Injection",
        severity="critical",
        confidence="high",
        status="open",
        location=FindingLocation(file_path="db.py", line_start=10, line_end=12, snippet="query"),
        evidence="query",
        impact="Database leak",
        recommendation="Parameterize",
        verification_steps=["Test"],
    )
    base_scan = ScanResponse(
        scan_id="scan-base-fail-guard",
        status="completed",
        project="fail-test",
        coverage=ScanCoverage(files_scanned=1, skipped_files=[], rules_evaluated=5),
        findings=[f],
        repair_prompt="",
        limitations=[],
    )
    curr_scan = ScanResponse(
        scan_id="scan-curr-fail-guard",
        status="failed",
        project="fail-test",
        coverage=ScanCoverage(files_scanned=0, skipped_files=[], rules_evaluated=5),
        findings=[],
        repair_prompt="",
        limitations=["Scanner crashed"],
    )
    default_scan_store.save_scan(base_scan)
    default_scan_store.save_scan(curr_scan)

    res = client.post(
        "/api/v1/scans/compare",
        json={"baseline_scan_id": "scan-base-fail-guard", "current_scan_id": "scan-curr-fail-guard"},
    )
    assert res.status_code == 200
    comp = res.json()
    assert comp["summary"]["resolved_count"] == 0
    assert comp["summary"]["not_verifiable_count"] == 1
    assert comp["findings"][0]["disposition"] == "not_verifiable"


# --- 4. API Schema & Frontend Connectivity Tests ---

def test_e2e_dashboard_and_phases_api_connected(client):
    """Verify that frontend dashboard and live phase status endpoint respond correctly."""
    res_dash = client.get("/")
    assert res_dash.status_code == 200
    assert "VibeCheck" in res_dash.text
    assert "Intake, Rescan & Diff Verification Engine" in res_dash.text

    res_phases = client.get("/api/v1/phases")
    assert res_phases.status_code == 200
    phases = res_phases.json()
    assert len(phases) == 7
    # Verify phases 1 through 5 pass
    for i in range(1, 6):
        p = next(x for x in phases if x["phase"] == i)
        assert p["status"] == "PASS"
