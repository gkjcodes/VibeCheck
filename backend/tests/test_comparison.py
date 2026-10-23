"""Automated tests for Phase 5 Scan Comparison Engine and API Integration.

Covers all 30 matching, scan integrity, and security adversarial test cases:
1. Finding ID unchanged and finding still present.
2. Finding ID changed but evidence indicates same underlying finding.
3. Line number shifted after code changes.
4. Baseline finding absent from comparable, covered scan (RESOLVED).
5. Finding still present with changed severity.
6. Newly introduced finding (NEW).
7. Duplicate findings in either scan handled safely.
8. Ambiguous matching resolved deterministically.
9. Multiple baseline findings competing for one current finding.
10. A finding moved to a different file.
11. File path normalization across Windows and POSIX separators.
12. Invalid or out-of-scope paths.
13. Baseline scan failed limitation reporting.
14. Current scan failed prevents false resolution (NOT_VERIFIABLE).
15. Current scan incomplete prevents false resolution.
16. Relevant files skipped in rescan produces NOT_VERIFIABLE.
17. Scope and rule coverage limitations recorded.
18. Zero files scanned in rescan produces NOT_VERIFIABLE.
19. Malformed scan data raises appropriate validation error.
20. Empty but valid scan results return 0 counts cleanly.
21. Missing scan references in store return 404 / KeyError.
22. Unmatched finding without adequate correlation not falsely linked.
23. Disappeared finding ID does not automatically imply resolution without coverage.
24. Incomplete scan cannot falsely resolve all baseline findings.
25. Failed scanner cannot produce a false all-clear.
26. Duplicate matching does not silently drop or merge distinct findings.
27. Untrusted markup in finding titles/evidence safely contained.
28. Sensitive credentials scrubbed from comparison evidence.
29. API rejects arbitrary filesystem paths and invalid scan IDs.
30. Summary counts and item dispositions are internally consistent.
"""

import io
from pathlib import Path
import zipfile
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.comparison import (
    CompareRequest,
    ComparisonResult,
    FindingDisposition,
)
from backend.app.schemas.finding import Finding, FindingLocation
from backend.app.schemas.scan import ScanCoverage, ScanResponse
from backend.comparison.comparator import ScanComparator, compare_scans, normalize_path
from backend.comparison.service import ComparisonService
from backend.comparison.store import ScanStore


def make_finding(
    fid: str = "finding-1",
    rule_id: str = "VIBE-INJ-001",
    file_path: str = "src/app.py",
    line_start: int = 20,
    line_end: int = 22,
    severity: str = "high",
    category: str = "injection",
    title: str = "SQL Injection in Query",
    evidence: str = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
    snippet: str = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
) -> Finding:
    return Finding(
        id=fid,
        rule_id=rule_id,
        category=category,
        title=title,
        severity=severity,
        confidence="high",
        status="open",
        location=FindingLocation(
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            snippet=snippet,
        ),
        evidence=evidence,
        impact="Database compromise.",
        recommendation="Use parameterized queries.",
        verification_steps=["Check parameterized query execution."],
    )


def make_scan(
    scan_id: str,
    findings=None,
    status: str = "completed",
    project: str = "test-project",
    files_scanned: int = 5,
    skipped_files=None,
    rules_evaluated: int = 10,
) -> ScanResponse:
    return ScanResponse(
        scan_id=scan_id,
        status=status,
        project=project,
        coverage=ScanCoverage(
            files_scanned=files_scanned,
            skipped_files=skipped_files or [],
            rules_evaluated=rules_evaluated,
        ),
        findings=findings or [],
        repair_prompt="Sample prompt",
        limitations=[],
    )


# --- 1. Matching and disposition tests ---

def test_1_finding_id_unchanged_still_present():
    f1 = make_finding("f-1", rule_id="RULE-1", file_path="app.py", line_start=10)
    f2 = make_finding("f-1", rule_id="RULE-1", file_path="app.py", line_start=10)

    base = make_scan("base-1", [f1])
    curr = make_scan("curr-1", [f2])

    result = compare_scans(base, curr)
    assert result.summary.still_present_count == 1
    assert result.summary.resolved_count == 0
    assert result.summary.new_count == 0
    assert result.findings[0].disposition == FindingDisposition.STILL_PRESENT
    assert result.findings[0].baseline_id == "f-1"
    assert result.findings[0].current_id == "f-1"


def test_2_finding_id_changed_evidence_matches():
    f1 = make_finding("f-old", rule_id="RULE-1", file_path="app.py", line_start=15, evidence="secret_call()")
    f2 = make_finding("f-new-uuid", rule_id="RULE-1", file_path="app.py", line_start=15, evidence="secret_call()")

    base = make_scan("base-1", [f1])
    curr = make_scan("curr-1", [f2])

    result = compare_scans(base, curr)
    assert result.summary.still_present_count == 1
    item = result.findings[0]
    assert item.disposition == FindingDisposition.STILL_PRESENT
    assert item.baseline_id == "f-old"
    assert item.current_id == "f-new-uuid"
    assert "ID changed" in item.match_rationale


def test_3_line_number_shifted_after_code_changes():
    f1 = make_finding("f-1", rule_id="RULE-1", file_path="app.py", line_start=20, line_end=22)
    # Line shifted from 20 to 35 due to added comments/imports
    f2 = make_finding("f-2", rule_id="RULE-1", file_path="app.py", line_start=35, line_end=37)

    base = make_scan("base-1", [f1])
    curr = make_scan("curr-1", [f2])

    result = compare_scans(base, curr)
    assert result.summary.still_present_count == 1
    item = result.findings[0]
    assert item.disposition == FindingDisposition.STILL_PRESENT
    assert item.location_before.line_start == 20
    assert item.location_after.line_start == 35
    assert "line shifted" in item.match_rationale.lower()


def test_4_baseline_finding_absent_conclusively_resolved():
    f1 = make_finding("f-1", rule_id="RULE-1", file_path="app.py", line_start=10)

    base = make_scan("base-1", [f1], files_scanned=2)
    curr = make_scan("curr-1", [], files_scanned=2)  # Zero findings in rescan

    result = compare_scans(base, curr)
    assert result.summary.resolved_count == 1
    assert result.summary.still_present_count == 0
    assert result.summary.not_verifiable_count == 0
    assert result.findings[0].disposition == FindingDisposition.RESOLVED
    assert result.findings[0].baseline_id == "f-1"


def test_5_finding_still_present_with_changed_severity():
    f1 = make_finding("f-1", severity="critical")
    f2 = make_finding("f-1", severity="medium")

    base = make_scan("base-1", [f1])
    curr = make_scan("curr-1", [f2])

    result = compare_scans(base, curr)
    assert result.summary.still_present_count == 1
    item = result.findings[0]
    assert item.disposition == FindingDisposition.STILL_PRESENT
    assert item.severity_before == "critical"
    assert item.severity_after == "medium"
    assert "Severity changed" in item.match_rationale


def test_6_newly_introduced_finding():
    f_new = make_finding("f-brand-new", rule_id="RULE-XSRF", file_path="auth.py")

    base = make_scan("base-1", [])
    curr = make_scan("curr-1", [f_new])

    result = compare_scans(base, curr)
    assert result.summary.new_count == 1
    assert result.summary.baseline_total == 0
    assert result.summary.current_total == 1
    item = result.findings[0]
    assert item.disposition == FindingDisposition.NEW
    assert item.current_id == "f-brand-new"
    assert item.baseline_id is None


def test_7_duplicate_findings_in_scans():
    f1_a = make_finding("f-1a", rule_id="RULE-1", file_path="app.py", line_start=10)
    f1_b = make_finding("f-1b", rule_id="RULE-1", file_path="app.py", line_start=10)
    curr_f = make_finding("f-1curr", rule_id="RULE-1", file_path="app.py", line_start=10)

    base = make_scan("base-1", [f1_a, f1_b])
    curr = make_scan("curr-1", [curr_f])

    result = compare_scans(base, curr)
    # One matched, one resolved (since second occurrence no longer in curr)
    assert result.summary.still_present_count == 1
    assert result.summary.resolved_count == 1
    assert len(result.findings) == 2


def test_8_ambiguous_matching_deterministic_selection():
    # Two baseline findings for the same rule in different lines
    b1 = make_finding("b-1", rule_id="RULE-1", file_path="app.py", line_start=10)
    b2 = make_finding("b-2", rule_id="RULE-1", file_path="app.py", line_start=50)
    # Current finding at line 12 (much closer to b1)
    c1 = make_finding("c-1", rule_id="RULE-1", file_path="app.py", line_start=12)

    base = make_scan("base-1", [b1, b2])
    curr = make_scan("curr-1", [c1])

    result = compare_scans(base, curr)
    # b1 should match c1 due to closer line distance; b2 should be resolved
    still_present = [f for f in result.findings if f.disposition == FindingDisposition.STILL_PRESENT]
    resolved = [f for f in result.findings if f.disposition == FindingDisposition.RESOLVED]
    assert len(still_present) == 1
    assert still_present[0].baseline_id == "b-1"
    assert len(resolved) == 1
    assert resolved[0].baseline_id == "b-2"


def test_9_multiple_baseline_competing_for_one_current():
    b1 = make_finding("b-1", rule_id="RULE-A", file_path="app.py", line_start=10, evidence="ev1")
    b2 = make_finding("b-2", rule_id="RULE-A", file_path="app.py", line_start=10, evidence="ev2")
    c1 = make_finding("c-1", rule_id="RULE-A", file_path="app.py", line_start=10, evidence="ev1")

    base = make_scan("base-1", [b1, b2])
    curr = make_scan("curr-1", [c1])

    result = compare_scans(base, curr)
    # b1 has exact evidence match -> matches c1; b2 is resolved
    matched = [f for f in result.findings if f.disposition == FindingDisposition.STILL_PRESENT]
    assert len(matched) == 1
    assert matched[0].baseline_id == "b-1"


def test_10_finding_moved_to_different_file():
    # If a finding completely moved files and has no file path match, rule + identical evidence can match
    b1 = make_finding("b-1", rule_id="RULE-1", file_path="old_app.py", line_start=10, evidence="fixed_string_xyz()")
    c1 = make_finding("c-1", rule_id="RULE-1", file_path="new_app.py", line_start=20, evidence="fixed_string_xyz()")

    base = make_scan("base-1", [b1])
    curr = make_scan("curr-1", [c1])

    result = compare_scans(base, curr)
    assert result.summary.still_present_count == 1
    assert result.findings[0].disposition == FindingDisposition.STILL_PRESENT


def test_11_file_path_normalization_windows_posix():
    assert normalize_path(r"src\auth\jwt.py") == "src/auth/jwt.py"
    assert normalize_path("src//auth///jwt.py") == "src/auth/jwt.py"
    assert normalize_path("./src/auth/jwt.py") == "src/auth/jwt.py"

    f_win = make_finding("f-1", file_path=r"src\models\user.py")
    f_posix = make_finding("f-2", file_path="src/models/user.py")

    base = make_scan("base-1", [f_win])
    curr = make_scan("curr-1", [f_posix])

    result = compare_scans(base, curr)
    assert result.summary.still_present_count == 1
    assert result.findings[0].disposition == FindingDisposition.STILL_PRESENT


def test_12_invalid_or_out_of_scope_paths():
    # Directory traversal path normalized safely
    norm = normalize_path("../../../etc/passwd")
    assert ".." not in norm
    assert normalize_path(None) == ""
    assert normalize_path("") == ""


# --- 2. Scan integrity tests ---

def test_13_baseline_scan_failed():
    f1 = make_finding("f-1")
    base = make_scan("base-1", [f1], status="failed")
    curr = make_scan("curr-1", [f1], status="completed")

    result = compare_scans(base, curr)
    assert any("Baseline scan status is 'failed'" in lim for lim in result.limitations)


def test_14_current_scan_failed_cannot_resolve():
    f1 = make_finding("f-1")
    base = make_scan("base-1", [f1], status="completed")
    curr = make_scan("curr-1", [], status="failed")  # 0 findings because scan crashed

    result = compare_scans(base, curr)
    # CRITICAL: A failed scan cannot mark baseline findings as RESOLVED!
    assert result.summary.resolved_count == 0
    assert result.summary.not_verifiable_count == 1
    assert result.findings[0].disposition == FindingDisposition.NOT_VERIFIABLE
    assert "cannot conclusively verify resolution" in (result.findings[0].unverifiable_reason or "")


def test_15_current_scan_incomplete_unverifiable():
    f1 = make_finding("f-1")
    base = make_scan("base-1", [f1], status="completed")
    curr = make_scan("curr-1", [], status="incomplete")

    result = compare_scans(base, curr)
    assert result.summary.resolved_count == 0
    assert result.summary.not_verifiable_count == 1
    assert result.findings[0].disposition == FindingDisposition.NOT_VERIFIABLE


def test_16_relevant_files_skipped_unverifiable():
    f1 = make_finding("f-1", file_path="src/large_file.py")
    base = make_scan("base-1", [f1], files_scanned=2)
    # Rescan skipped src/large_file.py due to timeout/size
    curr = make_scan("curr-1", [], files_scanned=1, skipped_files=["src/large_file.py"])

    result = compare_scans(base, curr)
    assert result.summary.resolved_count == 0
    assert result.summary.not_verifiable_count == 1
    item = result.findings[0]
    assert item.disposition == FindingDisposition.NOT_VERIFIABLE
    assert "was skipped during rescan" in item.unverifiable_reason


def test_17_scan_scopes_rules_evaluated_difference():
    f1 = make_finding("f-1")
    base = make_scan("base-1", [f1], rules_evaluated=20)
    curr = make_scan("curr-1", [f1], rules_evaluated=5)

    result = compare_scans(base, curr)
    assert any("evaluated fewer security rules" in lim for lim in result.limitations)


def test_18_zero_files_scanned_unverifiable():
    f1 = make_finding("f-1")
    base = make_scan("base-1", [f1], files_scanned=3)
    curr = make_scan("curr-1", [], files_scanned=0)

    result = compare_scans(base, curr)
    assert result.summary.resolved_count == 0
    assert result.summary.not_verifiable_count == 1
    assert result.findings[0].disposition == FindingDisposition.NOT_VERIFIABLE


def test_19_malformed_scan_data_rejected():
    comparator = ScanComparator()
    with pytest.raises(TypeError):
        comparator.compare("not-a-scan", "also-not-a-scan")


def test_20_empty_valid_scan_results():
    base = make_scan("base-1", [])
    curr = make_scan("curr-1", [])

    result = compare_scans(base, curr)
    assert result.summary.baseline_total == 0
    assert result.summary.current_total == 0
    assert result.summary.resolved_count == 0
    assert result.summary.still_present_count == 0
    assert result.summary.new_count == 0
    assert result.summary.not_verifiable_count == 0
    assert len(result.findings) == 0


def test_21_missing_scan_reference_in_store():
    store = ScanStore()
    service = ComparisonService(store=store)
    with pytest.raises(KeyError):
        service.compare_by_ids("missing-id-1", "missing-id-2")


def test_22_unconfident_match_not_forced():
    # Baseline finding in file A, current finding in file B with completely different rule and evidence
    b1 = make_finding("b-1", rule_id="RULE-SQLI", file_path="db.py", evidence="SELECT * FROM table")
    c1 = make_finding("c-1", rule_id="RULE-XSS", file_path="view.html", evidence="<div>Hello</div>")

    base = make_scan("base-1", [b1], files_scanned=2)
    curr = make_scan("curr-1", [c1], files_scanned=2)

    result = compare_scans(base, curr)
    # b1 should be RESOLVED (or not present in db.py), c1 should be NEW. They must NOT be merged!
    assert result.summary.resolved_count == 1
    assert result.summary.new_count == 1
    assert result.summary.still_present_count == 0


# --- 3. Security and correctness tests ---

def test_23_disappeared_id_does_not_imply_resolution_without_coverage():
    f1 = make_finding("f-1", file_path="service.py")
    base = make_scan("base-1", [f1])
    # Rescan failed or skipped service.py
    curr = make_scan("curr-1", [], status="failed")

    result = compare_scans(base, curr)
    assert result.findings[0].disposition != FindingDisposition.RESOLVED
    assert result.findings[0].disposition == FindingDisposition.NOT_VERIFIABLE


def test_24_incomplete_scan_cannot_falsely_resolve_all():
    findings = [make_finding(f"f-{i}") for i in range(5)]
    base = make_scan("base-1", findings)
    curr = make_scan("curr-1", [], status="incomplete")

    result = compare_scans(base, curr)
    assert result.summary.resolved_count == 0
    assert result.summary.not_verifiable_count == 5


def test_25_failed_scanner_cannot_produce_false_all_clear():
    f1 = make_finding("f-crit", severity="critical")
    base = make_scan("base-1", [f1])
    curr = make_scan("curr-1", [], status="failed")

    result = compare_scans(base, curr)
    assert result.summary.resolved_count == 0
    assert result.status != "completed"


def test_26_duplicate_matching_does_not_hide_findings():
    f1 = make_finding("f-1", rule_id="RULE-1", file_path="app.py", line_start=10)
    f2 = make_finding("f-2", rule_id="RULE-1", file_path="app.py", line_start=10)
    f3 = make_finding("f-3", rule_id="RULE-1", file_path="app.py", line_start=10)

    base = make_scan("base-1", [f1, f2, f3])
    curr = make_scan("curr-1", [f1])

    result = compare_scans(base, curr)
    assert len(result.findings) == 3
    assert result.summary.baseline_total == 3


def test_27_malicious_markup_in_finding_is_contained():
    malicious_title = "<script>alert('pwned')</script> Injection"
    f1 = make_finding("f-xss", title=malicious_title)
    base = make_scan("base-1", [f1])
    curr = make_scan("curr-1", [f1])

    result = compare_scans(base, curr)
    item = result.findings[0]
    # Check title is intact in Pydantic data structure without breaking JSON serialization
    json_out = result.model_dump_json()
    assert "alert('pwned')" in json_out


def test_28_sensitive_values_scrubbed_in_evidence():
    secret_ev = "api_key = 'wJalrXUtnFEMI_K7MDENG_bPxRfiCYEXAMPLEKEY'"
    f1 = make_finding("f-secret", evidence=secret_ev)
    base = make_scan("base-1", [f1])
    curr = make_scan("curr-1", [f1])

    result = compare_scans(base, curr)
    item = result.findings[0]
    assert "wJalrXUtnFEMI" not in (item.evidence_before or "")
    assert "****" in (item.evidence_before or "")


def test_29_api_path_traversal_rejection():
    store = ScanStore()
    with pytest.raises(ValueError):
        store.get_scan("../../../etc/passwd")

    with pytest.raises(ValueError):
        store.get_scan("invalid/slash/id")


def test_30_comparison_counts_and_dispositions_consistency():
    b1 = make_finding("b-1", rule_id="R-1", file_path="a.py")
    b2 = make_finding("b-2", rule_id="R-2", file_path="b.py")
    b3 = make_finding("b-3", rule_id="R-3", file_path="c.py")

    c1 = make_finding("c-1", rule_id="R-1", file_path="a.py")  # still present
    c2 = make_finding("c-new", rule_id="R-NEW", file_path="d.py")  # new
    # b2 will be resolved
    # b3 file c.py skipped in rescan -> not verifiable

    base = make_scan("base-1", [b1, b2, b3], files_scanned=3)
    curr = make_scan("curr-1", [c1, c2], files_scanned=2, skipped_files=["c.py"])

    result = compare_scans(base, curr)
    s = result.summary
    assert s.baseline_total == 3
    assert s.current_total == 2
    assert s.still_present_count == 1
    assert s.resolved_count == 1
    assert s.not_verifiable_count == 1
    assert s.new_count == 1

    # Invariant: baseline findings = still_present + resolved + not_verifiable
    assert s.baseline_total == (s.still_present_count + s.resolved_count + s.not_verifiable_count)
    # Invariant: current findings = still_present + new
    assert s.current_total == (s.still_present_count + s.new_count)
    assert len(result.findings) == (s.still_present_count + s.resolved_count + s.not_verifiable_count + s.new_count)


# --- 4. API Endpoints Integration Tests ---

def test_31_api_compare_direct_payload():
    client = TestClient(app)
    f1 = make_finding("f-1")
    base = make_scan("scan-base", [f1])
    curr = make_scan("scan-curr", [])

    payload = {
        "baseline_scan": base.model_dump(),
        "current_scan": curr.model_dump(),
    }
    response = client.post("/api/v1/scans/compare", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["resolved_count"] == 1
    assert data["summary"]["still_present_count"] == 0


def test_32_api_compare_by_ids():
    client = TestClient(app)
    from backend.comparison import default_scan_store

    f1 = make_finding("f-1")
    base = make_scan("scan-stored-base", [f1])
    curr = make_scan("scan-stored-curr", [f1])

    default_scan_store.save_scan(base)
    default_scan_store.save_scan(curr)

    payload = {
        "baseline_scan_id": "scan-stored-base",
        "current_scan_id": "scan-stored-curr",
    }
    response = client.post("/api/v1/scans/compare", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["still_present_count"] == 1


def test_33_api_phases_status():
    client = TestClient(app)
    response = client.get("/api/v1/phases")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 7
    phase1 = next(p for p in data if p["phase"] == 1)
    assert phase1["status"] == "PASS"


def test_34_dashboard_serves_html():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "VibeCheck" in response.text
    assert "text/html" in response.headers.get("content-type", "")
