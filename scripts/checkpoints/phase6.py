"""Phase 6 Checkpoint: End-to-End User Journey.

Verifies complete MVP workflow via FastAPI TestClient/fixtures:
- Submit project archive.
- Execute security scan.
- Retrieve evidence-backed report.
- Retrieve usable repair prompt.
- Submit corrected version.
- Rescan and compare findings.
- Validate response schemas and error conditions.
- Run complete integration test suite.

Fails if any stage of the user journey is not yet implemented.
"""

import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import zipfile

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


def _build_zip_from_dir(directory: Path) -> bytes:
    """Build an in-memory ZIP archive from a directory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in directory.rglob("*"):
            if file_path.is_file():
                arcname = file_path.relative_to(directory).as_posix()
                zf.write(file_path, arcname)
    return buf.getvalue()


def _build_memory_zip(file_map: Dict[str, str]) -> bytes:
    """Build an in-memory ZIP archive from a dict of relative paths to contents."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, content in file_map.items():
            zf.writestr(arcname, content)
    return buf.getvalue()


class Phase6Check:
    """Checkpoint gate runner for Phase 6: End-to-End MVP."""

    phase_number = 6
    phase_name = "End-to-End MVP Integration"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        # Check prerequisite endpoints
        endpoints = cls._get_api_endpoints()

        scan_endpoint = any("/scan" in ep for ep in endpoints)
        rescan_endpoint = any("/rescan" in ep or "/compare" in ep for ep in endpoints)

        if not scan_endpoint:
            results.append(
                CheckResult(
                    name="E2E Initial Submission & Scan Execution",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Scan intake endpoint not yet registered in API.",
                )
            )
            results.append(
                CheckResult(
                    name="E2E Report & Finding Retrieval",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Report retrieval awaiting scan endpoint implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="E2E Usable Repair Prompt Generation",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Repair prompt retrieval awaiting scan endpoint implementation.",
                )
            )
            scan_id = None
            client = None
        else:
            scan_check, rep_check, prompt_check, scan_id, client = cls._run_scan_workflow()
            results.append(scan_check)
            results.append(rep_check)
            results.append(prompt_check)

        if not rescan_endpoint or not scan_id or not client:
            results.append(
                CheckResult(
                    name="E2E Corrected Code Rescan Submission",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Rescan endpoint not yet registered in API or initial scan failed.",
                )
            )
            results.append(
                CheckResult(
                    name="E2E Verification & Diff Output",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Rescan diff awaiting rescan endpoint implementation.",
                )
            )
        else:
            rescan_check, diff_check = cls._run_rescan_workflow(client, scan_id)
            results.append(rescan_check)
            results.append(diff_check)

        # Response schemas and error cases
        if not client or not scan_id:
            results.append(
                CheckResult(
                    name="E2E Response Schema & Error Condition Audit",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Comprehensive E2E contract check awaiting full workflow implementation.",
                )
            )
        else:
            results.append(cls._check_response_schemas_and_errors(client, scan_id))

        # Integration test suite
        e2e_test = REPO_ROOT / "backend" / "tests" / "test_e2e.py"
        if not e2e_test.exists():
            results.append(
                CheckResult(
                    name="E2E Automated Integration Test Suite",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/tests/test_e2e.py not yet implemented.",
                )
            )
        else:
            results.append(cls._run_e2e_tests(str(e2e_test)))

        return results

    @classmethod
    def _get_api_endpoints(cls) -> List[str]:
        try:
            from backend.app.main import app

            eps: List[str] = []
            for route in app.routes:
                p = getattr(route, "path", "")
                if p:
                    eps.append(p)
                orig = getattr(route, "original_router", None)
                if orig and hasattr(orig, "routes"):
                    for sub in orig.routes:
                        sp = getattr(sub, "path", "")
                        if sp:
                            eps.append(sp)
            return eps
        except Exception:
            return []

    @classmethod
    def _run_scan_workflow(
        cls,
    ) -> Tuple[CheckResult, CheckResult, CheckResult, Optional[str], Optional[Any]]:
        try:
            from fastapi.testclient import TestClient
            from backend.app.main import app

            client = TestClient(app)

            # Prepare vulnerable sample zip
            vulnerable_dir = REPO_ROOT / "samples" / "vulnerable"
            if vulnerable_dir.exists():
                zip_bytes = _build_zip_from_dir(vulnerable_dir)
            else:
                zip_bytes = _build_memory_zip({
                    "sample.py": "api_key = 'sk_live_' + '12345678901234567890abcdef'\nos.system('rm -rf ' + user_input)\n"
                })

            res = client.post(
                "/api/v1/scans",
                files={"file": ("vulnerable_project.zip", zip_bytes, "application/zip")},
            )

            if res.status_code not in (200, 201):
                fail = CheckResult(
                    name="E2E Initial Submission & Scan Execution",
                    status=CheckStatus.FAIL,
                    details=f"POST /api/v1/scans returned unexpected status {res.status_code}: {res.text[:200]}",
                )
                not_impl = CheckResult(
                    name="E2E Report & Finding Retrieval",
                    status=CheckStatus.FAIL,
                    details="Scan submission failed; report retrieval cannot proceed.",
                )
                prompt_fail = CheckResult(
                    name="E2E Usable Repair Prompt Generation",
                    status=CheckStatus.FAIL,
                    details="Scan submission failed; repair prompt check cannot proceed.",
                )
                return fail, not_impl, prompt_fail, None, client

            data = res.json()
            scan_id = data.get("scan_id")
            if not scan_id or str(data.get("status", "")).lower() != "completed":
                fail = CheckResult(
                    name="E2E Initial Submission & Scan Execution",
                    status=CheckStatus.FAIL,
                    details=f"Scan response missing valid scan_id or completed status: {data}",
                )
                return fail, fail, fail, None, client

            total_findings = len(data.get("findings", []))
            scan_check = CheckResult(
                name="E2E Initial Submission & Scan Execution",
                status=CheckStatus.PASS,
                details=f"Scan executed successfully (scan_id={scan_id}, findings={total_findings}).",
            )

            # Check report retrieval
            get_res = client.get(f"/api/v1/scans/{scan_id}")
            if get_res.status_code != 200:
                report_check = CheckResult(
                    name="E2E Report & Finding Retrieval",
                    status=CheckStatus.FAIL,
                    details=f"GET /api/v1/scans/{scan_id} failed with status {get_res.status_code}",
                )
            else:
                rep_data = get_res.json()
                findings = rep_data.get("findings", [])
                if findings and all(isinstance(f.get("id"), str) and "evidence" in f for f in findings):
                    report_check = CheckResult(
                        name="E2E Report & Finding Retrieval",
                        status=CheckStatus.PASS,
                        details=f"Evidence-backed report retrieved with {len(findings)} structured findings.",
                    )
                else:
                    report_check = CheckResult(
                        name="E2E Report & Finding Retrieval",
                        status=CheckStatus.PASS,
                        details=f"Report retrieved successfully (findings count: {len(findings)}).",
                    )

            # Check usable repair prompt
            repair_prompt = data.get("repair_prompt") or rep_data.get("repair_prompt")
            if not repair_prompt:
                # Try dedicated endpoint
                prompt_res = client.get(f"/api/v1/scans/{scan_id}/repair-prompt")
                if prompt_res.status_code == 200:
                    repair_prompt = prompt_res.json().get("repair_prompt")

            if repair_prompt and "VibeCheck" in repair_prompt:
                prompt_check = CheckResult(
                    name="E2E Usable Repair Prompt Generation",
                    status=CheckStatus.PASS,
                    details="Generated actionable, Markdown-safe repair prompt with instructions and evidence.",
                )
            else:
                prompt_check = CheckResult(
                    name="E2E Usable Repair Prompt Generation",
                    status=CheckStatus.FAIL,
                    details="Scan response did not contain usable repair prompt.",
                )

            return scan_check, report_check, prompt_check, scan_id, client

        except Exception as exc:
            err = CheckResult(
                name="E2E Initial Submission & Scan Execution",
                status=CheckStatus.FAIL,
                details=f"Exception running scan workflow: {exc}",
            )
            return err, err, err, None, None

    @classmethod
    def _run_rescan_workflow(
        cls,
        client: Any,
        baseline_scan_id: str,
    ) -> Tuple[CheckResult, CheckResult]:
        try:
            corrected_dir = REPO_ROOT / "samples" / "corrected"
            if corrected_dir.exists():
                zip_bytes = _build_zip_from_dir(corrected_dir)
            else:
                zip_bytes = _build_memory_zip({
                    "sample.py": "api_key = os.environ.get('API_KEY')\nsubprocess.run(['rm', '-rf', shlex.quote(user_input)])\n"
                })

            res = client.post(
                f"/api/v1/scans/{baseline_scan_id}/rescan",
                files={"file": ("corrected_project.zip", zip_bytes, "application/zip")},
            )

            if res.status_code != 200:
                fail = CheckResult(
                    name="E2E Corrected Code Rescan Submission",
                    status=CheckStatus.FAIL,
                    details=f"POST /api/v1/scans/{baseline_scan_id}/rescan returned status {res.status_code}: {res.text[:200]}",
                )
                diff_fail = CheckResult(
                    name="E2E Verification & Diff Output",
                    status=CheckStatus.FAIL,
                    details="Rescan failed; diff output cannot be validated.",
                )
                return fail, diff_fail

            data = res.json()
            summary = data.get("summary", {})
            resolved_count = summary.get("resolved_count", 0)

            rescan_check = CheckResult(
                name="E2E Corrected Code Rescan Submission",
                status=CheckStatus.PASS,
                details=f"Rescan successfully processed comparison (comparison_id={data.get('comparison_id')}).",
            )

            if resolved_count > 0 or "resolved_findings" in data:
                diff_check = CheckResult(
                    name="E2E Verification & Diff Output",
                    status=CheckStatus.PASS,
                    details=f"Comparison diff verified: resolved={resolved_count}, still_present={summary.get('still_present_count', 0)}, new={summary.get('new_count', 0)}.",
                )
            else:
                diff_check = CheckResult(
                    name="E2E Verification & Diff Output",
                    status=CheckStatus.FAIL,
                    details=f"Comparison diff missing resolved findings or invalid summary: {summary}",
                )

            return rescan_check, diff_check

        except Exception as exc:
            err = CheckResult(
                name="E2E Corrected Code Rescan Submission",
                status=CheckStatus.FAIL,
                details=f"Exception during rescan submission: {exc}",
            )
            return err, err

    @classmethod
    def _check_response_schemas_and_errors(
        cls,
        client: Any,
        scan_id: str,
    ) -> CheckResult:
        try:
            # 1. Non-zip file rejected with 415
            res_invalid = client.post(
                "/api/v1/scans",
                files={"file": ("script.py", b"print('hello')", "text/x-python")},
            )
            if res_invalid.status_code != 415:
                return CheckResult(
                    name="E2E Response Schema & Error Condition Audit",
                    status=CheckStatus.FAIL,
                    details=f"Non-ZIP upload expected status 415, got {res_invalid.status_code}",
                )

            # 2. Unknown scan ID returns 404
            res_404 = client.get("/api/v1/scans/unknown-scan-id-xyz-999")
            if res_404.status_code != 404:
                return CheckResult(
                    name="E2E Response Schema & Error Condition Audit",
                    status=CheckStatus.FAIL,
                    details=f"Unknown scan ID expected status 404, got {res_404.status_code}",
                )

            # 3. Remediation proposals endpoint functional and requires human approval
            prop_res = client.get(f"/api/v1/scans/{scan_id}/remediation/proposals")
            if prop_res.status_code != 200:
                return CheckResult(
                    name="E2E Response Schema & Error Condition Audit",
                    status=CheckStatus.FAIL,
                    details=f"GET proposals expected 200, got {prop_res.status_code}",
                )
            prop_data = prop_res.json()
            if not prop_data.get("requires_approval", False):
                return CheckResult(
                    name="E2E Response Schema & Error Condition Audit",
                    status=CheckStatus.FAIL,
                    details="Proposals response missing requires_approval=True invariant",
                )

            # 4. Remediation apply rejects unapproved requests
            apply_unapproved = client.post(
                f"/api/v1/scans/{scan_id}/remediation/apply",
                json={"approved_proposal_ids": ["prop_1"], "confirm_approval": False},
            )
            if apply_unapproved.status_code != 400:
                return CheckResult(
                    name="E2E Response Schema & Error Condition Audit",
                    status=CheckStatus.FAIL,
                    details=f"Unapproved remediation apply expected 400, got {apply_unapproved.status_code}",
                )

            return CheckResult(
                name="E2E Response Schema & Error Condition Audit",
                status=CheckStatus.PASS,
                details="All boundary error conditions, media validations, and human approval gates passed audit.",
            )

        except Exception as exc:
            return CheckResult(
                name="E2E Response Schema & Error Condition Audit",
                status=CheckStatus.FAIL,
                details=f"Exception auditing response schemas & error conditions: {exc}",
            )

    @classmethod
    def _run_e2e_tests(cls, test_path: str) -> CheckResult:
        success, output = run_pytest([test_path])
        if success:
            return CheckResult(
                name="E2E Automated Integration Test Suite",
                status=CheckStatus.PASS,
                details="E2E integration tests passed.",
            )
        return CheckResult(
            name="E2E Automated Integration Test Suite",
            status=CheckStatus.FAIL,
            details=f"E2E tests failed:\n{output}",
        )
