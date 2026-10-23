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

from typing import List

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase6Check:
    """Checkpoint gate runner for Phase 6: End-to-End MVP."""

    phase_number = 6
    phase_name = "Phase 6: End-to-End MVP Integration"

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
        else:
            results.append(cls._check_scan_workflow())

        if not rescan_endpoint:
            results.append(
                CheckResult(
                    name="E2E Corrected Code Rescan Submission",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Rescan endpoint not yet registered in API.",
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
            results.append(cls._check_rescan_workflow())

        # Response schemas and error cases
        results.append(
            CheckResult(
                name="E2E Response Schema & Error Condition Audit",
                status=CheckStatus.NOT_IMPLEMENTED,
                details="Comprehensive E2E contract check awaiting full workflow implementation.",
            )
        )

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

            return [getattr(route, "path", "") for route in app.routes]
        except Exception:
            return []

    @classmethod
    def _check_scan_workflow(cls) -> CheckResult:
        return CheckResult(
            name="E2E Initial Submission & Scan Execution",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="E2E scan verification awaiting Phase 6 implementation.",
        )

    @classmethod
    def _check_rescan_workflow(cls) -> CheckResult:
        return CheckResult(
            name="E2E Corrected Code Rescan Submission",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="E2E rescan verification awaiting Phase 6 implementation.",
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
