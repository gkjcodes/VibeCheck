"""Phase 5 Checkpoint: Rescan Comparison & State Tracking.

Verifies:
- Baseline scan persistence from vulnerable fixture.
- Rescan execution against corrected fixture.
- Stable finding comparison using rule_id, location, and evidence.
- State transitions: resolved, unresolved (persistent), and new findings.
- Honest resolution check (unverifiable findings not falsely marked resolved).
- Comparison test suite passes.
"""

from typing import List

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase5Check:
    """Checkpoint gate runner for Phase 5: Rescan Comparison."""

    phase_number = 5
    phase_name = "Phase 5: Rescan Comparison & Verification"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        comparison_ready = cls._inspect_comparison_module()

        if not comparison_ready:
            results.append(
                CheckResult(
                    name="Comparison Engine Interface Implementation",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/comparison does not export scan comparison service or diff engine.",
                )
            )
            results.append(
                CheckResult(
                    name="Baseline Scan Storage & Retrieval",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Baseline persistence awaiting Phase 5 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Corrected Fixture Rescan Ingestion",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Rescan ingestion awaiting Phase 5 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Stable Finding Matching (Rule, Location, Evidence)",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Diff matching logic awaiting Phase 5 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Tri-State Finding Classification (Resolved / Persistent / New)",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="State classification awaiting Phase 5 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Honest Resolution Verification (No False Clears)",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Verification guard awaiting Phase 5 implementation.",
                )
            )
        else:
            results.append(cls._check_live_comparison())

        comparison_test = REPO_ROOT / "backend" / "tests" / "test_comparison.py"
        if not comparison_test.exists():
            results.append(
                CheckResult(
                    name="Comparison Automated Test Suite",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/tests/test_comparison.py not yet implemented.",
                )
            )
        else:
            results.append(cls._run_comparison_tests(str(comparison_test)))

        return results

    @classmethod
    def _inspect_comparison_module(cls) -> bool:
        try:
            import backend.comparison as comparison

            return any(
                hasattr(comparison, attr)
                for attr in [
                    "compare_scans",
                    "ScanComparator",
                    "ComparisonResult",
                ]
            )
        except Exception:
            return False

    @classmethod
    def _check_live_comparison(cls) -> CheckResult:
        return CheckResult(
            name="Comparison Engine Interface Implementation",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="Live comparison checks awaiting Phase 5 implementation.",
        )

    @classmethod
    def _run_comparison_tests(cls, test_path: str) -> CheckResult:
        success, output = run_pytest([test_path])
        if success:
            return CheckResult(
                name="Comparison Automated Test Suite",
                status=CheckStatus.PASS,
                details="Comparison tests passed.",
            )
        return CheckResult(
            name="Comparison Automated Test Suite",
            status=CheckStatus.FAIL,
            details=f"Comparison tests failed:\n{output}",
        )
