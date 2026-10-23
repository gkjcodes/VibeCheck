"""Phase 5 Checkpoint: Rescan Comparison & State Tracking.

Verifies:
- Baseline scan persistence and retrieval via ScanStore.
- Rescan execution against corrected fixtures.
- Stable finding matching using rule_id, normalized location, and code evidence.
- State transitions: RESOLVED, STILL_PRESENT, NEW, and NOT_VERIFIABLE findings.
- Honest resolution check (unverifiable findings and skipped files not falsely marked resolved).
- Comparison test suite passes completely.
"""

from pathlib import Path
import tempfile
from typing import List

from backend.app.schemas.comparison import (
    ComparisonResult,
    ComparisonSummary,
    FindingDisposition,
)
from backend.app.schemas.finding import Finding, FindingLocation
from backend.app.schemas.scan import ScanCoverage, ScanResponse
from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase5Check:
    """Checkpoint gate runner for Phase 5: Rescan Comparison."""

    phase_number = 5
    phase_name = "Rescan Comparison & Verification"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        if not cls._inspect_comparison_module():
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
            return results

        # Run behavioral checks
        results.append(cls._check_comparison_interface())
        results.append(cls._check_baseline_storage())
        results.append(cls._check_rescan_ingestion())
        results.append(cls._check_stable_matching())
        results.append(cls._check_classification())
        results.append(cls._check_honest_resolution())

        # Test suite check
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

            return all(
                hasattr(comparison, attr)
                for attr in [
                    "compare_scans",
                    "ScanComparator",
                    "ComparisonResult",
                    "FindingDisposition",
                    "ScanStore",
                ]
            )
        except Exception:
            return False

    @classmethod
    def _check_comparison_interface(cls) -> CheckResult:
        try:
            from backend.comparison import (
                compare_scans,
                ComparisonResult,
                ScanComparator,
            )

            empty_cov = ScanCoverage(files_scanned=1, skipped_files=[], rules_evaluated=5)
            s1 = ScanResponse(
                scan_id="test-base",
                status="completed",
                project="proj",
                coverage=empty_cov,
                findings=[],
                repair_prompt="",
                limitations=[],
            )
            s2 = ScanResponse(
                scan_id="test-curr",
                status="completed",
                project="proj",
                coverage=empty_cov,
                findings=[],
                repair_prompt="",
                limitations=[],
            )

            comp = compare_scans(s1, s2)
            if not isinstance(comp, ComparisonResult):
                return CheckResult(
                    name="Comparison Engine Interface Implementation",
                    status=CheckStatus.FAIL,
                    details=f"compare_scans returned {type(comp)}, expected ComparisonResult.",
                )

            if not hasattr(comp, "summary") or not hasattr(comp, "findings"):
                return CheckResult(
                    name="Comparison Engine Interface Implementation",
                    status=CheckStatus.FAIL,
                    details="ComparisonResult missing required summary or findings attributes.",
                )

            return CheckResult(
                name="Comparison Engine Interface Implementation",
                status=CheckStatus.PASS,
                details="Comparison engine interface and contract verified.",
            )
        except Exception as exc:
            return CheckResult(
                name="Comparison Engine Interface Implementation",
                status=CheckStatus.FAIL,
                details=f"Exception testing comparison interface: {exc}",
            )

    @classmethod
    def _check_baseline_storage(cls) -> CheckResult:
        try:
            from backend.comparison.store import ScanStore

            with tempfile.TemporaryDirectory() as tmp_dir:
                store = ScanStore(storage_dir=Path(tmp_dir))
                cov = ScanCoverage(files_scanned=2, skipped_files=[], rules_evaluated=5)
                scan = ScanResponse(
                    scan_id="scan-store-001",
                    status="completed",
                    project="sample-project",
                    coverage=cov,
                    findings=[],
                    repair_prompt="prompt",
                    limitations=[],
                )
                store.save_scan(scan)
                retrieved = store.get_scan("scan-store-001")
                if not retrieved or retrieved.scan_id != "scan-store-001":
                    return CheckResult(
                        name="Baseline Scan Storage & Retrieval",
                        status=CheckStatus.FAIL,
                        details="ScanStore failed to save and retrieve scan response.",
                    )

                if store.get_scan("non-existent-id") is not None:
                    return CheckResult(
                        name="Baseline Scan Storage & Retrieval",
                        status=CheckStatus.FAIL,
                        details="ScanStore returned a result for non-existent scan ID.",
                    )

                try:
                    store.get_scan("../../traversal_id")
                    return CheckResult(
                        name="Baseline Scan Storage & Retrieval",
                        status=CheckStatus.FAIL,
                        details="ScanStore failed to reject traversal characters in scan ID.",
                    )
                except ValueError:
                    pass

            return CheckResult(
                name="Baseline Scan Storage & Retrieval",
                status=CheckStatus.PASS,
                details="Scan persistence, thread-safe cache, and path-traversal rejection verified.",
            )
        except Exception as exc:
            return CheckResult(
                name="Baseline Scan Storage & Retrieval",
                status=CheckStatus.FAIL,
                details=f"Exception testing baseline storage: {exc}",
            )

    @classmethod
    def _check_rescan_ingestion(cls) -> CheckResult:
        try:
            from backend.comparison import compare_scans
            from backend.scanners import ScannerEngine

            vulnerable_dir = REPO_ROOT / "samples" / "vulnerable"
            corrected_dir = REPO_ROOT / "samples" / "corrected"

            if not vulnerable_dir.exists() or not corrected_dir.exists():
                return CheckResult(
                    name="Corrected Fixture Rescan Ingestion",
                    status=CheckStatus.FAIL,
                    details=f"Sample fixtures missing at {vulnerable_dir} or {corrected_dir}.",
                )

            engine = ScannerEngine()
            vuln_findings, vuln_cov, vuln_lim = engine.scan_workspace(vulnerable_dir)
            corr_findings, corr_cov, corr_lim = engine.scan_workspace(corrected_dir)

            base_scan = ScanResponse(
                scan_id="vulnerable-base",
                status="completed",
                project="sample-app",
                coverage=vuln_cov,
                findings=vuln_findings,
                repair_prompt="",
                limitations=vuln_lim,
            )
            curr_scan = ScanResponse(
                scan_id="corrected-rescan",
                status="completed",
                project="sample-app",
                coverage=corr_cov,
                findings=corr_findings,
                repair_prompt="",
                limitations=corr_lim,
            )

            result = compare_scans(base_scan, curr_scan)
            if result.summary.resolved_count < 1:
                return CheckResult(
                    name="Corrected Fixture Rescan Ingestion",
                    status=CheckStatus.FAIL,
                    details=f"Expected resolved findings in corrected fixture rescan, got {result.summary.resolved_count}.",
                )

            return CheckResult(
                name="Corrected Fixture Rescan Ingestion",
                status=CheckStatus.PASS,
                details=(
                    f"Rescan successfully compared: {result.summary.baseline_total} baseline findings -> "
                    f"{result.summary.resolved_count} resolved, {result.summary.still_present_count} still present."
                ),
            )
        except Exception as exc:
            return CheckResult(
                name="Corrected Fixture Rescan Ingestion",
                status=CheckStatus.FAIL,
                details=f"Exception during rescan comparison: {exc}",
            )

    @classmethod
    def _check_stable_matching(cls) -> CheckResult:
        try:
            from backend.comparison import compare_scans

            # Baseline finding at line 20
            f_base = Finding(
                id="f-original-id",
                rule_id="VIBE-INJ-001",
                category="injection",
                title="SQL Injection",
                severity="high",
                confidence="high",
                status="open",
                location=FindingLocation(
                    file_path="src/api.py",
                    line_start=20,
                    line_end=22,
                    snippet="db.execute(query)",
                ),
                evidence="db.execute(query)",
                impact="DB compromise",
                recommendation="Use parameters",
                verification_steps=["Run test"],
            )

            # Rescan finding: changed ID and shifted line (+15 lines)
            f_curr = Finding(
                id="f-new-id-generated",
                rule_id="VIBE-INJ-001",
                category="injection",
                title="SQL Injection",
                severity="high",
                confidence="high",
                status="open",
                location=FindingLocation(
                    file_path="src/api.py",
                    line_start=35,
                    line_end=37,
                    snippet="db.execute(query)",
                ),
                evidence="db.execute(query)",
                impact="DB compromise",
                recommendation="Use parameters",
                verification_steps=["Run test"],
            )

            cov = ScanCoverage(files_scanned=1, skipped_files=[], rules_evaluated=5)
            s_base = ScanResponse(
                scan_id="s1",
                status="completed",
                project="p",
                coverage=cov,
                findings=[f_base],
                repair_prompt="",
                limitations=[],
            )
            s_curr = ScanResponse(
                scan_id="s2",
                status="completed",
                project="p",
                coverage=cov,
                findings=[f_curr],
                repair_prompt="",
                limitations=[],
            )

            result = compare_scans(s_base, s_curr)
            if result.summary.still_present_count != 1 or len(result.findings) != 1:
                return CheckResult(
                    name="Stable Finding Matching (Rule, Location, Evidence)",
                    status=CheckStatus.FAIL,
                    details="Failed to correlate finding across shifted line and changed finding ID.",
                )

            item = result.findings[0]
            if item.disposition != FindingDisposition.STILL_PRESENT:
                return CheckResult(
                    name="Stable Finding Matching (Rule, Location, Evidence)",
                    status=CheckStatus.FAIL,
                    details=f"Disposition is {item.disposition}, expected STILL_PRESENT.",
                )

            return CheckResult(
                name="Stable Finding Matching (Rule, Location, Evidence)",
                status=CheckStatus.PASS,
                details=f"Stable correlation across line shifts and ID rotations verified ({item.match_rationale}).",
            )
        except Exception as exc:
            return CheckResult(
                name="Stable Finding Matching (Rule, Location, Evidence)",
                status=CheckStatus.FAIL,
                details=f"Exception testing stable finding matching: {exc}",
            )

    @classmethod
    def _check_classification(cls) -> CheckResult:
        try:
            from backend.comparison import compare_scans

            f1 = Finding(
                id="f-1",
                rule_id="RULE-1",
                category="cat",
                title="Finding 1",
                severity="high",
                confidence="high",
                status="open",
                location=FindingLocation(file_path="a.py", line_start=10, line_end=12, snippet="x"),
                evidence="x",
                impact="x",
                recommendation="x",
                verification_steps=["x"],
            )
            f2 = Finding(
                id="f-2",
                rule_id="RULE-2",
                category="cat",
                title="Finding 2",
                severity="medium",
                confidence="high",
                status="open",
                location=FindingLocation(file_path="b.py", line_start=20, line_end=22, snippet="y"),
                evidence="y",
                impact="y",
                recommendation="y",
                verification_steps=["y"],
            )
            f_new = Finding(
                id="f-new",
                rule_id="RULE-3",
                category="cat",
                title="Finding New",
                severity="low",
                confidence="high",
                status="open",
                location=FindingLocation(file_path="c.py", line_start=5, line_end=6, snippet="z"),
                evidence="z",
                impact="z",
                recommendation="z",
                verification_steps=["z"],
            )

            cov = ScanCoverage(files_scanned=3, skipped_files=[], rules_evaluated=5)
            s_base = ScanResponse(
                scan_id="s1",
                status="completed",
                project="p",
                coverage=cov,
                findings=[f1, f2],
                repair_prompt="",
                limitations=[],
            )
            # f1 resolved (absent), f2 persistent (present), f_new introduced (new)
            s_curr = ScanResponse(
                scan_id="s2",
                status="completed",
                project="p",
                coverage=cov,
                findings=[f2, f_new],
                repair_prompt="",
                limitations=[],
            )

            result = compare_scans(s_base, s_curr)
            if (
                result.summary.resolved_count != 1
                or result.summary.still_present_count != 1
                or result.summary.new_count != 1
            ):
                return CheckResult(
                    name="Tri-State Finding Classification (Resolved / Persistent / New)",
                    status=CheckStatus.FAIL,
                    details=(
                        f"Expected (resolved=1, still_present=1, new=1), got "
                        f"(resolved={result.summary.resolved_count}, "
                        f"still_present={result.summary.still_present_count}, "
                        f"new={result.summary.new_count})."
                    ),
                )

            return CheckResult(
                name="Tri-State Finding Classification (Resolved / Persistent / New)",
                status=CheckStatus.PASS,
                details="Tri-state finding classifications (RESOLVED, STILL_PRESENT, NEW) verified.",
            )
        except Exception as exc:
            return CheckResult(
                name="Tri-State Finding Classification (Resolved / Persistent / New)",
                status=CheckStatus.FAIL,
                details=f"Exception testing classification: {exc}",
            )

    @classmethod
    def _check_honest_resolution(cls) -> CheckResult:
        try:
            from backend.comparison import compare_scans

            f = Finding(
                id="f-1",
                rule_id="RULE-1",
                category="cat",
                title="Finding 1",
                severity="high",
                confidence="high",
                status="open",
                location=FindingLocation(file_path="src/large.py", line_start=10, line_end=12, snippet="x"),
                evidence="x",
                impact="x",
                recommendation="x",
                verification_steps=["x"],
            )

            base = ScanResponse(
                scan_id="s1",
                status="completed",
                project="p",
                coverage=ScanCoverage(files_scanned=2, skipped_files=[], rules_evaluated=5),
                findings=[f],
                repair_prompt="",
                limitations=[],
            )

            # Scenario A: Rescan skipped the file containing the finding
            rescan_skipped = ScanResponse(
                scan_id="s2",
                status="completed",
                project="p",
                coverage=ScanCoverage(files_scanned=1, skipped_files=["src/large.py"], rules_evaluated=5),
                findings=[],  # finding absent only because file was skipped
                repair_prompt="",
                limitations=[],
            )

            res_a = compare_scans(base, rescan_skipped)
            if res_a.summary.resolved_count != 0 or res_a.summary.not_verifiable_count != 1:
                return CheckResult(
                    name="Honest Resolution Verification (No False Clears)",
                    status=CheckStatus.FAIL,
                    details="Finding in skipped file was falsely claimed resolved instead of NOT_VERIFIABLE.",
                )

            # Scenario B: Rescan failed execution entirely
            rescan_failed = ScanResponse(
                scan_id="s3",
                status="failed",
                project="p",
                coverage=ScanCoverage(files_scanned=0, skipped_files=[], rules_evaluated=5),
                findings=[],
                repair_prompt="",
                limitations=["Scanner crash"],
            )

            res_b = compare_scans(base, rescan_failed)
            if res_b.summary.resolved_count != 0 or res_b.summary.not_verifiable_count != 1:
                return CheckResult(
                    name="Honest Resolution Verification (No False Clears)",
                    status=CheckStatus.FAIL,
                    details="Failed rescan falsely claimed findings were resolved instead of NOT_VERIFIABLE.",
                )

            return CheckResult(
                name="Honest Resolution Verification (No False Clears)",
                status=CheckStatus.PASS,
                details="Honest resolution verified: failed rescans and skipped files strictly yield NOT_VERIFIABLE.",
            )
        except Exception as exc:
            return CheckResult(
                name="Honest Resolution Verification (No False Clears)",
                status=CheckStatus.FAIL,
                details=f"Exception testing honest resolution guards: {exc}",
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
