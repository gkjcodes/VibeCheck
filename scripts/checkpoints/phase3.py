"""Phase 3 Checkpoint: Security Scanner Integration.

Verifies:
- Scanner engine exports active rules across all 5 core security categories.
- Real static analysis detects vulnerabilities in controlled vulnerable fixtures.
- Finding instances contain grounded file locations, line numbers, and evidence.
- Findings conform strictly to the agreed Finding Pydantic model and schema.
- Sensitive credentials and keys are masked in evidence, snippets, and outputs.
- API endpoint /api/v1/scans invokes the scanner and returns live findings.
- Scanner failures are handled honestly without false clean scans.
- Corrected fixtures are verified to produce clean results for fixed patterns.
- Automated scanner test suite passes completely.
"""

import io
from pathlib import Path
import tempfile
from typing import List, Set
import zipfile

from fastapi.testclient import TestClient

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase3Check:
    """Checkpoint gate runner for Phase 3: Security Scanner Integration."""

    phase_number = 3
    phase_name = "Security Scanner Integration"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        # 1. Scanner engine & rules inspection
        engine_check, scanner_cls = cls._check_scanner_engine_exports()
        results.append(engine_check)

        if engine_check.status != CheckStatus.PASS or scanner_cls is None:
            results.append(
                CheckResult(
                    name="Controlled Vulnerable Fixture Scanning",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Scanner engine not implemented in backend/scanners.",
                )
            )
            results.append(
                CheckResult(
                    name="Grounded Finding Location & Line Evidence",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Awaiting scanner engine implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Finding Schema Conformity",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Awaiting scanner engine implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Secret Masking in Logs & Output",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Awaiting secret masking implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="API Scanner Integration (/api/v1/scans)",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Awaiting scanner API integration.",
                )
            )
            results.append(
                CheckResult(
                    name="Honest Scanner Failure Handling (No False Cleans)",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Awaiting scanner error handling implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Corrected Fixture Scan Verification",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Awaiting scanner implementation.",
                )
            )
        else:
            # 2. Controlled Vulnerable Fixture Scanning
            results.append(cls._check_vulnerable_fixture_scan(scanner_cls))

            # 3. Grounded Finding Location & Line Evidence
            results.append(cls._check_grounded_findings(scanner_cls))

            # 4. Finding Schema Conformity
            results.append(cls._check_finding_schema_conformity(scanner_cls))

            # 5. Secret Masking in Logs & Output
            results.append(cls._check_secret_masking(scanner_cls))

            # 6. API Scanner Integration (/api/v1/scans)
            results.append(cls._check_api_scanner_integration())

            # 7. Honest Scanner Failure Handling
            results.append(cls._check_honest_scanner_failures(scanner_cls))

            # 8. Corrected Fixture Scan Verification
            results.append(cls._check_corrected_fixture_scan(scanner_cls))

        # 9. Scanner automated test suite
        scanner_test = REPO_ROOT / "backend" / "tests" / "test_scanners.py"
        if not scanner_test.exists():
            results.append(
                CheckResult(
                    name="Scanner Automated Test Suite",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/tests/test_scanners.py not yet implemented.",
                )
            )
        else:
            results.append(cls._run_scanner_tests(str(scanner_test)))

        return results

    @classmethod
    def _check_scanner_engine_exports(cls):
        try:
            from backend.scanners import ScannerEngine, get_default_rules, mask_secret

            rules = get_default_rules()
            if not rules:
                return (
                    CheckResult(
                        name="Scanner Engine & Rule Registry Implementation",
                        status=CheckStatus.FAIL,
                        details="get_default_rules() returned an empty rule list.",
                    ),
                    None,
                )

            categories: Set[str] = {r.category for r in rules}
            expected_categories = {
                "hardcoded-secret",
                "dangerous-js",
                "injection",
                "frontend-risk",
                "insecure-config",
            }
            missing_categories = expected_categories - categories

            if missing_categories:
                return (
                    CheckResult(
                        name="Scanner Engine & Rule Registry Implementation",
                        status=CheckStatus.FAIL,
                        details=f"Scanner rules missing expected categories: {missing_categories}",
                    ),
                    None,
                )

            return (
                CheckResult(
                    name="Scanner Engine & Rule Registry Implementation",
                    status=CheckStatus.PASS,
                    details=f"ScannerEngine active with {len(rules)} rules across all required categories: {sorted(list(categories))}.",
                ),
                ScannerEngine,
            )
        except Exception as exc:
            return (
                CheckResult(
                    name="Scanner Engine & Rule Registry Implementation",
                    status=CheckStatus.FAIL,
                    details=f"Failed to import ScannerEngine or rules: {exc}",
                ),
                None,
            )

    @classmethod
    def _check_vulnerable_fixture_scan(cls, scanner_cls) -> CheckResult:
        try:
            engine = scanner_cls()
            vulnerable_dir = REPO_ROOT / "samples" / "vulnerable"
            if not vulnerable_dir.exists():
                return CheckResult(
                    name="Controlled Vulnerable Fixture Scanning",
                    status=CheckStatus.FAIL,
                    details=f"Vulnerable samples directory missing at {vulnerable_dir}",
                )

            findings, coverage, _ = engine.scan_workspace(vulnerable_dir)
            if not findings:
                return CheckResult(
                    name="Controlled Vulnerable Fixture Scanning",
                    status=CheckStatus.FAIL,
                    details="Scanner produced 0 findings on known vulnerable sample fixtures.",
                )

            found_categories = {f.category for f in findings}
            return CheckResult(
                name="Controlled Vulnerable Fixture Scanning",
                status=CheckStatus.PASS,
                details=f"Detected {len(findings)} vulnerability findings across categories: {sorted(list(found_categories))}.",
            )
        except Exception as exc:
            return CheckResult(
                name="Controlled Vulnerable Fixture Scanning",
                status=CheckStatus.FAIL,
                details=f"Exception during vulnerable fixture scan: {exc}",
            )

    @classmethod
    def _check_grounded_findings(cls, scanner_cls) -> CheckResult:
        try:
            engine = scanner_cls()
            vulnerable_dir = REPO_ROOT / "samples" / "vulnerable"
            findings, _, _ = engine.scan_workspace(vulnerable_dir)

            for f in findings:
                if not f.location or not f.location.file_path:
                    return CheckResult(
                        name="Grounded Finding Location & Line Evidence",
                        status=CheckStatus.FAIL,
                        details=f"Finding {f.id} ({f.rule_id}) is missing relative file_path.",
                    )
                # Ensure path is relative POSIX
                if "\\" in f.location.file_path or f.location.file_path.startswith("/"):
                    return CheckResult(
                        name="Grounded Finding Location & Line Evidence",
                        status=CheckStatus.FAIL,
                        details=f"Finding {f.id} has non-relative or non-POSIX file_path: {f.location.file_path}",
                    )
                if not f.location.line_start or f.location.line_start < 1:
                    return CheckResult(
                        name="Grounded Finding Location & Line Evidence",
                        status=CheckStatus.FAIL,
                        details=f"Finding {f.id} has invalid line_start: {f.location.line_start}",
                    )
                if not f.evidence:
                    return CheckResult(
                        name="Grounded Finding Location & Line Evidence",
                        status=CheckStatus.FAIL,
                        details=f"Finding {f.id} is missing concrete evidence description.",
                    )

            return CheckResult(
                name="Grounded Finding Location & Line Evidence",
                status=CheckStatus.PASS,
                details=f"All {len(findings)} findings contain verified relative POSIX paths, 1-indexed lines, and evidence.",
            )
        except Exception as exc:
            return CheckResult(
                name="Grounded Finding Location & Line Evidence",
                status=CheckStatus.FAIL,
                details=f"Exception checking grounded finding locations: {exc}",
            )

    @classmethod
    def _check_finding_schema_conformity(cls, scanner_cls) -> CheckResult:
        try:
            from backend.app.schemas.finding import Finding

            engine = scanner_cls()
            vulnerable_dir = REPO_ROOT / "samples" / "vulnerable"
            findings, _, _ = engine.scan_workspace(vulnerable_dir)

            for f in findings:
                # Re-validate against Pydantic model
                dumped = f.model_dump()
                revalidated = Finding.model_validate(dumped)
                assert revalidated.id == f.id
                assert revalidated.severity in ("critical", "high", "medium", "low", "info")

            return CheckResult(
                name="Finding Schema Conformity",
                status=CheckStatus.PASS,
                details=f"All {len(findings)} generated findings conform strictly to the Finding schema contract.",
            )
        except Exception as exc:
            return CheckResult(
                name="Finding Schema Conformity",
                status=CheckStatus.FAIL,
                details=f"Finding schema validation failure: {exc}",
            )

    @classmethod
    def _check_secret_masking(cls, scanner_cls) -> CheckResult:
        try:
            raw_secret = "sk_test_51MzXYZ1234567890abcdef"
            content = f"const STRIPE = '{raw_secret}';\n"

            engine = scanner_cls()
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = Path(tmp_dir)
                (tmp_path / "key.js").write_text(content, encoding="utf-8")

                findings, _, _ = engine.scan_workspace(tmp_path)
                if not findings:
                    return CheckResult(
                        name="Secret Masking in Logs & Output",
                        status=CheckStatus.FAIL,
                        details="Exposed secret was not detected by scanner.",
                    )

                for f in findings:
                    if raw_secret in f.evidence or (f.location.snippet and raw_secret in f.location.snippet):
                        return CheckResult(
                            name="Secret Masking in Logs & Output",
                            status=CheckStatus.FAIL,
                            details="Raw unmasked credential leaked in finding evidence or snippet!",
                        )

            return CheckResult(
                name="Secret Masking in Logs & Output",
                status=CheckStatus.PASS,
                details="Sensitive tokens are cleanly masked in evidence and source snippets.",
            )
        except Exception as exc:
            return CheckResult(
                name="Secret Masking in Logs & Output",
                status=CheckStatus.FAIL,
                details=f"Exception checking secret masking: {exc}",
            )

    @classmethod
    def _check_api_scanner_integration(cls) -> CheckResult:
        try:
            from backend.app.main import app
            from backend.app.intake import WorkspaceManager

            client = TestClient(app)
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as zf:
                zf.writestr(
                    "src/app.js",
                    "const API_KEY = 'sk_test_51MzXYZ1234567890abcdef';\neval(userInput);\n",
                )

            zip_buffer.seek(0)
            response = client.post(
                "/api/v1/scans",
                files={"file": ("vibe-test.zip", zip_buffer.getvalue(), "application/zip")},
            )

            if response.status_code != 201:
                return CheckResult(
                    name="API Scanner Integration (/api/v1/scans)",
                    status=CheckStatus.FAIL,
                    details=f"Expected HTTP 201 from /api/v1/scans, got {response.status_code}: {response.text}",
                )

            data = response.json()
            if data.get("status") != "completed":
                return CheckResult(
                    name="API Scanner Integration (/api/v1/scans)",
                    status=CheckStatus.FAIL,
                    details=f"Expected status 'completed', got '{data.get('status')}'",
                )

            findings = data.get("findings", [])
            if not findings:
                return CheckResult(
                    name="API Scanner Integration (/api/v1/scans)",
                    status=CheckStatus.FAIL,
                    details="API returned 0 findings for known vulnerable test upload.",
                )

            # Cleanup test workspace
            wm = WorkspaceManager()
            wm.cleanup_workspace(data["scan_id"])

            return CheckResult(
                name="API Scanner Integration (/api/v1/scans)",
                status=CheckStatus.PASS,
                details=f"API successfully triggered scanner and returned {len(findings)} findings with completed status.",
            )
        except Exception as exc:
            return CheckResult(
                name="API Scanner Integration (/api/v1/scans)",
                status=CheckStatus.FAIL,
                details=f"Exception testing API scanner integration: {exc}",
            )

    @classmethod
    def _check_honest_scanner_failures(cls, scanner_cls) -> CheckResult:
        try:
            from backend.scanners import ScannerError

            engine = scanner_cls()
            non_existent = REPO_ROOT / "temp_scans" / "non_existent_path_xyz_123"

            try:
                engine.scan_workspace(non_existent)
                return CheckResult(
                    name="Honest Scanner Failure Handling (No False Cleans)",
                    status=CheckStatus.FAIL,
                    details="Scanner silently returned clean result for non-existent workspace path.",
                )
            except ScannerError:
                return CheckResult(
                    name="Honest Scanner Failure Handling (No False Cleans)",
                    status=CheckStatus.PASS,
                    details="Scanner correctly raises ScannerError on invalid workspaces rather than falsely reporting clean results.",
                )
        except Exception as exc:
            return CheckResult(
                name="Honest Scanner Failure Handling (No False Cleans)",
                status=CheckStatus.FAIL,
                details=f"Exception testing scanner error handling: {exc}",
            )

    @classmethod
    def _check_corrected_fixture_scan(cls, scanner_cls) -> CheckResult:
        try:
            engine = scanner_cls()
            corrected_dir = REPO_ROOT / "samples" / "corrected"
            if not corrected_dir.exists():
                return CheckResult(
                    name="Corrected Fixture Scan Verification",
                    status=CheckStatus.FAIL,
                    details=f"Corrected samples directory missing at {corrected_dir}",
                )

            findings, coverage, _ = engine.scan_workspace(corrected_dir)
            if findings:
                rule_ids = [f.rule_id for f in findings]
                return CheckResult(
                    name="Corrected Fixture Scan Verification",
                    status=CheckStatus.FAIL,
                    details=f"Corrected fixtures triggered unexpected findings: {rule_ids}",
                )

            return CheckResult(
                name="Corrected Fixture Scan Verification",
                status=CheckStatus.PASS,
                details=f"Scanned {coverage.files_scanned} corrected fixture files; 0 false positive findings reported.",
            )
        except Exception as exc:
            return CheckResult(
                name="Corrected Fixture Scan Verification",
                status=CheckStatus.FAIL,
                details=f"Exception testing corrected fixtures: {exc}",
            )

    @classmethod
    def _run_scanner_tests(cls, test_path: str) -> CheckResult:
        success, output = run_pytest([test_path])
        if success:
            return CheckResult(
                name="Scanner Automated Test Suite",
                status=CheckStatus.PASS,
                details="All automated scanner tests in backend/tests/test_scanners.py passed.",
            )
        return CheckResult(
            name="Scanner Automated Test Suite",
            status=CheckStatus.FAIL,
            details=f"Scanner tests failed:\n{output}",
        )
