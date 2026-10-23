"""Phase 2 Checkpoint: Secure Source Code Intake.

Verifies:
- Valid ZIP upload accepted through intake endpoint.
- Invalid file types rejected.
- Oversized uploads rejected.
- File count and uncompressed-size limits enforced (zip bomb guard).
- ZIP path traversal entries rejected safely (Zip Slip guard).
- Symlink entries rejected safely.
- Extracted files cannot escape per-scan workspace.
- Uploaded source code is never executed.
- Workspace cleanup and error handling behave as documented.
- Intake test suite passes.

If intake is not implemented, marks checks NOT IMPLEMENTED and fails the gate.
"""

from pathlib import Path
from typing import List, Optional

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase2Check:
    """Checkpoint gate runner for Phase 2: Secure Intake."""

    phase_number = 2
    phase_name = "Phase 2: Secure Source Code Intake"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        # Check whether intake route/module exists
        intake_endpoint = cls._find_intake_endpoint()
        intake_module = cls._inspect_intake_module()

        # 1. Valid ZIP upload endpoint
        if not intake_endpoint:
            results.append(
                CheckResult(
                    name="ZIP Archive Upload Endpoint",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="No intake/scan upload endpoint registered on FastAPI application.",
                )
            )
        else:
            results.append(cls._check_valid_zip_upload(intake_endpoint))

        # 2. Invalid file type rejection
        if not intake_endpoint:
            results.append(
                CheckResult(
                    name="Invalid File Type Rejection",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Intake endpoint not available to test file type validation.",
                )
            )
        else:
            results.append(cls._check_invalid_file_type(intake_endpoint))

        # 3. Oversized upload rejection
        if not intake_endpoint:
            results.append(
                CheckResult(
                    name="Oversized Upload Rejection",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Intake endpoint not available to test payload size limits.",
                )
            )
        else:
            results.append(cls._check_oversized_upload(intake_endpoint))

        # 4. Zip bomb (uncompressed size/count) protection
        if not intake_module:
            results.append(
                CheckResult(
                    name="Archive Entry Count & Uncompressed Size Limits",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Archive intake extractor not yet implemented in backend/app/intake.",
                )
            )
        else:
            results.append(cls._check_zip_bomb_protection(intake_module))

        # 5. Zip slip / path traversal protection
        if not intake_module:
            results.append(
                CheckResult(
                    name="ZIP Path Traversal Protection (Zip Slip)",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Archive extraction safety guards not yet implemented.",
                )
            )
        else:
            results.append(cls._check_zip_slip_protection(intake_module))

        # 6. Symlink rejection
        if not intake_module:
            results.append(
                CheckResult(
                    name="Symlink Entry Rejection",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Symlink filter logic not yet implemented in intake module.",
                )
            )
        else:
            results.append(cls._check_symlink_rejection(intake_module))

        # 7. Workspace isolation
        if not intake_module:
            results.append(
                CheckResult(
                    name="Per-Scan Workspace Isolation",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Workspace sandbox management not yet implemented.",
                )
            )
        else:
            results.append(cls._check_workspace_isolation(intake_module))

        # 8. Source code non-execution guarantee
        if not intake_module:
            results.append(
                CheckResult(
                    name="Safe Static Intake (No Code Execution)",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Intake pipeline not yet implemented.",
                )
            )
        else:
            results.append(cls._check_non_execution(intake_module))

        # 9. Workspace cleanup & error handling
        if not intake_module:
            results.append(
                CheckResult(
                    name="Workspace Lifecycle Cleanup & Error Handling",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Intake lifecycle cleanup logic not yet implemented.",
                )
            )
        else:
            results.append(cls._check_workspace_cleanup(intake_module))

        # 10. Intake test suite execution
        intake_test = REPO_ROOT / "backend" / "tests" / "test_intake.py"
        if not intake_test.exists():
            results.append(
                CheckResult(
                    name="Intake Automated Test Suite",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/tests/test_intake.py not yet implemented.",
                )
            )
        else:
            results.append(cls._run_intake_tests(str(intake_test)))

        return results

    @classmethod
    def _find_intake_endpoint(cls) -> Optional[str]:
        try:
            from backend.app.main import app

            for route in app.routes:
                path = getattr(route, "path", "")
                methods = getattr(route, "methods", set())
                if "POST" in methods and ("/scan" in path or "/intake" in path):
                    return path
            return None
        except Exception:
            return None

    @classmethod
    def _inspect_intake_module(cls) -> Optional[object]:
        try:
            import backend.app.intake as intake

            # Check if intake defines extraction or validation functions
            if any(
                hasattr(intake, attr)
                for attr in [
                    "extract_archive",
                    "validate_archive",
                    "extract_zip_safe",
                    "WorkspaceManager",
                    "IntakeService",
                ]
            ):
                return intake
            return None
        except Exception:
            return None

    @classmethod
    def _check_valid_zip_upload(cls, endpoint: str) -> CheckResult:
        # Placeholder for Phase 2 execution once implemented
        return CheckResult(
            name="ZIP Archive Upload Endpoint",
            status=CheckStatus.NOT_IMPLEMENTED,
            details=f"Endpoint {endpoint} registered but functional verification not yet ready.",
        )

    @classmethod
    def _check_invalid_file_type(cls, endpoint: str) -> CheckResult:
        return CheckResult(
            name="Invalid File Type Rejection",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="File type validation check awaiting Phase 2 implementation.",
        )

    @classmethod
    def _check_oversized_upload(cls, endpoint: str) -> CheckResult:
        return CheckResult(
            name="Oversized Upload Rejection",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="Upload size guard check awaiting Phase 2 implementation.",
        )

    @classmethod
    def _check_zip_bomb_protection(cls, intake_module: object) -> CheckResult:
        return CheckResult(
            name="Archive Entry Count & Uncompressed Size Limits",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="Zip bomb guard check awaiting Phase 2 implementation.",
        )

    @classmethod
    def _check_zip_slip_protection(cls, intake_module: object) -> CheckResult:
        return CheckResult(
            name="ZIP Path Traversal Protection (Zip Slip)",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="Zip slip guard check awaiting Phase 2 implementation.",
        )

    @classmethod
    def _check_symlink_rejection(cls, intake_module: object) -> CheckResult:
        return CheckResult(
            name="Symlink Entry Rejection",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="Symlink guard check awaiting Phase 2 implementation.",
        )

    @classmethod
    def _check_workspace_isolation(cls, intake_module: object) -> CheckResult:
        return CheckResult(
            name="Per-Scan Workspace Isolation",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="Workspace isolation check awaiting Phase 2 implementation.",
        )

    @classmethod
    def _check_non_execution(cls, intake_module: object) -> CheckResult:
        return CheckResult(
            name="Safe Static Intake (No Code Execution)",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="Non-execution audit check awaiting Phase 2 implementation.",
        )

    @classmethod
    def _check_workspace_cleanup(cls, intake_module: object) -> CheckResult:
        return CheckResult(
            name="Workspace Lifecycle Cleanup & Error Handling",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="Workspace cleanup check awaiting Phase 2 implementation.",
        )

    @classmethod
    def _run_intake_tests(cls, test_path: str) -> CheckResult:
        success, output = run_pytest([test_path])
        if success:
            return CheckResult(
                name="Intake Automated Test Suite",
                status=CheckStatus.PASS,
                details="Intake tests passed.",
            )
        return CheckResult(
            name="Intake Automated Test Suite",
            status=CheckStatus.FAIL,
            details=f"Intake tests failed:\n{output}",
        )
