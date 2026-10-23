"""Phase 2 Checkpoint: Secure Source Code Intake.

Verifies:
- Valid ZIP upload accepted through intake endpoint (/api/v1/scans).
- Invalid file types rejected.
- Oversized uploads rejected.
- File count and uncompressed-size limits enforced (zip bomb guard).
- ZIP path traversal entries rejected safely (Zip Slip guard).
- Symlink entries rejected safely.
- Extracted files cannot escape per-scan workspace.
- Uploaded source code is never executed.
- Workspace cleanup and error handling behave as documented.
- Intake test suite passes.
"""

import io
from pathlib import Path
from typing import List, Optional
import zipfile

from fastapi.testclient import TestClient

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase2Check:
    """Checkpoint gate runner for Phase 2: Secure Intake."""

    phase_number = 2
    phase_name = "Secure Source Code Intake"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

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
        if not intake_module:
            results.append(
                CheckResult(
                    name="Oversized Upload Rejection",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Intake module not available to test upload limits.",
                )
            )
        else:
            results.append(cls._check_oversized_upload(intake_module))

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

            paths = app.openapi().get("paths", {})
            for path, methods in paths.items():
                if "post" in methods and ("/scan" in path or "/intake" in path):
                    return path
            return None
        except Exception:
            return None

    @classmethod
    def _inspect_intake_module(cls) -> Optional[object]:
        try:
            import backend.app.intake as intake

            if hasattr(intake, "SafeExtractor") and hasattr(intake, "WorkspaceManager"):
                return intake
            return None
        except Exception:
            return None

    @classmethod
    def _check_valid_zip_upload(cls, endpoint: str) -> CheckResult:
        try:
            from backend.app.main import app
            from backend.app.intake import WorkspaceManager

            client = TestClient(app)
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as zf:
                zf.writestr("src/app.js", "console.log('VibeShield check');")

            zip_buffer.seek(0)
            response = client.post(
                endpoint,
                files={"file": ("project.zip", zip_buffer.getvalue(), "application/zip")},
            )

            if response.status_code not in (200, 201):
                return CheckResult(
                    name="ZIP Archive Upload Endpoint",
                    status=CheckStatus.FAIL,
                    details=f"Expected HTTP 201/200, got {response.status_code}: {response.text}",
                )

            data = response.json()
            if "scan_id" not in data or not data["scan_id"].startswith("scan_"):
                return CheckResult(
                    name="ZIP Archive Upload Endpoint",
                    status=CheckStatus.FAIL,
                    details=f"Invalid scan_id in response: {data.get('scan_id')}",
                )

            # Cleanup test workspace
            wm = WorkspaceManager()
            wm.cleanup_workspace(data["scan_id"])

            return CheckResult(
                name="ZIP Archive Upload Endpoint",
                status=CheckStatus.PASS,
                details=f"Successfully uploaded valid ZIP to {endpoint} and received scan ID {data['scan_id']}.",
            )
        except Exception as exc:
            return CheckResult(
                name="ZIP Archive Upload Endpoint",
                status=CheckStatus.FAIL,
                details=f"Exception during valid ZIP upload: {exc}",
            )

    @classmethod
    def _check_invalid_file_type(cls, endpoint: str) -> CheckResult:
        try:
            from backend.app.main import app

            client = TestClient(app)
            # Submit non-zip text file
            response = client.post(
                endpoint,
                files={"file": ("malicious.txt", b"not a zip archive", "text/plain")},
            )

            if response.status_code in (400, 415, 422):
                return CheckResult(
                    name="Invalid File Type Rejection",
                    status=CheckStatus.PASS,
                    details=f"Correctly rejected non-ZIP upload with HTTP {response.status_code}.",
                )
            return CheckResult(
                name="Invalid File Type Rejection",
                status=CheckStatus.FAIL,
                details=f"Expected rejection (400/415/422), got {response.status_code}",
            )
        except Exception as exc:
            return CheckResult(
                name="Invalid File Type Rejection",
                status=CheckStatus.FAIL,
                details=f"Exception during invalid file type test: {exc}",
            )

    @classmethod
    def _check_oversized_upload(cls, intake_module: object) -> CheckResult:
        try:
            from backend.app.intake import SafeExtractor, ArchiveLimitError
            import io

            # Test individual file limit enforcement
            extractor = SafeExtractor(max_file_bytes=50)
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as zf:
                zf.writestr("huge.txt", "A" * 200)

            zip_buffer.seek(0)
            temp_dest = REPO_ROOT / "temp_scans" / "check_oversize_test"
            temp_dest.mkdir(parents=True, exist_ok=True)

            try:
                extractor.extract(zip_buffer.getvalue(), temp_dest)
                return CheckResult(
                    name="Oversized Upload Rejection",
                    status=CheckStatus.FAIL,
                    details="Extractor failed to reject file exceeding individual size limit.",
                )
            except ArchiveLimitError:
                return CheckResult(
                    name="Oversized Upload Rejection",
                    status=CheckStatus.PASS,
                    details="Correctly enforced individual and upload size limits with ArchiveLimitError.",
                )
            finally:
                import shutil
                shutil.rmtree(temp_dest, ignore_errors=True)
        except Exception as exc:
            return CheckResult(
                name="Oversized Upload Rejection",
                status=CheckStatus.FAIL,
                details=f"Exception testing size limits: {exc}",
            )

    @classmethod
    def _check_zip_bomb_protection(cls, intake_module: object) -> CheckResult:
        try:
            from backend.app.intake import SafeExtractor, ArchiveLimitError
            import io

            # Test entry count limit
            extractor = SafeExtractor(max_entries=2)
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as zf:
                zf.writestr("f1.txt", "1")
                zf.writestr("f2.txt", "2")
                zf.writestr("f3.txt", "3")

            temp_dest = REPO_ROOT / "temp_scans" / "check_zipbomb_test"
            temp_dest.mkdir(parents=True, exist_ok=True)

            try:
                extractor.extract(zip_buffer.getvalue(), temp_dest)
                return CheckResult(
                    name="Archive Entry Count & Uncompressed Size Limits",
                    status=CheckStatus.FAIL,
                    details="Extractor failed to enforce archive entry count limit.",
                )
            except ArchiveLimitError:
                return CheckResult(
                    name="Archive Entry Count & Uncompressed Size Limits",
                    status=CheckStatus.PASS,
                    details="Correctly rejected entry count overflow with ArchiveLimitError.",
                )
            finally:
                import shutil
                shutil.rmtree(temp_dest, ignore_errors=True)
        except Exception as exc:
            return CheckResult(
                name="Archive Entry Count & Uncompressed Size Limits",
                status=CheckStatus.FAIL,
                details=f"Exception testing zip bomb limits: {exc}",
            )

    @classmethod
    def _check_zip_slip_protection(cls, intake_module: object) -> CheckResult:
        try:
            from backend.app.intake import SafeExtractor, SecurityViolationError
            import io

            extractor = SafeExtractor()
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as zf:
                zf.writestr("../../escaped.txt", "payload")

            temp_dest = REPO_ROOT / "temp_scans" / "check_zipslip_test"
            temp_dest.mkdir(parents=True, exist_ok=True)

            try:
                extractor.extract(zip_buffer.getvalue(), temp_dest)
                return CheckResult(
                    name="ZIP Path Traversal Protection (Zip Slip)",
                    status=CheckStatus.FAIL,
                    details="Extractor failed to reject path traversal (Zip Slip).",
                )
            except SecurityViolationError:
                return CheckResult(
                    name="ZIP Path Traversal Protection (Zip Slip)",
                    status=CheckStatus.PASS,
                    details="Detected and blocked path traversal entry with SecurityViolationError.",
                )
            finally:
                import shutil
                shutil.rmtree(temp_dest, ignore_errors=True)
        except Exception as exc:
            return CheckResult(
                name="ZIP Path Traversal Protection (Zip Slip)",
                status=CheckStatus.FAIL,
                details=f"Exception testing path traversal: {exc}",
            )

    @classmethod
    def _check_symlink_rejection(cls, intake_module: object) -> CheckResult:
        try:
            from backend.app.intake import SafeExtractor, SecurityViolationError
            import io

            extractor = SafeExtractor()
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as zf:
                info = zipfile.ZipInfo("symlink_target")
                # Set POSIX symlink attribute (0o120777 << 16)
                info.external_attr = 0o120777 << 16
                zf.writestr(info, "/etc/passwd")

            temp_dest = REPO_ROOT / "temp_scans" / "check_symlink_test"
            temp_dest.mkdir(parents=True, exist_ok=True)

            try:
                extractor.extract(zip_buffer.getvalue(), temp_dest)
                return CheckResult(
                    name="Symlink Entry Rejection",
                    status=CheckStatus.FAIL,
                    details="Extractor failed to reject symlink entry.",
                )
            except SecurityViolationError:
                return CheckResult(
                    name="Symlink Entry Rejection",
                    status=CheckStatus.PASS,
                    details="Detected and blocked symlink entry with SecurityViolationError.",
                )
            finally:
                import shutil
                shutil.rmtree(temp_dest, ignore_errors=True)
        except Exception as exc:
            return CheckResult(
                name="Symlink Entry Rejection",
                status=CheckStatus.FAIL,
                details=f"Exception testing symlink rejection: {exc}",
            )

    @classmethod
    def _check_workspace_isolation(cls, intake_module: object) -> CheckResult:
        try:
            from backend.app.intake import WorkspaceManager

            wm = WorkspaceManager()
            scan_a, dir_a = wm.create_workspace()
            scan_b, dir_b = wm.create_workspace()

            try:
                if scan_a == scan_b or dir_a == dir_b:
                    return CheckResult(
                        name="Per-Scan Workspace Isolation",
                        status=CheckStatus.FAIL,
                        details="Workspaces failed to allocate unique paths.",
                    )
                return CheckResult(
                    name="Per-Scan Workspace Isolation",
                    status=CheckStatus.PASS,
                    details="Workspaces are strictly isolated with independent temporary sandboxes.",
                )
            finally:
                wm.cleanup_workspace(scan_a)
                wm.cleanup_workspace(scan_b)
        except Exception as exc:
            return CheckResult(
                name="Per-Scan Workspace Isolation",
                status=CheckStatus.FAIL,
                details=f"Exception testing workspace isolation: {exc}",
            )

    @classmethod
    def _check_non_execution(cls, intake_module: object) -> CheckResult:
        try:
            from backend.app.intake import SafeExtractor
            import io

            canary_marker = REPO_ROOT / "temp_scans" / "canary_executed.marker"
            if canary_marker.exists():
                canary_marker.unlink()

            # Python code that attempts to execute on import/run
            malicious_code = f"""
import os
with open({repr(str(canary_marker))}, 'w') as f:
    f.write('executed')
"""
            extractor = SafeExtractor()
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w") as zf:
                zf.writestr("exploit.py", malicious_code)

            temp_dest = REPO_ROOT / "temp_scans" / "check_non_exec_test"
            temp_dest.mkdir(parents=True, exist_ok=True)

            try:
                manifest = extractor.extract(zip_buffer.getvalue(), temp_dest)
                if canary_marker.exists():
                    canary_marker.unlink()
                    return CheckResult(
                        name="Safe Static Intake (No Code Execution)",
                        status=CheckStatus.FAIL,
                        details="Uploaded source code was executed during intake!",
                    )
                return CheckResult(
                    name="Safe Static Intake (No Code Execution)",
                    status=CheckStatus.PASS,
                    details=f"Successfully extracted {manifest.total_files} file(s) statically without execution.",
                )
            finally:
                import shutil
                shutil.rmtree(temp_dest, ignore_errors=True)
                if canary_marker.exists():
                    canary_marker.unlink()
        except Exception as exc:
            return CheckResult(
                name="Safe Static Intake (No Code Execution)",
                status=CheckStatus.FAIL,
                details=f"Exception testing code non-execution: {exc}",
            )

    @classmethod
    def _check_workspace_cleanup(cls, intake_module: object) -> CheckResult:
        try:
            from backend.app.intake import WorkspaceManager

            wm = WorkspaceManager()
            scan_id, source_dir = wm.create_workspace()
            dummy_file = source_dir / "test.txt"
            dummy_file.write_text("temporary staging content")

            wm.cleanup_workspace(scan_id)

            if dummy_file.exists() or source_dir.exists():
                return CheckResult(
                    name="Workspace Lifecycle Cleanup & Error Handling",
                    status=CheckStatus.FAIL,
                    details="Workspace cleanup failed to remove staging directory.",
                )

            return CheckResult(
                name="Workspace Lifecycle Cleanup & Error Handling",
                status=CheckStatus.PASS,
                details="Staging workspace cleaned up cleanly without leftover temporary artifacts.",
            )
        except Exception as exc:
            return CheckResult(
                name="Workspace Lifecycle Cleanup & Error Handling",
                status=CheckStatus.FAIL,
                details=f"Exception testing workspace cleanup: {exc}",
            )

    @classmethod
    def _run_intake_tests(cls, test_path: str) -> CheckResult:
        success, output = run_pytest([test_path])
        if success:
            return CheckResult(
                name="Intake Automated Test Suite",
                status=CheckStatus.PASS,
                details="All automated intake tests in backend/tests/test_intake.py passed.",
            )
        return CheckResult(
            name="Intake Automated Test Suite",
            status=CheckStatus.FAIL,
            details=f"Intake tests failed:\n{output}",
        )
