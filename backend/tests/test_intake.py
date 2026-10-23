"""Comprehensive automated test suite for Phase 2: Secure Source Code Intake."""

import io
from pathlib import Path
import tempfile
import zipfile
import pytest
from fastapi.testclient import TestClient

from backend.app.intake.config import (
    MAX_ARCHIVE_ENTRIES,
    MAX_INDIVIDUAL_FILE_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
)
from backend.app.intake.exceptions import (
    ArchiveLimitError,
    InvalidArchiveError,
    SecurityViolationError,
    UnsupportedFileTypeError,
)
from backend.app.intake.extractor import SafeExtractor
from backend.app.intake.service import IntakeService
from backend.app.intake.workspace import WorkspaceManager
from backend.app.main import app

client = TestClient(app)


def create_zip_bytes(files: dict[str, Union[str, bytes]]) -> bytes:
    """Helper to construct in-memory ZIP archives."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files.items():
            if isinstance(content, str):
                zf.writestr(filename, content)
            else:
                zf.writestr(filename, content)
    return buf.getvalue()


def test_valid_zip_upload_accepted():
    """Verify that a valid ZIP archive is accepted by POST /api/v1/scans."""
    zip_bytes = create_zip_bytes(
        {
            "src/index.js": "console.log('hello world');\nconst x = 1;",
            "package.json": '{"name": "test-app", "version": "1.0.0"}',
            "README.md": "# Test Project",
        }
    )

    response = client.post(
        "/api/v1/scans",
        files={"file": ("my-vibe-app.zip", zip_bytes, "application/zip")},
    )

    assert response.status_code == 201
    data = response.json()

    assert data["scan_id"].startswith("scan_")
    assert data["status"] in ("pending", "completed")
    assert data["project"] == "my-vibe-app"
    assert data["coverage"]["files_scanned"] == 3
    assert data["coverage"]["rules_evaluated"] >= 0
    assert data["findings"] == []
    assert data["repair_prompt"] is None or isinstance(data["repair_prompt"], str)
    assert len(data["limitations"]) > 0

    # Cleanup staged workspace
    wm = WorkspaceManager()
    wm.cleanup_workspace(data["scan_id"])


def test_invalid_file_type_rejected():
    """Verify non-ZIP uploads are rejected with HTTP 415."""
    response = client.post(
        "/api/v1/scans",
        files={"file": ("malicious.sh", b"#!/bin/bash\necho evil", "text/x-sh")},
    )
    assert response.status_code == 415
    assert "Only .zip archives are accepted" in response.json()["detail"]


def test_malformed_zip_rejected():
    """Verify corrupted ZIP payload is rejected with HTTP 400."""
    response = client.post(
        "/api/v1/scans",
        files={"file": ("corrupt.zip", b"PK\x03\x04corrupted-junk-payload", "application/zip")},
    )
    assert response.status_code == 400
    assert "corrupt" in response.json()["detail"].lower()


def test_empty_zip_upload_rejected():
    """Verify an empty payload is rejected with HTTP 400."""
    response = client.post(
        "/api/v1/scans",
        files={"file": ("empty.zip", b"", "application/zip")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_compressed_upload_size_limit_enforced():
    """Verify that exceeding compressed upload size limit triggers HTTP 413."""
    small_service = IntakeService(max_upload_size=100)

    class FakeUpload:
        filename = "test.zip"
        _data = b"PK\x03\x04" + b"A" * 200
        _offset = 0

        async def read(self, size: int):
            if self._offset >= len(self._data):
                return b""
            chunk = self._data[self._offset : self._offset + size]
            self._offset += len(chunk)
            return chunk

    with pytest.raises(ArchiveLimitError) as exc_info:
        import asyncio

        asyncio.run(small_service.stage_upload(FakeUpload()))

    assert exc_info.value.status_code == 413
    assert "exceeds limit" in exc_info.value.message


def test_archive_entry_count_limit():
    """Verify extractor enforces entry count limit."""
    extractor = SafeExtractor(max_entries=3)
    zip_bytes = create_zip_bytes(
        {
            "f1.txt": "1",
            "f2.txt": "2",
            "f3.txt": "3",
            "f4.txt": "4",
        }
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(ArchiveLimitError) as exc_info:
            extractor.extract(zip_bytes, Path(tmp_dir))
        assert "entry count" in exc_info.value.message.lower()


def test_individual_file_size_limit():
    """Verify extractor rejects single files exceeding individual size limit."""
    extractor = SafeExtractor(max_file_bytes=100)
    zip_bytes = create_zip_bytes({"large.txt": "X" * 250})

    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(ArchiveLimitError) as exc_info:
            extractor.extract(zip_bytes, Path(tmp_dir))
        assert "exceeds limit" in exc_info.value.message


def test_total_uncompressed_size_limit():
    """Verify extractor rejects archives exceeding total uncompressed size limit."""
    extractor = SafeExtractor(max_total_bytes=300)
    zip_bytes = create_zip_bytes(
        {
            "file1.txt": "A" * 150,
            "file2.txt": "B" * 200,
        }
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(ArchiveLimitError) as exc_info:
            extractor.extract(zip_bytes, Path(tmp_dir))
        assert "total uncompressed" in exc_info.value.message.lower()


def test_path_traversal_rejection():
    """Verify Zip Slip path traversal ('../') is detected and rejected."""
    zip_bytes = create_zip_bytes(
        {
            "../../escape.txt": "content",
            "normal.txt": "ok",
        }
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        extractor = SafeExtractor()
        with pytest.raises(SecurityViolationError) as exc_info:
            extractor.extract(zip_bytes, Path(tmp_dir))
        assert "traversal" in exc_info.value.message.lower()


def test_absolute_path_rejection():
    """Verify Unix absolute path is rejected."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("/etc/passwd", "root:x:0:0")

    with tempfile.TemporaryDirectory() as tmp_dir:
        extractor = SafeExtractor()
        with pytest.raises(SecurityViolationError) as exc_info:
            extractor.extract(buf.getvalue(), Path(tmp_dir))
        assert "absolute" in exc_info.value.message.lower()


def test_windows_path_traversal_rejection():
    """Verify Windows backslash traversal and drive letter rejection."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("..\\..\\windows_escape.txt", "payload")

    with tempfile.TemporaryDirectory() as tmp_dir:
        extractor = SafeExtractor()
        with pytest.raises(SecurityViolationError) as exc_info:
            extractor.extract(buf.getvalue(), Path(tmp_dir))
        assert "traversal" in exc_info.value.message.lower()

    # Drive prefix test
    buf2 = io.BytesIO()
    with zipfile.ZipFile(buf2, "w") as zf:
        zf.writestr("C:\\Windows\\win.ini", "config")

    with tempfile.TemporaryDirectory() as tmp_dir:
        with pytest.raises(SecurityViolationError) as exc_info:
            extractor.extract(buf2.getvalue(), Path(tmp_dir))
        assert "drive" in exc_info.value.message.lower()


def test_symlink_rejection():
    """Verify that POSIX symlinks inside archives are rejected."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link_to_passwd")
        # 0o120777 indicates symlink mode in POSIX
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/passwd")

    with tempfile.TemporaryDirectory() as tmp_dir:
        extractor = SafeExtractor()
        with pytest.raises(SecurityViolationError) as exc_info:
            extractor.extract(buf.getvalue(), Path(tmp_dir))
        assert "symlink" in exc_info.value.message.lower()


def test_prohibited_executable_rejection():
    """Verify disallowed executable extensions (.exe, .dll, etc.) are rejected."""
    zip_bytes = create_zip_bytes({"evil.exe": b"\x4d\x5a\x90\x00"})

    with tempfile.TemporaryDirectory() as tmp_dir:
        extractor = SafeExtractor()
        with pytest.raises(UnsupportedFileTypeError) as exc_info:
            extractor.extract(zip_bytes, Path(tmp_dir))
        assert "prohibited" in exc_info.value.message.lower()


def test_no_files_written_outside_workspace():
    """Verify extracted files strictly remain within the workspace boundary."""
    zip_bytes = create_zip_bytes(
        {
            "src/components/Button.jsx": "export default () => <button>Click</button>;",
            "public/index.html": "<!DOCTYPE html><html></html>",
        }
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        root_path = Path(tmp_dir).resolve()
        extractor = SafeExtractor()
        manifest = extractor.extract(zip_bytes, root_path)

        assert manifest.total_files == 2
        for manifest_file in manifest.files:
            file_on_disk = (root_path / manifest_file.relative_path).resolve()
            assert file_on_disk.exists()
            assert file_on_disk.is_relative_to(root_path)


def test_workspace_isolation_between_scans():
    """Verify two independent scans receive unique, non-interfering workspaces."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        wm = WorkspaceManager(base_dir=Path(tmp_dir))

        scan_1, dir_1 = wm.create_workspace()
        scan_2, dir_2 = wm.create_workspace()

        assert scan_1 != scan_2
        assert dir_1 != dir_2
        assert dir_1.parent != dir_2.parent

        # Writing to scan 1 does not affect scan 2
        (dir_1 / "file1.txt").write_text("scan 1 content")
        assert not (dir_2 / "file1.txt").exists()

        wm.cleanup_workspace(scan_1)
        assert not dir_1.exists()
        assert dir_2.exists()

        wm.cleanup_workspace(scan_2)
        assert not dir_2.exists()


def test_cleanup_after_extraction_failure():
    """Verify that an extraction failure cleans up the workspace automatically."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        wm = WorkspaceManager(base_dir=Path(tmp_dir))
        service = IntakeService(workspace_manager=wm)

        # Upload containing path traversal will fail extraction
        bad_zip = create_zip_bytes({"../../escaped.txt": "data"})

        class MockUpload:
            filename = "bad.zip"
            _data = bad_zip
            _pos = 0

            async def read(self, size: int):
                chunk = self._data[self._pos : self._pos + size]
                self._pos += len(chunk)
                return chunk

        with pytest.raises(SecurityViolationError):
            import asyncio

            asyncio.run(service.stage_upload(MockUpload()))

        # Check no scan directories remain in the base directory
        remaining = list(Path(tmp_dir).iterdir())
        assert len(remaining) == 0


def test_source_code_is_never_executed():
    """Verify that uploaded Python code is not executed during intake."""
    canary_file = Path(tempfile.gettempdir()) / "vibeshield_canary_executed.test"
    if canary_file.exists():
        canary_file.unlink()

    code_payload = f"""
import os
with open({repr(str(canary_file))}, 'w') as f:
    f.write('EXPLOIT_EXECUTED')
"""
    zip_bytes = create_zip_bytes({"server.py": code_payload})

    with tempfile.TemporaryDirectory() as tmp_dir:
        extractor = SafeExtractor()
        manifest = extractor.extract(zip_bytes, Path(tmp_dir))
        assert manifest.total_files == 1

        # Assert canary file was never created!
        assert not canary_file.exists(), "Source code was executed during extraction!"


def test_api_errors_do_not_leak_local_paths():
    """Verify API error responses sanitize error details without leaking local absolute host paths."""
    zip_bytes = create_zip_bytes({"../../evil.txt": "content"})

    response = client.post(
        "/api/v1/scans",
        files={"file": ("project.zip", zip_bytes, "application/zip")},
    )

    assert response.status_code == 400
    detail = response.json()["detail"]

    # Must not contain common local host path markers
    assert "c:\\" not in detail.lower()
    assert "/users/" not in detail.lower()
    assert "/home/" not in detail.lower()
    assert "traversal" in detail.lower()
