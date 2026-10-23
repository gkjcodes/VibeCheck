"""Intake service orchestrating archive validation, workspace staging, and manifest creation."""

from pathlib import Path
from typing import Optional, Tuple
from fastapi import UploadFile

from backend.app.intake.config import (
    MAX_ARCHIVE_ENTRIES,
    MAX_INDIVIDUAL_FILE_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    MAX_UPLOAD_SIZE_BYTES,
)
from backend.app.intake.exceptions import (
    ArchiveLimitError,
    InvalidArchiveError,
    UnsupportedFileTypeError,
)
from backend.app.intake.extractor import ProjectManifest, SafeExtractor
from backend.app.intake.workspace import WorkspaceManager


class IntakeService:
    """Coordinates validation, workspace sandboxing, and safe extraction for uploaded source archives."""

    def __init__(
        self,
        workspace_manager: Optional[WorkspaceManager] = None,
        extractor: Optional[SafeExtractor] = None,
        max_upload_size: int = MAX_UPLOAD_SIZE_BYTES,
    ):
        self.workspace_manager = workspace_manager or WorkspaceManager()
        self.extractor = extractor or SafeExtractor(
            max_entries=MAX_ARCHIVE_ENTRIES,
            max_total_bytes=MAX_TOTAL_UNCOMPRESSED_BYTES,
            max_file_bytes=MAX_INDIVIDUAL_FILE_BYTES,
        )
        self.max_upload_size = max_upload_size

    async def stage_upload(
        self, upload_file: UploadFile
    ) -> Tuple[str, str, ProjectManifest, Path]:
        """Validate, stage, and extract an uploaded archive.
        
        Returns:
            (scan_id, project_name, manifest, workspace_source_dir)
        """
        # 1. Validate filename
        filename = upload_file.filename or ""
        if not filename.lower().endswith(".zip"):
            raise UnsupportedFileTypeError(
                f"Unsupported file type for upload: '{filename}'. Only .zip archives are accepted."
            )

        # Derive project identifier from filename
        raw_project_name = Path(filename).stem.strip() or "vibe-project"
        # Sanitize project name
        project_name = "".join(
            c for c in raw_project_name if c.isalnum() or c in ("-", "_", ".")
        )[:64]

        # 2. Read compressed upload in chunks enforcing max_upload_size
        chunk_size = 64 * 1024
        compressed_bytes = bytearray()

        while True:
            chunk = await upload_file.read(chunk_size)
            if not chunk:
                break
            compressed_bytes.extend(chunk)
            if len(compressed_bytes) > self.max_upload_size:
                raise ArchiveLimitError(
                    f"Uploaded archive size ({len(compressed_bytes)} bytes) exceeds limit ({self.max_upload_size} bytes)"
                )

        if len(compressed_bytes) == 0:
            raise InvalidArchiveError("Uploaded archive is empty (0 bytes)")

        # Verify magic bytes
        self.extractor.validate_magic_bytes(bytes(compressed_bytes[:4]))

        # 3. Create isolated workspace
        scan_id, source_dir = self.workspace_manager.create_workspace()

        # 4. Extract securely; cleanup immediately on any error
        try:
            manifest = self.extractor.extract(bytes(compressed_bytes), source_dir)
            return scan_id, project_name, manifest, source_dir
        except Exception:
            self.workspace_manager.cleanup_workspace(scan_id)
            raise
