"""Source code intake and extraction package for VibeShield."""

from backend.app.intake.config import (
    DEFAULT_WORKSPACE_BASE,
    DISALLOWED_EXTENSIONS,
    IGNORED_DIRECTORIES,
    MAX_ARCHIVE_ENTRIES,
    MAX_INDIVIDUAL_FILE_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
    MAX_UPLOAD_SIZE_BYTES,
)
from backend.app.intake.exceptions import (
    ArchiveLimitError,
    IntakeError,
    InvalidArchiveError,
    SecurityViolationError,
    UnsupportedFileTypeError,
)
from backend.app.intake.extractor import (
    ManifestFile,
    ProjectManifest,
    SafeExtractor,
)
from backend.app.intake.service import IntakeService
from backend.app.intake.workspace import WorkspaceManager

# Standalone convenience helper functions for validation and extraction
_default_service = IntakeService()
_default_extractor = SafeExtractor()


def validate_archive(data: bytes) -> None:
    """Validate archive magic bytes and basic integrity."""
    SafeExtractor.validate_magic_bytes(data)


def extract_archive(archive_data: bytes, dest_dir) -> ProjectManifest:
    """Safely extract archive data into destination directory."""
    return _default_extractor.extract(archive_data, dest_dir)


def extract_zip_safe(archive_data: bytes, dest_dir) -> ProjectManifest:
    """Alias for extract_archive."""
    return extract_archive(archive_data, dest_dir)


__all__ = [
    "ArchiveLimitError",
    "DEFAULT_WORKSPACE_BASE",
    "DISALLOWED_EXTENSIONS",
    "IGNORED_DIRECTORIES",
    "IntakeError",
    "IntakeService",
    "InvalidArchiveError",
    "MAX_ARCHIVE_ENTRIES",
    "MAX_INDIVIDUAL_FILE_BYTES",
    "MAX_TOTAL_UNCOMPRESSED_BYTES",
    "MAX_UPLOAD_SIZE_BYTES",
    "ManifestFile",
    "ProjectManifest",
    "SafeExtractor",
    "SecurityViolationError",
    "UnsupportedFileTypeError",
    "WorkspaceManager",
    "extract_archive",
    "extract_zip_safe",
    "validate_archive",
]
