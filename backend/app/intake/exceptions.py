"""Custom exceptions for source code intake and archive validation."""


class IntakeError(Exception):
    """Base exception for all source code intake errors.
    
    Ensures safe, client-facing error messages that never leak absolute paths.
    """

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class InvalidArchiveError(IntakeError):
    """Raised when an archive is corrupted, truncated, or lacks valid magic bytes."""

    def __init__(self, message: str = "Invalid or corrupted ZIP archive"):
        super().__init__(message, status_code=400)


class UnsupportedFileTypeError(IntakeError):
    """Raised when an uploaded file is not a supported archive or contains disallowed executables."""

    def __init__(self, message: str = "Unsupported archive or file type"):
        super().__init__(message, status_code=415)


class ArchiveLimitError(IntakeError):
    """Raised when an archive exceeds size, entry count, or uncompressed size limits."""

    def __init__(self, message: str = "Archive exceeded configured size or entry limits"):
        super().__init__(message, status_code=413)


class SecurityViolationError(IntakeError):
    """Raised when an archive attempts directory traversal, symlinks, or sandbox escape."""

    def __init__(self, message: str = "Security constraint violation detected in archive"):
        super().__init__(message, status_code=400)
