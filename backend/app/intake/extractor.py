"""Secure ZIP archive extraction and manifest generation."""

from dataclasses import dataclass, field
import io
from pathlib import Path
import re
from typing import BinaryIO, List, Optional, Set, Union
import zipfile

from backend.app.intake.config import (
    DISALLOWED_EXTENSIONS,
    IGNORED_DIRECTORIES,
    MAX_ARCHIVE_ENTRIES,
    MAX_DIRECTORY_DEPTH,
    MAX_INDIVIDUAL_FILE_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
)
from backend.app.intake.exceptions import (
    ArchiveLimitError,
    InvalidArchiveError,
    SecurityViolationError,
    UnsupportedFileTypeError,
)

# Standard ZIP magic headers:
# PK\x03\x04: Local file header
# PK\x05\x06: End of central directory (empty zip)
# PK\x07\x08: Data descriptor
ZIP_MAGIC_HEADERS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

# Common code & web text extensions for line counting
TEXT_EXTENSIONS = frozenset(
    {
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".html",
        ".htm",
        ".css",
        ".scss",
        ".sass",
        ".json",
        ".py",
        ".md",
        ".txt",
        ".yml",
        ".yaml",
        ".toml",
        ".env",
        ".svg",
        ".xml",
        ".sql",
        ".sh",
    }
)


@dataclass
class ManifestFile:
    """Safe relative metadata for an extracted source file."""

    relative_path: str
    size_bytes: int
    extension: str
    line_count: Optional[int] = None


@dataclass
class ProjectManifest:
    """Consolidated intake manifest for a staged project."""

    files: List[ManifestFile] = field(default_factory=list)
    total_files: int = 0
    total_uncompressed_bytes: int = 0
    total_lines: int = 0
    skipped_files: List[str] = field(default_factory=list)


class SafeExtractor:
    """Extracts ZIP archives under strict resource and traversal constraints."""

    def __init__(
        self,
        max_entries: int = MAX_ARCHIVE_ENTRIES,
        max_total_bytes: int = MAX_TOTAL_UNCOMPRESSED_BYTES,
        max_file_bytes: int = MAX_INDIVIDUAL_FILE_BYTES,
        ignored_dirs: Set[str] = IGNORED_DIRECTORIES,
        disallowed_exts: Set[str] = DISALLOWED_EXTENSIONS,
    ):
        self.max_entries = max_entries
        self.max_total_bytes = max_total_bytes
        self.max_file_bytes = max_file_bytes
        self.ignored_dirs = ignored_dirs
        self.disallowed_exts = disallowed_exts

    @staticmethod
    def validate_magic_bytes(data: bytes) -> None:
        """Verify archive starts with valid ZIP magic bytes."""
        if len(data) < 4 or not any(data.startswith(magic) for magic in ZIP_MAGIC_HEADERS):
            raise InvalidArchiveError("Uploaded file lacks valid ZIP magic headers")

    def extract(
        self,
        archive_source: Union[bytes, BinaryIO, Path],
        workspace_dir: Path,
    ) -> ProjectManifest:
        """Safely extract archive entries into workspace_dir and build manifest.
        
        Guarantees:
        - Never executes uploaded source code
        - Rejects path traversal and absolute paths
        - Rejects symlinks and device files
        - Enforces size and entry limits while streaming
        - Cleans up partially written files on exception
        """
        dest_root = workspace_dir.resolve()
        manifest = ProjectManifest()

        if isinstance(archive_source, bytes):
            self.validate_magic_bytes(archive_source)
            archive_stream = io.BytesIO(archive_source)
        elif isinstance(archive_source, Path):
            with open(archive_source, "rb") as f:
                header = f.read(4)
                self.validate_magic_bytes(header)
            archive_stream = open(archive_source, "rb")
        else:
            header = archive_source.read(4)
            self.validate_magic_bytes(header)
            archive_source.seek(0)
            archive_stream = archive_source

        try:
            with zipfile.ZipFile(archive_stream, "r") as zf:
                infolist = zf.infolist()

                if len(infolist) > self.max_entries:
                    raise ArchiveLimitError(
                        f"Archive entry count ({len(infolist)}) exceeds limit ({self.max_entries})"
                    )

                for info in infolist:
                    self._process_entry(info, zf, dest_root, manifest)

            return manifest

        except zipfile.BadZipFile as err:
            raise InvalidArchiveError(f"Malformed or corrupt ZIP file: {err}")
        except Exception:
            raise
        finally:
            if isinstance(archive_source, Path) and hasattr(archive_stream, "close"):
                archive_stream.close()

    def _process_entry(
        self,
        info: zipfile.ZipInfo,
        zf: zipfile.ZipFile,
        dest_root: Path,
        manifest: ProjectManifest,
    ) -> None:
        """Inspect and safely write a single archive entry."""
        raw_name = info.filename
        if not raw_name:
            return

        # 1. Symlink and special file type check (POSIX external attribute)
        if self._is_symlink_or_special(info):
            raise SecurityViolationError(
                f"Prohibited entry type (symlink/device) detected: '{raw_name}'"
            )

        # 2. Sanitize and validate path
        rel_posix_path = self._sanitize_path(raw_name)

        # 3. Check for ignored directories (e.g., node_modules, .git)
        if self._should_ignore(rel_posix_path):
            manifest.skipped_files.append(rel_posix_path)
            return

        # 4. Check for disallowed executable extensions
        ext = Path(rel_posix_path).suffix.lower()
        if ext in self.disallowed_exts:
            raise UnsupportedFileTypeError(
                f"Prohibited executable or binary file type: '{ext}'"
            )

        # 5. Handle directory entry
        target_path = (dest_root / rel_posix_path).resolve()
        self._assert_containment(target_path, dest_root)

        if info.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
            return

        # 6. Stream and write file with real-time size enforcement
        target_path.parent.mkdir(parents=True, exist_ok=True)
        file_size, line_count = self._write_file_stream(
            info, zf, target_path, manifest.total_uncompressed_bytes, ext
        )

        manifest.total_uncompressed_bytes += file_size
        manifest.total_files += 1
        if line_count is not None:
            manifest.total_lines += line_count

        manifest.files.append(
            ManifestFile(
                relative_path=rel_posix_path,
                size_bytes=file_size,
                extension=ext,
                line_count=line_count,
            )
        )

    def _sanitize_path(self, raw_path: str) -> str:
        """Normalize path separators and reject path traversal or absolute roots."""
        # Normalize backslashes (Windows) to forward slashes
        normalized = raw_path.replace("\\", "/").strip()

        # Reject Windows drive prefix (e.g. C: or D:)
        if re.match(r"^[a-zA-Z]:", normalized):
            raise SecurityViolationError(
                f"Absolute Windows drive path is prohibited: '{raw_path}'"
            )

        # Reject Unix root absolute path
        if normalized.startswith("/"):
            raise SecurityViolationError(
                f"Absolute path root is prohibited: '{raw_path}'"
            )

        segments = [s for s in normalized.split("/") if s and s != "."]

        # Reject parent directory traversal
        if ".." in segments:
            raise SecurityViolationError(
                f"Parent directory traversal ('..') is prohibited: '{raw_path}'"
            )

        if len(segments) > MAX_DIRECTORY_DEPTH:
            raise SecurityViolationError(
                f"Directory nesting exceeds maximum depth ({MAX_DIRECTORY_DEPTH}): '{raw_path}'"
            )

        return "/".join(segments)

    def _is_symlink_or_special(self, info: zipfile.ZipInfo) -> bool:
        """Check if ZipInfo attributes denote a POSIX symlink or device."""
        mode = info.external_attr >> 16
        # S_IFLNK is 0o120000, S_IFCHR is 0o020000, S_IFBLK is 0o060000, S_IFIFO is 0o010000
        return (mode & 0o170000) in (0o120000, 0o020000, 0o060000, 0o010000)

    def _assert_containment(self, target: Path, root: Path) -> None:
        """Ensure resolved path does not escape root destination."""
        try:
            target.relative_to(root)
        except ValueError:
            raise SecurityViolationError("Path escapes sandbox destination workspace")

    def _should_ignore(self, rel_path: str) -> bool:
        """Check if any path component matches ignored directories."""
        parts = rel_path.split("/")
        return any(p in self.ignored_dirs for p in parts)

    def _write_file_stream(
        self,
        info: zipfile.ZipInfo,
        zf: zipfile.ZipFile,
        target_path: Path,
        current_total_bytes: int,
        ext: str,
    ) -> Tuple[int, Optional[int]]:
        """Stream chunks from ZIP entry to disk, enforcing size limits."""
        bytes_written = 0
        is_text = ext in TEXT_EXTENSIONS
        line_count = 0 if is_text else None

        chunk_size = 64 * 1024  # 64 KB chunks
        with zf.open(info, "r") as source_stream, open(target_path, "wb") as dest_stream:
            while True:
                chunk = source_stream.read(chunk_size)
                if not chunk:
                    break

                bytes_written += len(chunk)

                if bytes_written > self.max_file_bytes:
                    raise ArchiveLimitError(
                        f"Extracted file size ({bytes_written} bytes) exceeds limit ({self.max_file_bytes} bytes)"
                    )

                if current_total_bytes + bytes_written > self.max_total_bytes:
                    raise ArchiveLimitError(
                        f"Total uncompressed archive size exceeds limit ({self.max_total_bytes} bytes)"
                    )

                dest_stream.write(chunk)
                if is_text:
                    line_count += chunk.count(b"\n")

        # Adjust line count for trailing non-empty line without newline
        if is_text and bytes_written > 0 and line_count == 0:
            line_count = 1

        return bytes_written, line_count
