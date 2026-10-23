"""Configuration limits and constants for source code intake."""

import os
from pathlib import Path

# Size and entry limits (configurable via environment variables)
# Default max upload: 25 MB
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_MB", "25")) * 1024 * 1024

# Default max archive entries: 500 files
MAX_ARCHIVE_ENTRIES = int(os.getenv("MAX_ARCHIVE_ENTRIES", "500"))

# Default max total uncompressed size: 50 MB
MAX_TOTAL_UNCOMPRESSED_BYTES = (
    int(os.getenv("MAX_TOTAL_UNCOMPRESSED_MB", "50")) * 1024 * 1024
)

# Default max individual extracted file size: 5 MB
MAX_INDIVIDUAL_FILE_BYTES = (
    int(os.getenv("MAX_INDIVIDUAL_FILE_MB", "5")) * 1024 * 1024
)

# Directory traversal & tree depth limits
MAX_DIRECTORY_DEPTH = int(os.getenv("MAX_DIRECTORY_DEPTH", "15"))

# Unnecessary or dangerous directories excluded from extraction
IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".pytest_cache",
        ".idea",
        ".vscode",
        "dist",
        "build",
        ".next",
        ".nuxt",
        ".cache",
    }
)

# Dangerous binary executables disallowed in source archives
DISALLOWED_EXTENSIONS = frozenset(
    {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".elf",
        ".com",
        ".scr",
        ".msi",
        ".apk",
        ".jar",
        ".war",
    }
)

# Default workspace root directory
DEFAULT_WORKSPACE_BASE = (
    Path(os.getenv("VIBESHIELD_WORKSPACE_DIR", "temp_scans"))
    .resolve()
)
