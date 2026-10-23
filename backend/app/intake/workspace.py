"""Workspace lifecycle manager for isolated scan sandboxes."""

from pathlib import Path
import re
import shutil
from typing import Optional, Tuple
import uuid

from backend.app.intake.config import DEFAULT_WORKSPACE_BASE
from backend.app.intake.exceptions import SecurityViolationError

# Safe scan ID pattern: alphanumeric and underscores/hyphens only
SAFE_SCAN_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")


class WorkspaceManager:
    """Manages creation, containment verification, and cleanup of per-scan workspaces."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = (base_dir or DEFAULT_WORKSPACE_BASE).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def create_workspace(self, scan_id: Optional[str] = None) -> Tuple[str, Path]:
        """Create an isolated workspace directory for a scan.
        
        Returns:
            (scan_id, source_directory_path)
        """
        assigned_id = scan_id or f"scan_{uuid.uuid4().hex[:12]}"
        self._validate_scan_id(assigned_id)

        scan_root = (self.base_dir / assigned_id).resolve()
        self._verify_containment(scan_root)

        source_dir = scan_root / "source"
        source_dir.mkdir(parents=True, exist_ok=True)

        return assigned_id, source_dir

    def get_workspace_path(self, scan_id: str) -> Optional[Path]:
        """Retrieve the source directory for a scan if it exists."""
        self._validate_scan_id(scan_id)
        scan_root = (self.base_dir / scan_id).resolve()
        self._verify_containment(scan_root)

        source_dir = scan_root / "source"
        if source_dir.exists() and source_dir.is_dir():
            return source_dir
        return None

    def cleanup_workspace(self, scan_id: str) -> bool:
        """Safely remove a scan workspace and all staged files."""
        self._validate_scan_id(scan_id)
        scan_root = (self.base_dir / scan_id).resolve()
        self._verify_containment(scan_root)

        if scan_root.exists():
            shutil.rmtree(scan_root, ignore_errors=True)
            return True
        return False

    def _validate_scan_id(self, scan_id: str) -> None:
        """Ensure scan ID does not contain path separators or traversal characters."""
        if not scan_id or not SAFE_SCAN_ID_PATTERN.match(scan_id):
            raise SecurityViolationError("Invalid scan ID format")

    def _verify_containment(self, target_path: Path) -> None:
        """Assert that target_path is strictly within base_dir."""
        try:
            target_path.relative_to(self.base_dir)
        except ValueError:
            raise SecurityViolationError("Workspace path escapes designated base directory")
