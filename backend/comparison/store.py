"""Scan and comparison storage module for VibeCheck Phase 5."""

import json
from pathlib import Path
import re
import threading
from typing import Dict, List, Optional

from backend.app.intake.config import DEFAULT_WORKSPACE_BASE
from backend.app.schemas.comparison import ComparisonResult
from backend.app.schemas.scan import ScanResponse

SAFE_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


class ScanStore:
    """Thread-safe in-memory and file-backed storage for scans and comparison sessions."""

    def __init__(self, storage_dir: Optional[Path] = None):
        self._lock = threading.RLock()
        self._scans: Dict[str, ScanResponse] = {}
        self._comparisons: Dict[str, ComparisonResult] = {}
        self.storage_dir = (storage_dir or (DEFAULT_WORKSPACE_BASE / ".store")).resolve()
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
            self._scans_dir = self.storage_dir / "scans"
            self._scans_dir.mkdir(parents=True, exist_ok=True)
            self._comps_dir = self.storage_dir / "comparisons"
            self._comps_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            # Fallback to pure in-memory if directory creation fails
            self._scans_dir = None
            self._comps_dir = None

    def _validate_id(self, identifier: str) -> str:
        if not identifier or not isinstance(identifier, str):
            raise ValueError("Identifier must be a non-empty string.")
        clean_id = identifier.strip()
        if not SAFE_ID_REGEX.match(clean_id) or ".." in clean_id:
            raise ValueError(f"Invalid identifier format: '{clean_id}'.")
        return clean_id

    def save_scan(self, scan: ScanResponse) -> None:
        """Persist a scan response by its scan_id."""
        if not isinstance(scan, ScanResponse):
            raise TypeError("Expected ScanResponse instance.")
        scan_id = self._validate_id(scan.scan_id)
        with self._lock:
            self._scans[scan_id] = scan
            if self._scans_dir:
                try:
                    file_path = self._scans_dir / f"{scan_id}.json"
                    file_path.write_text(scan.model_dump_json(indent=2), encoding="utf-8")
                except Exception:
                    pass

    def get_scan(self, scan_id: str) -> Optional[ScanResponse]:
        """Retrieve a stored scan response by its scan_id."""
        clean_id = self._validate_id(scan_id)
        with self._lock:
            if clean_id in self._scans:
                return self._scans[clean_id]

            if self._scans_dir:
                file_path = self._scans_dir / f"{clean_id}.json"
                if file_path.exists() and file_path.is_file():
                    try:
                        data = json.loads(file_path.read_text(encoding="utf-8"))
                        scan = ScanResponse(**data)
                        self._scans[clean_id] = scan
                        return scan
                    except Exception:
                        return None
            return None

    def list_scans(self) -> List[ScanResponse]:
        """List all stored scan responses."""
        with self._lock:
            # Load any un-cached files from disk
            if self._scans_dir and self._scans_dir.exists():
                for p in self._scans_dir.glob("*.json"):
                    sid = p.stem
                    if sid not in self._scans:
                        try:
                            data = json.loads(p.read_text(encoding="utf-8"))
                            self._scans[sid] = ScanResponse(**data)
                        except Exception:
                            pass
            return list(self._scans.values())

    def save_comparison(self, comparison: ComparisonResult) -> None:
        """Persist a comparison result by its comparison_id."""
        if not isinstance(comparison, ComparisonResult):
            raise TypeError("Expected ComparisonResult instance.")
        comp_id = self._validate_id(comparison.comparison_id)
        with self._lock:
            self._comparisons[comp_id] = comparison
            if self._comps_dir:
                try:
                    file_path = self._comps_dir / f"{comp_id}.json"
                    file_path.write_text(comparison.model_dump_json(indent=2), encoding="utf-8")
                except Exception:
                    pass

    def get_comparison(self, comparison_id: str) -> Optional[ComparisonResult]:
        """Retrieve a stored comparison result by its comparison_id."""
        clean_id = self._validate_id(comparison_id)
        with self._lock:
            if clean_id in self._comparisons:
                return self._comparisons[clean_id]

            if self._comps_dir:
                file_path = self._comps_dir / f"{clean_id}.json"
                if file_path.exists() and file_path.is_file():
                    try:
                        data = json.loads(file_path.read_text(encoding="utf-8"))
                        comp = ComparisonResult(**data)
                        self._comparisons[clean_id] = comp
                        return comp
                    except Exception:
                        return None
            return None

    def list_comparisons(self) -> List[ComparisonResult]:
        """List all stored comparison results."""
        with self._lock:
            if self._comps_dir and self._comps_dir.exists():
                for p in self._comps_dir.glob("*.json"):
                    cid = p.stem
                    if cid not in self._comparisons:
                        try:
                            data = json.loads(p.read_text(encoding="utf-8"))
                            self._comparisons[cid] = ComparisonResult(**data)
                        except Exception:
                            pass
            return list(self._comparisons.values())

    def clear(self) -> None:
        """Clear in-memory and cached file storage (useful for tests)."""
        with self._lock:
            self._scans.clear()
            self._comparisons.clear()
            if self._scans_dir and self._scans_dir.exists():
                for p in self._scans_dir.glob("*.json"):
                    try:
                        p.unlink()
                    except Exception:
                        pass
            if self._comps_dir and self._comps_dir.exists():
                for p in self._comps_dir.glob("*.json"):
                    try:
                        p.unlink()
                    except Exception:
                        pass


# Default singleton instance for application use
default_scan_store = ScanStore()
