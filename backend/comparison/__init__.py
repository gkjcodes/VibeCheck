"""Rescan comparison, verification, and diff engine for VibeCheck Phase 5."""

from backend.app.schemas.comparison import (
    CompareRequest,
    ComparisonFindingItem,
    ComparisonResult,
    ComparisonSummary,
    FindingDisposition,
)
from backend.comparison.comparator import ScanComparator, compare_scans
from backend.comparison.service import ComparisonService
from backend.comparison.store import ScanStore, default_scan_store

__all__ = [
    "ScanComparator",
    "compare_scans",
    "ComparisonResult",
    "ComparisonSummary",
    "ComparisonFindingItem",
    "FindingDisposition",
    "CompareRequest",
    "ComparisonService",
    "ScanStore",
    "default_scan_store",
]
