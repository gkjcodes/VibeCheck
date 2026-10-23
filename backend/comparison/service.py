"""Comparison service layer orchestrating rescan ingestion, comparison, and persistence."""

from typing import List, Optional, Tuple
from fastapi import UploadFile

from backend.app.schemas.comparison import ComparisonResult
from backend.app.schemas.scan import ScanResponse
from backend.comparison.comparator import ScanComparator
from backend.comparison.store import ScanStore, default_scan_store


class ComparisonService:
    """High-level service coordinating scan storage, rescan ingestion, and diff analysis."""

    def __init__(
        self,
        comparator: Optional[ScanComparator] = None,
        store: Optional[ScanStore] = None,
    ):
        self.comparator = comparator or ScanComparator()
        self.store = store or default_scan_store

    def compare(
        self,
        baseline_scan: ScanResponse,
        current_scan: ScanResponse,
    ) -> ComparisonResult:
        """Compare two in-memory scan objects and persist the result."""
        result = self.comparator.compare(baseline_scan, current_scan)
        self.store.save_comparison(result)
        return result

    def compare_by_ids(
        self,
        baseline_scan_id: str,
        current_scan_id: str,
    ) -> ComparisonResult:
        """Retrieve two stored scans by ID and perform comparison."""
        baseline = self.store.get_scan(baseline_scan_id)
        if not baseline:
            raise KeyError(f"Baseline scan ID '{baseline_scan_id}' not found in scan store.")

        current = self.store.get_scan(current_scan_id)
        if not current:
            raise KeyError(f"Current scan ID '{current_scan_id}' not found in scan store.")

        return self.compare(baseline, current)

    async def ingest_rescan_and_compare(
        self,
        baseline_scan_id: str,
        upload_file: UploadFile,
        intake_service,
        scanner_engine,
        remediation_service,
    ) -> Tuple[ScanResponse, ComparisonResult]:
        """Stage, scan, remediate, store, and compare a rescan archive against an existing baseline."""
        baseline = self.store.get_scan(baseline_scan_id)
        if not baseline:
            raise KeyError(f"Baseline scan '{baseline_scan_id}' not found in store.")

        # Stage rescan archive
        scan_id, project_name, manifest, source_dir = await intake_service.stage_upload(upload_file)

        try:
            # Execute scanner on rescan
            findings, coverage, limitations = scanner_engine.scan_workspace(source_dir, manifest)

            # Synthesize remediation prompt for any remaining findings
            repair_prompt = remediation_service.generate_repair_prompt(
                project_name=project_name,
                findings=findings,
                coverage=coverage,
                limitations=limitations,
            )

            current_scan = ScanResponse(
                scan_id=scan_id,
                status="completed",
                project=project_name,
                coverage=coverage,
                findings=findings,
                repair_prompt=repair_prompt,
                limitations=limitations,
            )

            # Persist current scan
            self.store.save_scan(current_scan)

            # Run comparison against baseline
            comparison = self.compare(baseline, current_scan)
            return current_scan, comparison
        finally:
            intake_service.workspace_manager.cleanup_workspace(scan_id)

    def get_comparison(self, comparison_id: str) -> Optional[ComparisonResult]:
        """Retrieve stored comparison by ID."""
        return self.store.get_comparison(comparison_id)

    def list_comparisons(self) -> List[ComparisonResult]:
        """List all comparisons."""
        return self.store.list_comparisons()

    def get_scan(self, scan_id: str) -> Optional[ScanResponse]:
        """Retrieve stored scan by ID."""
        return self.store.get_scan(scan_id)

    def list_scans(self) -> List[ScanResponse]:
        """List all stored scans."""
        return self.store.list_scans()


TupleComparison = tuple[ScanResponse, ComparisonResult]
