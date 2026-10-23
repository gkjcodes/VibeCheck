"""API router definition for VibeCheck endpoints."""

import os
from typing import Any, Dict, List
from fastapi import APIRouter, File, HTTPException, UploadFile, status

from backend.app.intake.exceptions import IntakeError
from backend.app.intake.service import IntakeService
from backend.app.schemas.comparison import (
    CompareRequest,
    ComparisonResult,
)
from backend.app.schemas.scan import ScanCoverage, ScanResponse
from backend.comparison.service import ComparisonService
from backend.remediation.generator import RemediationError, RemediationService
from backend.scanners.engine import ScannerEngine, ScannerError

api_router = APIRouter()
intake_service = IntakeService()
scanner_engine = ScannerEngine()
remediation_service = RemediationService()
comparison_service = ComparisonService()


@api_router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and scan website source code for security review",
    tags=["Scans"],
)
async def create_scan(file: UploadFile = File(...)) -> ScanResponse:
    """Accept a ZIP archive, validate safety constraints, stage files, run static security analysis, and return findings."""
    try:
        scan_id, project_name, manifest, source_dir = await intake_service.stage_upload(file)
    except IntakeError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.message,
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during archive intake.",
        )

    # Execute deterministic static security scanner
    try:
        findings, coverage, limitations = scanner_engine.scan_workspace(source_dir, manifest)
    except Exception as scan_err:
        intake_service.workspace_manager.cleanup_workspace(scan_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scanner execution failed: {str(scan_err)}",
        )

    # Synthesize consolidated advisory repair prompt
    try:
        repair_prompt = remediation_service.generate_repair_prompt(
            project_name=project_name,
            findings=findings,
            coverage=coverage,
            limitations=limitations,
        )
    except RemediationError as rem_err:
        intake_service.workspace_manager.cleanup_workspace(scan_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Remediation synthesis failed: {rem_err.sanitized_message}",
        )
    except Exception:
        intake_service.workspace_manager.cleanup_workspace(scan_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during remediation prompt synthesis.",
        )

    scan_response = ScanResponse(
        scan_id=scan_id,
        status="completed",
        project=project_name,
        coverage=coverage,
        findings=findings,
        repair_prompt=repair_prompt,
        limitations=limitations,
    )

    # Store scan in persistent store for comparison
    comparison_service.store.save_scan(scan_response)

    return scan_response


@api_router.get(
    "/scans",
    response_model=List[ScanResponse],
    summary="List all executed scans",
    tags=["Scans"],
)
def list_scans() -> List[ScanResponse]:
    """Retrieve all scans recorded in the local scan store."""
    return comparison_service.list_scans()


@api_router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    summary="Retrieve a specific scan by ID",
    tags=["Scans"],
)
def get_scan(scan_id: str) -> ScanResponse:
    """Retrieve findings, coverage, and remediation prompt for a previously executed scan."""
    try:
        scan = comparison_service.get_scan(scan_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan ID format: '{scan_id}'.",
        )
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )
    return scan


@api_router.post(
    "/scans/{baseline_scan_id}/rescan",
    response_model=ComparisonResult,
    status_code=status.HTTP_200_OK,
    summary="Upload corrected archive and compare against existing baseline scan",
    tags=["Comparison"],
)
async def rescan_and_compare(
    baseline_scan_id: str,
    file: UploadFile = File(...),
) -> ComparisonResult:
    """Upload corrected codebase archive, execute rescan, and compare findings against the baseline scan."""
    try:
        baseline = comparison_service.get_scan(baseline_scan_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan ID format: '{baseline_scan_id}'.",
        )
    if not baseline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline scan ID '{baseline_scan_id}' not found. Cannot perform rescan comparison.",
        )

    try:
        _, comparison = await comparison_service.ingest_rescan_and_compare(
            baseline_scan_id=baseline_scan_id,
            upload_file=file,
            intake_service=intake_service,
            scanner_engine=scanner_engine,
            remediation_service=remediation_service,
        )
        return comparison
    except IntakeError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Rescan comparison execution failed: {str(exc)}",
        )


@api_router.post(
    "/scans/compare",
    response_model=ComparisonResult,
    status_code=status.HTTP_200_OK,
    summary="Compare two scans by ID or direct payload",
    tags=["Comparison"],
)
def compare_scans_endpoint(payload: CompareRequest) -> ComparisonResult:
    """Compare a baseline scan and a rescan to generate finding verification states."""
    if payload.baseline_scan_id and payload.current_scan_id:
        try:
            return comparison_service.compare_by_ids(
                payload.baseline_scan_id, payload.current_scan_id
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Comparison failed: {str(exc)}",
            )

    if payload.baseline_scan and payload.current_scan:
        try:
            return comparison_service.compare(payload.baseline_scan, payload.current_scan)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Comparison failed: {str(exc)}",
            )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Must provide either (baseline_scan_id and current_scan_id) or (baseline_scan and current_scan).",
    )


@api_router.get(
    "/comparisons/{comparison_id}",
    response_model=ComparisonResult,
    summary="Retrieve comparison result by ID",
    tags=["Comparison"],
)
def get_comparison_endpoint(comparison_id: str) -> ComparisonResult:
    """Retrieve previously generated comparison session."""
    try:
        comp = comparison_service.get_comparison(comparison_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid comparison ID format: '{comparison_id}'.",
        )
    if not comp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Comparison with ID '{comparison_id}' not found.",
        )
    return comp


@api_router.get(
    "/comparisons",
    response_model=List[ComparisonResult],
    summary="List all comparisons",
    tags=["Comparison"],
)
def list_comparisons_endpoint() -> List[ComparisonResult]:
    """List all comparison sessions recorded in the local store."""
    return comparison_service.list_comparisons()


@api_router.get(
    "/phases",
    summary="Retrieve current status across all VibeCheck project phases",
    tags=["Dashboard"],
)
def get_phases_status() -> List[Dict[str, Any]]:
    """Return live status, checks, and blockers for Phase 1 through Phase 7."""
    prev_fast = os.environ.get("VIBECHECK_FAST_CHECK")
    os.environ["VIBECHECK_FAST_CHECK"] = "1"
    try:
        from scripts.checkpoints import PHASE_REGISTRY
        from scripts.checkpoints.common import CheckStatus

        phases_data = []
        prereq_failed: Optional[int] = None

        for phase_num in sorted(PHASE_REGISTRY.keys()):
            checker = PHASE_REGISTRY[phase_num]
            if prereq_failed is not None:
                prereq_name = PHASE_REGISTRY[prereq_failed].phase_name
                phases_data.append(
                    {
                        "phase": phase_num,
                        "name": checker.phase_name,
                        "status": "BLOCKED",
                        "reason": f"Blocked by prerequisite Phase {prereq_failed} ({prereq_name})",
                        "checks": [],
                    }
                )
                continue

            try:
                checks = checker.run_all()
                fails = [c for c in checks if c.status == CheckStatus.FAIL]
                not_impls = [c for c in checks if c.status == CheckStatus.NOT_IMPLEMENTED]

                if fails:
                    prereq_failed = phase_num
                    status_str = "FAIL"
                    reason = fails[0].details or fails[0].name
                elif not_impls:
                    prereq_failed = phase_num
                    status_str = "NOT IMPLEMENTED"
                    reason = not_impls[0].details or not_impls[0].name
                else:
                    status_str = "PASS"
                    reason = "All checkpoint checks passed."

                phases_data.append(
                    {
                        "phase": phase_num,
                        "name": checker.phase_name,
                        "status": status_str,
                        "reason": reason,
                        "checks": [
                            {"name": c.name, "status": c.status.name, "details": c.details}
                            for c in checks
                        ],
                    }
                )
            except Exception as exc:
                prereq_failed = phase_num
                phases_data.append(
                    {
                        "phase": phase_num,
                        "name": checker.phase_name,
                        "status": "FAIL",
                        "reason": f"Exception during gate check: {exc}",
                        "checks": [],
                    }
                )

        return phases_data
    except Exception as exc:
        return [
            {
                "phase": i,
                "name": f"Phase {i}",
                "status": "UNKNOWN",
                "reason": f"Could not determine status: {exc}",
                "checks": [],
            }
            for i in range(1, 8)
        ]
    finally:
        if prev_fast is None:
            os.environ.pop("VIBECHECK_FAST_CHECK", None)
        else:
            os.environ["VIBECHECK_FAST_CHECK"] = prev_fast
