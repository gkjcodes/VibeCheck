"""API router definition for VibeCheck endpoints."""

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from backend.app.intake.exceptions import IntakeError
from backend.app.intake.service import IntakeService
from backend.app.schemas.scan import ScanCoverage, ScanResponse
from backend.scanners.engine import ScannerEngine, ScannerError

api_router = APIRouter()
intake_service = IntakeService()
scanner_engine = ScannerEngine()


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
    except Exception as exc:
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

    return ScanResponse(
        scan_id=scan_id,
        status="completed",
        project=project_name,
        coverage=coverage,
        findings=findings,
        repair_prompt=None,
        limitations=limitations,
    )
