"""API router definition for VibeShield endpoints."""

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from backend.app.intake.exceptions import IntakeError
from backend.app.intake.service import IntakeService
from backend.app.schemas.scan import ScanCoverage, ScanResponse

api_router = APIRouter()
intake_service = IntakeService()


@api_router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and stage website source code for security review",
    tags=["Scans"],
)
async def create_scan(file: UploadFile = File(...)) -> ScanResponse:
    """Accept a ZIP archive, validate safety constraints, stage files, and return intake status."""
    try:
        scan_id, project_name, manifest, _ = await intake_service.stage_upload(file)
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

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        project=project_name,
        coverage=ScanCoverage(
            files_scanned=manifest.total_files,
            total_lines=manifest.total_lines,
            rules_evaluated=0,
            skipped_files=manifest.skipped_files,
        ),
        findings=[],
        repair_prompt=None,
        limitations=[
            "Intake complete; source code securely staged in isolated workspace.",
            "Static security scanning is scheduled for Phase 3; no security findings generated yet.",
        ],
    )
