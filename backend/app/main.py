"""VibeCheck FastAPI application entrypoint."""

from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.app.api.router import api_router
from backend.app.schemas.health import HealthResponse

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

app = FastAPI(
    title="VibeCheck API",
    description="AI Security Reviewer for Vibe-Coded Websites",
    version="0.1.0",
)


@app.get("/health", response_model=HealthResponse, tags=["Health"])
def get_health() -> HealthResponse:
    """Readiness probe returning service status and readiness metadata."""
    return HealthResponse(
        status="ready",
        ready=True,
        service="VibeCheck API",
        version="0.1.0",
    )


@app.get("/", tags=["Dashboard"])
def serve_dashboard():
    """Serve the VibeCheck interactive developer dashboard."""
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "VibeCheck API operational. Frontend not found."}


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

app.include_router(api_router, prefix="/api/v1")
