"""VibeCheck FastAPI application entrypoint."""

from fastapi import FastAPI

from backend.app.api.router import api_router
from backend.app.schemas.health import HealthResponse

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


app.include_router(api_router, prefix="/api/v1")
