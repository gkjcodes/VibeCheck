"""Health check response schema."""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Readiness response model returned by GET /health."""

    status: str = Field(
        default="ready",
        description="Service operational status (e.g., 'ready', 'healthy')",
    )
    ready: bool = Field(
        default=True,
        description="Boolean readiness indicator for health probes",
    )
    service: str = Field(
        default="VibeCheck API",
        description="Name of the backend service",
    )
    version: str = Field(
        default="0.1.0",
        description="Current service version",
    )
