"""Automated tests for the /health endpoint."""

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.health import HealthResponse

client = TestClient(app)


def test_health_endpoint_returns_ok():
    """Verify that GET /health returns 200 and readiness payload."""
    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ready"
    assert data["ready"] is True
    assert data["service"] == "VibeShield API"
    assert data["version"] == "0.1.0"

    # Ensure response conforms to the Pydantic schema
    validated = HealthResponse(**data)
    assert validated.ready is True
