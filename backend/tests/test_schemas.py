"""Automated tests for Pydantic schemas and contract compatibility."""

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from backend.app.schemas.finding import Finding, FindingLocation
from backend.app.schemas.health import HealthResponse
from backend.app.schemas.scan import ScanCoverage, ScanResponse

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def test_finding_schema_validation_success():
    """Verify that a properly structured finding passes validation."""
    finding_data = {
        "id": "finding-001",
        "rule_id": "VIBE-AUTH-001",
        "category": "auth-bypass",
        "title": "Missing JWT Expiration Verification",
        "severity": "high",
        "confidence": "high",
        "status": "open",
        "location": {
            "file_path": "src/auth/jwt.py",
            "line_start": 45,
            "line_end": 48,
            "snippet": "jwt.decode(token, SECRET, options={'verify_exp': False})",
        },
        "evidence": "verify_exp set to False in jwt.decode call",
        "impact": "Allows expired authentication tokens to remain valid indefinitely.",
        "recommendation": "Enable token expiration verification by setting verify_exp to True.",
        "verification_steps": [
            "Ensure verify_exp option is set to True.",
            "Run unit tests with an expired token and assert rejection.",
        ],
    }

    finding = Finding(**finding_data)
    assert finding.id == "finding-001"
    assert finding.rule_id == "VIBE-AUTH-001"
    assert finding.location.file_path == "src/auth/jwt.py"
    assert len(finding.verification_steps) == 2


def test_finding_schema_validation_missing_required_fields():
    """Verify that omitting required fields raises ValidationError."""
    incomplete_data = {
        "id": "finding-002",
        "rule_id": "VIBE-CORS-001",
        # Missing category, title, severity, confidence, location, evidence, impact, recommendation
    }

    with pytest.raises(ValidationError):
        Finding(**incomplete_data)


def test_scan_response_schema_validation():
    """Verify that ScanResponse model correctly structures all 7 required fields."""
    sample_finding = Finding(
        id="f-1",
        rule_id="RULE-1",
        category="secret",
        title="Sample Secret",
        severity="critical",
        confidence="high",
        status="open",
        location=FindingLocation(file_path="env.js", line_start=1),
        evidence="API_KEY=123",
        impact="Leakage of key",
        recommendation="Use env vars",
        verification_steps=["Check env"],
    )

    scan_data = {
        "scan_id": "scan-12345",
        "status": "completed",
        "project": "sample-vibe-project",
        "coverage": {
            "files_scanned": 10,
            "total_lines": 500,
            "rules_evaluated": 15,
            "skipped_files": [],
        },
        "findings": [sample_finding],
        "repair_prompt": "Fix the following issues...",
        "limitations": ["Static analysis only"],
    }

    response = ScanResponse(**scan_data)
    assert response.scan_id == "scan-12345"
    assert response.status == "completed"
    assert response.project == "sample-vibe-project"
    assert response.coverage.files_scanned == 10
    assert len(response.findings) == 1
    assert response.repair_prompt == "Fix the following issues..."
    assert response.limitations == ["Static analysis only"]


def test_contracts_finding_schema_file_matches_pydantic():
    """Verify that contracts/finding.schema.json matches the Pydantic Finding model."""
    schema_path = REPO_ROOT / "contracts" / "finding.schema.json"
    assert schema_path.exists(), f"Schema file not found at {schema_path}"

    with open(schema_path, "r", encoding="utf-8") as f:
        stored_schema = json.load(f)

    generated_schema = Finding.model_json_schema()

    # Compare top-level property keys
    assert set(stored_schema["properties"].keys()) == set(
        generated_schema["properties"].keys()
    )

    # Compare required fields
    assert set(stored_schema["required"]) == set(generated_schema["required"])


def test_contracts_api_examples_validates():
    """Verify that contracts/api-examples.json contains valid data against our schemas."""
    examples_path = REPO_ROOT / "contracts" / "api-examples.json"
    assert examples_path.exists(), f"Examples file not found at {examples_path}"

    with open(examples_path, "r", encoding="utf-8") as f:
        examples = json.load(f)

    # Validate health response example
    health = HealthResponse(**examples["health_response"])
    assert health.status == "ready"

    # Validate finding example
    finding = Finding(**examples["finding_example"])
    assert finding.id == "finding-sec-001"
    assert finding.location.file_path == "src/api/client.js"

    # Validate scan response example
    scan_response = ScanResponse(**examples["scan_response_example"])
    assert scan_response.scan_id == "scan-9f82b7c4"
    assert len(scan_response.findings) == 2
    assert scan_response.coverage.files_scanned == 18
    assert scan_response.repair_prompt is not None
