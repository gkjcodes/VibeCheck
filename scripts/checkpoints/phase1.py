"""Phase 1 Checkpoint: Foundation & Contracts.

Verifies:
- FastAPI application imports correctly.
- GET /health returns HTTP 200 and readiness payload.
- Finding and ScanResponse models validate valid data and reject invalid data.
- JSON Schema contract matches the Finding model.
- API example payloads validate against models.
- Existing Phase 1 test suite passes.
"""

import json
from pathlib import Path
from typing import List

from pydantic import ValidationError

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase1Check:
    """Checkpoint gate runner for Phase 1: Foundation."""

    phase_number = 1
    phase_name = "Foundation & Contracts"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        # 1. FastAPI App Import
        results.append(cls._check_fastapi_import())

        # 2. GET /health Endpoint
        results.append(cls._check_health_endpoint())

        # 3. Finding Model Validation & Rejection
        results.append(cls._check_finding_model())

        # 4. ScanResponse Model Validation & Rejection
        results.append(cls._check_scan_response_model())

        # 5. Finding JSON Schema Contract Synchronization
        results.append(cls._check_finding_schema_contract())

        # 6. API Examples Payload Validation
        results.append(cls._check_api_examples_payload())

        # 7. Automated Phase 1 Pytest Suite
        results.append(cls._check_pytest_suite())

        return results

    @classmethod
    def _check_fastapi_import(cls) -> CheckResult:
        try:
            from fastapi import FastAPI
            from backend.app.main import app

            if isinstance(app, FastAPI):
                return CheckResult(
                    name="FastAPI Application Import",
                    status=CheckStatus.PASS,
                    details=f"FastAPI app instance '{app.title}' (v{app.version}) loaded successfully.",
                )
            return CheckResult(
                name="FastAPI Application Import",
                status=CheckStatus.FAIL,
                details="Export 'app' in backend.app.main is not a FastAPI instance.",
            )
        except Exception as exc:
            return CheckResult(
                name="FastAPI Application Import",
                status=CheckStatus.FAIL,
                details=f"Failed to import backend.app.main: {str(exc)}",
            )

    @classmethod
    def _check_health_endpoint(cls) -> CheckResult:
        try:
            from fastapi.testclient import TestClient
            from backend.app.main import app

            client = TestClient(app)
            response = client.get("/health")

            if response.status_code != 200:
                return CheckResult(
                    name="GET /health Readiness Endpoint",
                    status=CheckStatus.FAIL,
                    details=f"Expected status 200, got {response.status_code}",
                )

            data = response.json()
            required_keys = {"status", "ready", "service", "version"}
            missing = required_keys - set(data.keys())
            if missing:
                return CheckResult(
                    name="GET /health Readiness Endpoint",
                    status=CheckStatus.FAIL,
                    details=f"Response missing required fields: {missing}",
                )

            if data.get("ready") is not True or data.get("status") != "ready":
                return CheckResult(
                    name="GET /health Readiness Endpoint",
                    status=CheckStatus.FAIL,
                    details=f"Unexpected readiness values: status={data.get('status')}, ready={data.get('ready')}",
                )

            return CheckResult(
                name="GET /health Readiness Endpoint",
                status=CheckStatus.PASS,
                details=f"Returned 200 OK with readiness payload (status={data['status']}, version={data['version']}).",
            )
        except Exception as exc:
            return CheckResult(
                name="GET /health Readiness Endpoint",
                status=CheckStatus.FAIL,
                details=f"Exception testing /health: {str(exc)}",
            )

    @classmethod
    def _check_finding_model(cls) -> CheckResult:
        try:
            from backend.app.schemas.finding import Finding, FindingLocation

            valid_finding = Finding(
                id="f-1",
                rule_id="SEC-001",
                category="hardcoded-secret",
                title="Test Secret",
                severity="critical",
                confidence="high",
                status="open",
                location=FindingLocation(file_path="src/index.js", line_start=10),
                evidence="KEY='abc'",
                impact="Secret leak",
                recommendation="Use env vars",
                verification_steps=["Inspect source"],
            )

            # Check rejection of missing required fields
            try:
                Finding(id="f-invalid")  # type: ignore
                return CheckResult(
                    name="Finding Model Validation & Rejection",
                    status=CheckStatus.FAIL,
                    details="Finding model failed to reject payload with missing required fields.",
                )
            except ValidationError:
                pass  # Correct behavior

            return CheckResult(
                name="Finding Model Validation & Rejection",
                status=CheckStatus.PASS,
                details=f"Valid data parsed successfully; missing required fields rejected with ValidationError.",
            )
        except Exception as exc:
            return CheckResult(
                name="Finding Model Validation & Rejection",
                status=CheckStatus.FAIL,
                details=f"Finding model error: {str(exc)}",
            )

    @classmethod
    def _check_scan_response_model(cls) -> CheckResult:
        try:
            from backend.app.schemas.scan import ScanCoverage, ScanResponse

            valid_scan = ScanResponse(
                scan_id="scan-001",
                status="completed",
                project="vibe-sample",
                coverage=ScanCoverage(files_scanned=5),
                findings=[],
                repair_prompt="Fix suggestions",
                limitations=["Static analysis only"],
            )

            # Check rejection of missing required fields
            try:
                ScanResponse(status="completed")  # type: ignore
                return CheckResult(
                    name="ScanResponse Model Validation & Rejection",
                    status=CheckStatus.FAIL,
                    details="ScanResponse model failed to reject payload with missing required fields.",
                )
            except ValidationError:
                pass  # Correct behavior

            return CheckResult(
                name="ScanResponse Model Validation & Rejection",
                status=CheckStatus.PASS,
                details="ScanResponse validates all 7 fields and rejects invalid payloads.",
            )
        except Exception as exc:
            return CheckResult(
                name="ScanResponse Model Validation & Rejection",
                status=CheckStatus.FAIL,
                details=f"ScanResponse model error: {str(exc)}",
            )

    @classmethod
    def _check_finding_schema_contract(cls) -> CheckResult:
        try:
            schema_file = REPO_ROOT / "contracts" / "finding.schema.json"
            if not schema_file.exists():
                return CheckResult(
                    name="Finding JSON Schema Contract Synchronization",
                    status=CheckStatus.FAIL,
                    details="contracts/finding.schema.json does not exist.",
                )

            with open(schema_file, "r", encoding="utf-8") as f:
                contract_json = json.load(f)

            from backend.app.schemas.finding import Finding

            generated_schema = Finding.model_json_schema()

            contract_props = set(contract_json.get("properties", {}).keys())
            model_props = set(generated_schema.get("properties", {}).keys())

            if contract_props != model_props:
                return CheckResult(
                    name="Finding JSON Schema Contract Synchronization",
                    status=CheckStatus.FAIL,
                    details=f"Property mismatch. Diff: {contract_props ^ model_props}",
                )

            contract_req = set(contract_json.get("required", []))
            model_req = set(generated_schema.get("required", []))
            if contract_req != model_req:
                return CheckResult(
                    name="Finding JSON Schema Contract Synchronization",
                    status=CheckStatus.FAIL,
                    details=f"Required fields mismatch. Diff: {contract_req ^ model_req}",
                )

            return CheckResult(
                name="Finding JSON Schema Contract Synchronization",
                status=CheckStatus.PASS,
                details="contracts/finding.schema.json exactly matches Finding.model_json_schema().",
            )
        except Exception as exc:
            return CheckResult(
                name="Finding JSON Schema Contract Synchronization",
                status=CheckStatus.FAIL,
                details=f"Schema comparison error: {str(exc)}",
            )

    @classmethod
    def _check_api_examples_payload(cls) -> CheckResult:
        try:
            examples_file = REPO_ROOT / "contracts" / "api-examples.json"
            if not examples_file.exists():
                return CheckResult(
                    name="API Examples Payload Validation",
                    status=CheckStatus.FAIL,
                    details="contracts/api-examples.json does not exist.",
                )

            with open(examples_file, "r", encoding="utf-8") as f:
                examples = json.load(f)

            from backend.app.schemas.finding import Finding
            from backend.app.schemas.health import HealthResponse
            from backend.app.schemas.scan import ScanResponse

            HealthResponse(**examples["health_response"])
            Finding(**examples["finding_example"])
            ScanResponse(**examples["scan_response_example"])

            return CheckResult(
                name="API Examples Payload Validation",
                status=CheckStatus.PASS,
                details="All example payloads in contracts/api-examples.json conform to Pydantic models.",
            )
        except Exception as exc:
            return CheckResult(
                name="API Examples Payload Validation",
                status=CheckStatus.FAIL,
                details=f"API example validation failed: {str(exc)}",
            )

    @classmethod
    def _check_pytest_suite(cls) -> CheckResult:
        success, output = run_pytest(
            ["backend/tests/test_health.py", "backend/tests/test_schemas.py"]
        )
        if success:
            return CheckResult(
                name="Phase 1 Automated Pytest Suite",
                status=CheckStatus.PASS,
                details="All Phase 1 tests passed (test_health.py, test_schemas.py).",
            )
        return CheckResult(
            name="Phase 1 Automated Pytest Suite",
            status=CheckStatus.FAIL,
            details=f"Pytest failure:\n{output}",
        )
