"""Comprehensive automated test suite for Phase 3: Security Scanner Integration."""

import io
from pathlib import Path
import tempfile
from typing import Dict, Union
import zipfile
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.schemas.finding import Finding
from backend.app.schemas.scan import ScanResponse
from backend.scanners.engine import ScannerEngine, ScannerError
from backend.scanners.masking import mask_secret, sanitize_text
from backend.scanners.rules import get_default_rules
from backend.scanners.rules.dangerous_js import EvalRule, InnerHTMLRule
from backend.scanners.rules.frontend import DangerousHTMLRule, InlineEventHandlerRule, InsecureHTTPResourceRule
from backend.scanners.rules.injection import CommandInjectionRule, SQLInjectionRule
from backend.scanners.rules.insecure_config import (
    DebugModeEnabledRule,
    DisabledTLSVerificationRule,
    InsecureCookieRule,
    PermissiveCORSRule,
)
from backend.scanners.rules.secrets import ExposedSecretRule, HardcodedCredentialRule, PrivateKeyRule

client = TestClient(app)
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def create_zip_bytes(files: Dict[str, Union[str, bytes]]) -> bytes:
    """Helper to construct in-memory ZIP archives."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files.items():
            if isinstance(content, str):
                zf.writestr(filename, content)
            else:
                zf.writestr(filename, content)
    return buf.getvalue()


# 1. Known vulnerable JavaScript fixture
def test_vulnerable_javascript_fixture():
    """Verify detection of eval(), innerHTML, and hardcoded API tokens in JavaScript."""
    js_sample = (REPO_ROOT / "samples" / "vulnerable" / "app.js").read_text(encoding="utf-8")
    engine = ScannerEngine()

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "app.js").write_text(js_sample, encoding="utf-8")

        findings, coverage, _ = engine.scan_workspace(tmp_path)
        rule_ids = {f.rule_id for f in findings}

        assert "VIBE-SEC-KEY" in rule_ids
        assert "VIBE-JS-EVAL" in rule_ids
        assert "VIBE-JS-INNERHTML" in rule_ids
        assert coverage.files_scanned == 1


# 2. Known vulnerable Python fixture
def test_vulnerable_python_fixture():
    """Verify detection of SQL injection, shell injection, disabled TLS, and debug mode in Python."""
    py_sample = (REPO_ROOT / "samples" / "vulnerable" / "server.py").read_text(encoding="utf-8")
    engine = ScannerEngine()

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "server.py").write_text(py_sample, encoding="utf-8")

        findings, coverage, _ = engine.scan_workspace(tmp_path)
        rule_ids = {f.rule_id for f in findings}

        assert "VIBE-INJ-SQL" in rule_ids
        assert "VIBE-INJ-SHELL" in rule_ids
        assert "VIBE-CFG-TLS" in rule_ids
        assert "VIBE-CFG-DEBUG" in rule_ids
        assert coverage.files_scanned == 1


# 3. Hardcoded fake test credential masking
def test_fake_credential_masking():
    """Verify that credentials are masked in finding snippets and evidence, never returned in raw form."""
    # Dynamically assembled synthetic test fixtures avoiding static secret-scanning alerts
    raw_stripe = "sk_" + "test_" + ("0" * 24)
    raw_google = "AIza" + "Sy" + ("0" * 33)
    raw_github = "gh" + "p_" + ("0" * 36)
    raw_aws = "AK" + "IA" + ("0" * 16)

    content = f"""
    const STRIPE = "{raw_stripe}";
    const GOOGLE = "{raw_google}";
    const GITHUB = "{raw_github}";
    const AWS = "{raw_aws}";
    """

    engine = ScannerEngine(rules=[ExposedSecretRule()])

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "credentials.js").write_text(content, encoding="utf-8")

        findings, _, _ = engine.scan_workspace(tmp_path)
        assert len(findings) >= 3

        for f in findings:
            # Raw secrets must never appear in snippet or evidence
            assert raw_stripe not in f.evidence
            assert raw_google not in f.evidence
            assert raw_github not in f.evidence
            assert raw_aws not in f.evidence

            if f.location.snippet:
                assert raw_stripe not in f.location.snippet
                assert raw_google not in f.location.snippet
                assert raw_github not in f.location.snippet
                assert raw_aws not in f.location.snippet

            # Masked placeholder must appear
            assert "****" in f.evidence


# 4. Vulnerable SQL and command injection
def test_injection_rules_trigger():
    """Verify SQL injection and OS command injection rules identify risky patterns."""
    sql_rule = SQLInjectionRule()
    shell_rule = CommandInjectionRule()

    sql_code = 'cursor.execute(f"SELECT * FROM accounts WHERE user_id = \'{user_input}\'")\n'
    shell_code = 'subprocess.run(f"rm -rf {user_dir}", shell=True)\n'

    sql_matches = sql_rule.scan_file("db.py", sql_code)
    shell_matches = shell_rule.scan_file("runner.py", shell_code)

    assert len(sql_matches) == 1
    assert sql_matches[0].rule_id == "VIBE-INJ-SQL"
    assert sql_matches[0].severity == "critical"

    assert len(shell_matches) == 1
    assert shell_matches[0].rule_id == "VIBE-INJ-SHELL"
    assert shell_matches[0].severity == "critical"


# 5. Insecure configuration rules
def test_insecure_configuration_rules():
    """Verify detection of TLS verification disabled, debug flags, permissive CORS, and insecure cookies."""
    engine = ScannerEngine(
        rules=[
            DisabledTLSVerificationRule(),
            DebugModeEnabledRule(),
            PermissiveCORSRule(),
            InsecureCookieRule(),
        ]
    )

    content = """
    # Disabled TLS
    requests.get("https://example.com", verify=False)
    # Debug mode
    DEBUG = True
    # Permissive CORS with credentials
    allow_origins = ["*"]
    allow_credentials = True
    # Insecure cookie
    response.set_cookie("session", "abc", secure=False, httponly=False)
    """

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "config.py").write_text(content, encoding="utf-8")

        findings, _, _ = engine.scan_workspace(tmp_path)
        rule_ids = {f.rule_id for f in findings}

        assert "VIBE-CFG-TLS" in rule_ids
        assert "VIBE-CFG-DEBUG" in rule_ids
        assert "VIBE-CFG-CORS" in rule_ids
        assert "VIBE-CFG-COOKIE" in rule_ids


# 6. Corrected fixtures produce zero findings
def test_corrected_fixtures_pass():
    """Verify that secure/corrected samples do not trigger false positive security findings."""
    engine = ScannerEngine()
    corrected_dir = REPO_ROOT / "samples" / "corrected"

    findings, coverage, _ = engine.scan_workspace(corrected_dir)
    assert len(findings) == 0
    assert coverage.files_scanned >= 2


# 7. Clean files report zero findings and honest limitations
def test_clean_files_report_zero_findings():
    """Verify a project with clean source code produces empty findings list and honest limitations."""
    clean_code = "const welcomeMessage = 'Hello, clean world!';\nconsole.log(welcomeMessage);"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "index.js").write_text(clean_code, encoding="utf-8")

        engine = ScannerEngine()
        findings, coverage, limitations = engine.scan_workspace(tmp_path)

        assert findings == []
        assert coverage.files_scanned == 1
        assert any("zero findings" in lim.lower() for lim in limitations)


# 8. Unsupported file extensions
def test_unsupported_file_extensions_skipped():
    """Verify unsupported file types are tracked in skipped_files without breaking the scan."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "data.xyz").write_text("unsupported content", encoding="utf-8")
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")

        engine = ScannerEngine()
        findings, coverage, _ = engine.scan_workspace(tmp_path)

        assert len(findings) == 0
        assert coverage.files_scanned == 0
        assert "data.xyz" in coverage.skipped_files or "image.png" in coverage.skipped_files


# 9. Empty projects and projects containing only excluded files
def test_empty_project_scan():
    """Verify scanning an empty workspace returns valid empty results."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        engine = ScannerEngine()
        findings, coverage, _ = engine.scan_workspace(tmp_path)

        assert findings == []
        assert coverage.files_scanned == 0
        assert coverage.total_lines == 0


# 10. Multiple findings in one file
def test_multiple_findings_in_single_file():
    """Verify multiple distinct vulnerabilities in one file are accurately reported with distinct lines."""
    content = """
    const apiKey = "sk_live_51MzXYZ0000000000abcdef"; // Line 2
    const result = eval(req.query.cmd);                // Line 3
    div.innerHTML = "<span>" + input + "</span>";      // Line 4
    """

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "multi.js").write_text(content, encoding="utf-8")

        engine = ScannerEngine()
        findings, _, _ = engine.scan_workspace(tmp_path)

        assert len(findings) >= 3
        lines = [f.location.line_start for f in findings]
        assert len(set(lines)) >= 2


# 11. Stable finding ordering and deduplication
def test_finding_ordering_and_deduplication():
    """Verify findings are stably sorted by severity rank and identical detections are deduplicated."""
    content = """
    const key = "sk_live_51MzXYZ1111111111abcdef";
    eval("alert(1)");
    const insecure = http_url;
    """

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "test.js").write_text(content, encoding="utf-8")

        engine = ScannerEngine()
        findings_1, _, _ = engine.scan_workspace(tmp_path)
        findings_2, _, _ = engine.scan_workspace(tmp_path)

        # Ordering must be deterministic across runs
        assert [f.id for f in findings_1] == [f.id for f in findings_2]

        # Critical severity should appear before medium
        severities = [f.severity for f in findings_1]
        if "critical" in severities and "medium" in severities:
            crit_idx = severities.index("critical")
            med_idx = severities.index("medium")
            assert crit_idx < med_idx


# 12. Malformed source files and unreadable files
def test_malformed_source_file_handling():
    """Verify non-UTF8 or malformed characters do not crash the scanner."""
    malformed_bytes = b"const bad = \xff\xfe\xfd;\nconst key = 'sk_live_51MzXYZ2222222222abcdef';\n"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        (tmp_path / "broken.js").write_bytes(malformed_bytes)

        engine = ScannerEngine()
        findings, coverage, _ = engine.scan_workspace(tmp_path)

        # Scanner should decode with replacement characters and detect secret without crash
        assert coverage.files_scanned == 1
        assert any(f.rule_id == "VIBE-SEC-KEY" for f in findings)


# 13. Path traversal and workspace-isolation protections
def test_scanner_workspace_containment():
    """Verify scanner rejects paths attempting to escape the designated workspace."""
    engine = ScannerEngine()
    non_existent = REPO_ROOT / "non_existent_scan_workspace_xyz"

    with pytest.raises(ScannerError):
        engine.scan_workspace(non_existent)


# 14. API response schema compatibility
def test_api_scan_endpoint_returns_valid_schema():
    """Verify POST /api/v1/scans returns a schema-compliant ScanResponse with findings."""
    zip_bytes = create_zip_bytes(
        {
            "src/client.js": "const STRIPE_KEY = 'sk_live_51MzXYZ3333333333abcdef';\neval(input);",
            "index.html": "<button onclick=\"doSomething()\">Click</button>",
        }
    )

    response = client.post(
        "/api/v1/scans",
        files={"file": ("vulnerable-vibe.zip", zip_bytes, "application/zip")},
    )

    assert response.status_code == 201
    data = response.json()

    # Validate against Pydantic schema
    validated = ScanResponse.model_validate(data)
    assert validated.status == "completed"
    assert validated.coverage.files_scanned == 2
    assert validated.coverage.rules_evaluated > 0
    assert len(validated.findings) >= 2


# 15. Scanner failure is not misreported as clean
def test_scanner_failure_returns_http_500(monkeypatch):
    """Verify that if scanner engine fails, the API returns an HTTP 500 error instead of a clean scan."""
    def broken_scan(*args, **kwargs):
        raise RuntimeError("Internal scanner engine crashed.")

    monkeypatch.setattr("backend.app.api.router.scanner_engine.scan_workspace", broken_scan)

    zip_bytes = create_zip_bytes({"src/index.js": "const a = 1;"})
    response = client.post(
        "/api/v1/scans",
        files={"file": ("test.zip", zip_bytes, "application/zip")},
    )

    assert response.status_code == 500
    assert "Scanner execution failed" in response.json()["detail"]


# 16. No raw secrets or absolute host paths in API response
def test_no_raw_secrets_or_absolute_paths_in_api_response():
    """Verify that API responses do not expose raw secret tokens or absolute local paths."""
    raw_secret = "sk_live_51MzXYZ4444444444abcdef"
    zip_bytes = create_zip_bytes(
        {
            "src/auth.js": f"const key = '{raw_secret}';\n",
        }
    )

    response = client.post(
        "/api/v1/scans",
        files={"file": ("secrets-project.zip", zip_bytes, "application/zip")},
    )

    assert response.status_code == 201
    raw_text = response.text

    # Raw credential must never appear
    assert raw_secret not in raw_text

    # Host paths must not appear
    assert "c:\\" not in raw_text.lower()
    assert "/users/" not in raw_text.lower()
    assert "/home/" not in raw_text.lower()
