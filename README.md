# VibeShield

> AI Security Reviewer for Vibe-Coded Websites (12-Hour Prototype)

VibeShield accepts submitted website source code, analyzes it for high-impact security vulnerabilities (such as exposed secrets, permissive CORS configurations, authentication flaws, and client-side credential leaks), generates one consolidated repair prompt for AI coding assistants, and supports submitting corrected code for comparison rescans.

---

## Phase Implementation Status

| Phase | Gate Name | Current Status | Description |
|---|---|---|---|
| **Phase 1** | Foundation & Contracts | **PASSED** | Core schemas, JSON contracts, FastAPI readiness `/health`, baseline tests. |
| **Phase 2** | Secure Source Code Intake | **PLANNED** | ZIP upload, archive safety limits, zip slip/bomb protection, sandboxing. |
| **Phase 3** | Security Scanner Integration | **PLANNED** | AST/regex vulnerability rules, line-grounded evidence, secret redaction. |
| **Phase 4** | Findings & Remediation | **PLANNED** | Deduplication, consolidated AI repair prompt synthesis. |
| **Phase 5** | Rescan Comparison | **PLANNED** | Baseline scan persistence, rescan diffing, state transitions. |
| **Phase 6** | End-to-End MVP | **PLANNED** | Full user journey execution from submission to rescan diff. |
| **Phase 7** | Release Gate | **BLOCKED** | Blocked until prerequisite phases 2 through 6 are implemented and passing. |

Detailed specifications and evidence criteria for each phase can be found in [CHECKPOINTS.md](file:///c:/Users/gopal/VibeCheck/CHECKPOINTS.md).

---

## Phase Checkpoint System

VibeShield includes a persistent checkpoint runner that deterministically evaluates phase gates.

### Running a Phase Gate
```bash
# On Windows (PowerShell / Command Prompt)
py scripts/phase_check.py 1
py scripts/phase_check.py 2
py scripts/phase_check.py 7

# On macOS / Linux
python3 scripts/phase_check.py 1
```

### Checkpoint Result Definitions
- `[PASS]`: Check executed real code/tests and all assertions passed.
- `[FAIL]`: Check ran but encountered an assertion failure, error, or schema mismatch.
- `[NOT IMPLEMENTED]`: Feature, endpoint, scanner, or test fixture is not yet built.

> **Exit Code Policy**: The runner exits with code `0` only when **all** checks in the phase achieve `[PASS]`. If any check fails or is marked `[NOT IMPLEMENTED]`, it exits with code `1` (or `2` for invalid arguments).

### Checkpoint Limitations
- The checkpoint runner tests deterministic local static contracts, behavioral checks, and integration tests.
- It does **not** make live external AI API calls or require internet access for local gates.
- Passing a gate guarantees that the required prototype criteria and safety guards are verified; it does not constitute an absolute mathematical proof of zero vulnerabilities.

---

## Repository Structure

```text
VibeCheck/
├── .env.example              # Environment variables template (no secrets)
├── .gitignore                # Ignores venvs, caches, temporary scan files, logs
├── CHECKPOINTS.md            # Detailed phase gate requirements and criteria
├── pytest.ini                # Pytest configuration with pythonpath
├── requirements.txt          # Python core dependencies
├── README.md                 # Project documentation and setup guide
├── backend/
│   ├── __init__.py
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py           # FastAPI entrypoint with GET /health
│   │   ├── api/              # API router (endpoints mounted here in Phases 2 & 3)
│   │   ├── intake/           # Source archive intake & extraction (Phase 2)
│   │   └── schemas/          # Pydantic models (Finding, ScanResponse, HealthResponse)
│   ├── scanners/             # Heuristic and AST security analyzers (Phase 2/3)
│   ├── remediation/          # Consolidated repair prompt synthesis (Phase 2/4)
│   ├── comparison/           # Initial vs corrected scan comparison (Phase 3/5)
│   └── tests/                # Automated pytest suite
│       ├── test_checkpoint_runner.py # Checkpoint system unit tests
│       ├── test_health.py    # Health endpoint verification
│       └── test_schemas.py   # Schema validation & contract synchronization
├── contracts/
│   ├── finding.schema.json   # Canonical JSON Schema for security findings
│   └── api-examples.json     # Example request/response payloads
├── samples/
│   ├── vulnerable/           # Sample vulnerable website source trees
│   └── corrected/            # Sample corrected website source trees
└── scripts/
    ├── phase_check.py        # Checkpoint CLI entrypoint (Phases 1-7)
    └── checkpoints/          # Modular phase check definitions
```

---

## Getting Started

### Prerequisites
- Python 3.10+ (tested on Python 3.14.5)
- Windows Python Launcher (`py`) or `python3` on PATH

### 1. Environment Setup

Create and activate a virtual environment:

```bash
# On Windows (PowerShell)
py -m venv .venv
.venv\Scripts\Activate.ps1

# On macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Copy the environment template:
```bash
# Windows (PowerShell)
Copy-Item .env.example .env

# macOS / Linux
cp .env.example .env
```

---

## Running the API

Start the FastAPI development server:

```bash
# Windows
py -m uvicorn backend.app.main:app --reload --port 8000

# macOS / Linux
uvicorn backend.app.main:app --reload --port 8000
```

The API will be available at:
- **Health Check**: `http://127.0.0.1:8000/health`
- **Interactive OpenAPI Docs**: `http://127.0.0.1:8000/docs`
- **ReDoc**: `http://127.0.0.1:8000/redoc`

### Verify Health Endpoint
```bash
curl http://127.0.0.1:8000/health
```

Expected response:
```json
{
  "status": "ready",
  "ready": true,
  "service": "VibeShield API",
  "version": "0.1.0"
}
```

---

## Running Automated Tests

Run the complete test suite:

```bash
# Windows
py -m pytest

# macOS / Linux
pytest
```

Run with coverage:
```bash
py -m pytest --cov=backend
```