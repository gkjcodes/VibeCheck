# VibeShield

> AI Security Reviewer for Vibe-Coded Websites (12-Hour Prototype)

VibeShield accepts submitted website source code, analyzes it for high-impact security vulnerabilities (such as exposed secrets, permissive CORS configurations, authentication flaws, and client-side credential leaks), generates one consolidated repair prompt for AI coding assistants, and supports submitting corrected code for comparison rescans.

---

## Phase Implementation Status

| Phase | Gate Name | Current Status | Description |
|---|---|---|---|
| **Phase 1** | Foundation & Contracts | **PASSED** | Core schemas, JSON contracts, FastAPI readiness `/health`, baseline tests. |
| **Phase 2** | Secure Source Code Intake | **PASSED** | ZIP upload endpoint (`POST /api/v1/scans`), archive safety limits, zip slip/bomb protection, sandboxed staging, manifest generation. |
| **Phase 3** | Security Scanner Integration | **PLANNED** (Next) | AST/regex vulnerability rules, line-grounded evidence, secret redaction. |
| **Phase 4** | Findings & Remediation | **BLOCKED** | Deduplication, consolidated AI repair prompt synthesis (requires Phase 3). |
| **Phase 5** | Rescan Comparison | **BLOCKED** | Baseline scan persistence, rescan diffing, state transitions (requires Phase 3). |
| **Phase 6** | End-to-End MVP | **BLOCKED** | Full user journey execution from submission to rescan diff (requires Phase 3). |
| **Phase 7** | Release Gate | **BLOCKED** | Release qualification audit (requires Phases 3–6). |

Detailed specifications, criteria, and evidence for every phase are documented in [CHECKPOINTS.md](file:///c:/Users/gopal/VibeCheck/CHECKPOINTS.md).

---

## Phase Checkpoint & Dashboard CLI

VibeShield includes a persistent checkpoint runner that deterministically evaluates individual phase gates or renders a unified status dashboard across all seven phases.

### 1. View All-Phase Status Dashboard
Run with no arguments or `--all`:
```bash
# Windows
py scripts/phase_check.py
# or
py scripts/phase_check.py --all

# macOS / Linux
python3 scripts/phase_check.py --all
```

### 2. Run Individual Phase Gate Checks
```bash
# Windows
py scripts/phase_check.py 1   # Verify Phase 1 (Foundation)
py scripts/phase_check.py 2   # Verify Phase 2 (Secure Intake)
py scripts/phase_check.py 3   # Verify Phase 3 (Scanner Integration)

# macOS / Linux
python3 scripts/phase_check.py 2
```

### Checkpoint Result Definitions
- `[PASS]`: Check executed real code or automated tests, and all assertions passed.
- `[FAIL]`: Check ran but encountered an assertion failure, error, or schema mismatch.
- `[NOT IMPLEMENTED]`: Feature, endpoint, scanner, or test fixture is not yet built.
- `[BLOCKED]`: Prerequisite phases are not passing, so this phase cannot yet be considered ready.

> **Exit Code Policy**:
> - Individual gate (`scripts/phase_check.py <n>`): Exits with `0` only if **every** check in that phase passes; exits with `1` otherwise.
> - Dashboard (`scripts/phase_check.py` or `--all`): Exits with `0` only when all 7 phases have passed; exits with `1` while development is in progress.
> - Invalid arguments: Exits with `2` and displays usage.

### Checkpoint Limitations
- Checkpoints test deterministic local contracts, behavioral assertions, and integration tests.
- Local tests do **not** make live external AI API calls or require internet access.
- Passing a gate guarantees that the prototype criteria and safety guards are verified; it does not constitute an absolute mathematical proof of zero vulnerabilities.

---

## Phase 2: Source Code Intake API

Phase 2 introduces the secure staging endpoint for website archives:

### Endpoint
- **URL**: `POST /api/v1/scans`
- **Content-Type**: `multipart/form-data`
- **Field**: `file: UploadFile` (must be a valid `.zip` file)
- **Response**: `201 Created` with `ScanResponse` JSON payload

### Safety Controls & Configurable Limits
- **Compressed Upload Size**: Default max 25 MB (`MAX_UPLOAD_SIZE_MB`)
- **Archive Entry Count**: Default max 500 entries (`MAX_ARCHIVE_ENTRIES`)
- **Total Uncompressed Size**: Default max 50 MB (`MAX_TOTAL_UNCOMPRESSED_MB`)
- **Individual Extracted File Size**: Default max 5 MB (`MAX_INDIVIDUAL_FILE_MB`)
- **Directory Traversal Protection**: Rejects `../`, absolute paths (`/`), and Windows drive paths (`C:`)
- **Prohibited Special Files**: Rejects POSIX symlinks, FIFOs, and device nodes
- **Disallowed Executables**: Rejects binary executables (`.exe`, `.dll`, `.so`, `.bin`, `.elf`, etc.)
- **Excluded Directories**: Automatically ignores `.git`, `node_modules`, `.venv`, `__pycache__`, etc.
- **Isolated Sandboxing**: Each scan receives a unique directory (`temp_scans/<scan_id>/source`)
- **Automatic Failure Cleanup**: Any upload or extraction error wipes the workspace immediately
- **Non-Execution Guarantee**: Uploaded source code is never executed, imported, or installed

### Example Upload
```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -F "file=@sample-site.zip"
```

Response:
```json
{
  "scan_id": "scan_84532e36dd9f",
  "status": "pending",
  "project": "sample-site",
  "coverage": {
    "files_scanned": 12,
    "total_lines": 850,
    "rules_evaluated": 0,
    "skipped_files": []
  },
  "findings": [],
  "repair_prompt": null,
  "limitations": [
    "Intake complete; source code securely staged in isolated workspace.",
    "Static security scanning is scheduled for Phase 3; no security findings generated yet."
  ]
}
```

---

## Git Milestone Tagging Workflow

To track stable phase completions in Git:
1. Run the phase checkpoint: `py scripts/phase_check.py <n>`
2. Ensure all checks achieve `[PASS]`.
3. Run the all-phase dashboard: `py scripts/phase_check.py --all`
4. Stage and commit changes:
   ```bash
   git add .
   git commit -m "feat(phase-N): implement Phase N"
   ```
5. Create and push the milestone tag:
   ```bash
   git tag -a v0.2.0-phase-2 -m "Phase 2: Secure source code intake"
   git push origin v0.2.0-phase-2
   ```

### Milestone Versions
- Phase 1: `v0.1.0-phase-1`
- Phase 2: `v0.2.0-phase-2`
- Phase 3: `v0.3.0-phase-3`
- Phase 4: `v0.4.0-phase-4`
- Phase 5: `v0.5.0-phase-5`
- Phase 6: `v0.6.0-phase-6`
- Phase 7: `v1.0.0`

> **Important**: Git tags mark specific commits in history; they do not independently prove that software works. Tags must only be created after verifying passing checkpoint tests.

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
- **Intake Upload**: `http://127.0.0.1:8000/api/v1/scans`
- **Interactive OpenAPI Docs**: `http://127.0.0.1:8000/docs`
- **ReDoc**: `http://127.0.0.1:8000/redoc`

---

## Running Automated Tests

Run the complete test suite:

```bash
# Windows
py -m pytest

# macOS / Linux
pytest
```

Run with coverage reporting:
```bash
py -m pytest --cov=backend
```