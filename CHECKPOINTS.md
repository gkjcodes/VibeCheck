# VibeShield Phase Checkpoint System

This document outlines the requirements, gate criteria, and expected verification evidence for each of the seven development phases of **VibeShield**.

The checkpoint runner (`scripts/phase_check.py`) enforces strict, deterministic verification at every phase boundary.

---

## Checkpoint Result Definitions

| Status | Meaning |
|---|---|
| `[PASS]` | The check executed real code or automated tests, and all assertions passed. |
| `[FAIL]` | The feature or test executed, but encountered an assertion failure, schema violation, or unhandled exception. |
| `[NOT IMPLEMENTED]` | The required endpoint, scanner module, or test fixture has not yet been implemented. |
| `[BLOCKED]` | Prerequisite phases are not passing, so this phase cannot yet be considered ready. |

> **Gate Rule**: A phase gate exits with `0` **only** when every check for that phase achieves `[PASS]`. If any check fails or is marked `[NOT IMPLEMENTED]`, the gate exits with code `1`.

---

## Phase Gates Summary

| Phase | Name | Target Scope | Current Status |
|---|---|---|---|
| **Phase 1** | Foundation & Contracts | Models, contracts, `/health`, test baseline | **PASSED** |
| **Phase 2** | Secure Source Code Intake | ZIP upload, archive safety, limits, sandboxing | **PASSED** |
| **Phase 3** | Security Scanner Integration | Rule engine, AST/heuristics, secret masking | **PLANNED** |
| **Phase 4** | Findings & Remediation | Finding deduplication, AI repair prompt | **BLOCKED (Phase 3)** |
| **Phase 5** | Rescan Comparison | Baseline scan vs rescan diffing, state transitions | **BLOCKED (Phase 3)** |
| **Phase 6** | End-to-End MVP | Full journey from archive submission to rescan diff | **BLOCKED (Phase 3)** |
| **Phase 7** | Release Gate | Full test suite, prerequisite checks, git/env audit | **BLOCKED (Phase 3)** |

---

## Git Milestone Workflow

After completing a development phase:
1. Run the phase checkpoint: `py scripts/phase_check.py <phase_num>`
2. Fix any failures until all checks achieve `[PASS]`.
3. Run the all-phase dashboard: `py scripts/phase_check.py --all`
4. Stage and commit the passing implementation:
   ```bash
   git add .
   git commit -m "feat(phase-N): implement Phase N"
   ```
5. Create and push a version tag for that phase:
   ```bash
   git tag -a <version_tag> -m "Phase N: Description"
   git push origin <version_tag>
   ```

### Milestone Tag Naming Conventions
- Phase 1: `v0.1.0-phase-1`
- Phase 2: `v0.2.0-phase-2`
- Phase 3: `v0.3.0-phase-3`
- Phase 4: `v0.4.0-phase-4`
- Phase 5: `v0.5.0-phase-5`
- Phase 6: `v0.6.0-phase-6`
- Phase 7: `v1.0.0`

> **Note on Verification**: Git tags simply mark specific commits in history; creating a tag does not independently prove that the software works. Every phase tag must be preceded by a passing run of `scripts/phase_check.py` and the full pytest suite.

---

## Phase Requirements & Evidence Specifications

### Phase 1: Foundation & Contracts
- **Status**: **PASSED**
- **Objective**: Establish the core intake API foundation, canonical Pydantic models, JSON schema contracts, and health readiness probe.
- **Requirements**:
  1. FastAPI application imports without circular dependencies or runtime errors.
  2. `GET /health` endpoint returns HTTP 200 with readiness fields (`status: "ready"`, `ready: true`, `service: "VibeShield API"`, `version: "0.1.0"`).
  3. `Finding` model validates valid security finding objects and rejects payloads missing required fields.
  4. `ScanResponse` model validates all 7 top-level fields (`scan_id`, `status`, `project`, `coverage`, `findings`, `repair_prompt`, `limitations`).
  5. Canonical JSON Schema in `contracts/finding.schema.json` is synchronized with `Finding.model_json_schema()`.
  6. Example payloads in `contracts/api-examples.json` parse and validate against target schemas.
  7. Automated pytest test suite passes completely.
- **Evidence**:
  - `py scripts/phase_check.py 1` exits with code `0`.
  - All Phase 1 tests pass in `backend/tests/`.

---

### Phase 2: Secure Source Code Intake
- **Status**: **PASSED**
- **Objective**: Safely accept, validate, and isolate submitted user project archives without code execution risk.
- **Implemented Route**: `POST /api/v1/scans` (multipart/form-data with `file: UploadFile`)
- **Safety Controls & Configurable Limits**:
  - `MAX_UPLOAD_SIZE_MB`: 25 MB default (enforced during stream read)
  - `MAX_ARCHIVE_ENTRIES`: 500 entries default
  - `MAX_TOTAL_UNCOMPRESSED_MB`: 50 MB default
  - `MAX_INDIVIDUAL_FILE_MB`: 5 MB default
  - `MAX_DIRECTORY_DEPTH`: 15 levels
  - Prohibited executables: `.exe`, `.dll`, `.so`, `.dylib`, `.bin`, `.elf`, etc.
  - Prohibited special files: POSIX symlinks, FIFOs, device nodes
  - Traversal protection: Parent `../` directory traversal, absolute paths (`/`), and Windows drive paths (`C:`) are rejected.
  - Directory exclusions: Automatically skips `.git`, `node_modules`, `.venv`, `__pycache__`, etc.
  - Sandboxed staging: Each scan receives an isolated temporary directory in `temp_scans/<scan_id>/source`.
  - Automatic failure cleanup: Any extraction or validation failure immediately wipes the allocated workspace.
  - Non-execution guarantee: Source files are read strictly as data streams; code is never executed, imported, or installed.
- **Evidence**:
  - `py scripts/phase_check.py 2` exits with code `0` (10/10 checks passing).
  - 18 automated intake tests in `backend/tests/test_intake.py` pass.

---

### Phase 3: Security Scanner Integration
- **Status**: **PLANNED** (Next Recommended Phase)
- **Objective**: Integrate deterministic static analysis heuristics and rule adapters for common vibe-coded vulnerabilities.
- **Requirements**:
  1. Scanner engine executes against isolated source trees.
  2. Evaluates controlled vulnerable test fixtures (`samples/vulnerable/`) and flags vulnerabilities.
  3. Findings contain grounded file path, start line, end line, and code snippet evidence.
  4. Scanner output validates against the canonical `Finding` schema.
  5. Sensitive values and secret tokens are redacted in logs and report output (e.g., `sk_live_***`).
  6. Scanner exceptions or dependency failures are reported explicitly (no false clean scans).
  7. Evaluates sample corrected fixtures (`samples/corrected/`) to confirm expected clean status.
  8. Automated scanner tests in `backend/tests/test_scanners.py` pass.
- **Evidence**:
  - `py scripts/phase_check.py 3` exits with code `0`.

---

### Phase 4: Findings & Consolidated Remediation
- **Status**: **BLOCKED (Requires Phase 3)**
- **Objective**: Synthesize actionable findings, deduplicate issues, and generate one unified repair prompt for AI coding tools.
- **Requirements**:
  1. Findings include complete metadata: impact, severity, confidence, recommendation, and verification steps.
  2. Duplicate findings (same file, rule, and location) are consolidated or suppressed.
  3. User-facing outputs and prompts redact raw secrets.
  4. Generates a structured repair prompt instructing AI assistants on exact fixes with file/line references.
  5. AI repair prompt never leaks raw secret values.
  6. Partial coverage and known scanner limitations are honestly reported in `limitations`.
  7. Automated tests in `backend/tests/test_remediation.py` pass.
- **Evidence**:
  - `py scripts/phase_check.py 4` exits with code `0`.

---

### Phase 5: Rescan Comparison & Verification
- **Status**: **BLOCKED (Requires Phase 3)**
- **Objective**: Compare an initial scan baseline against a corrected rescan to accurately track remediation progress.
- **Requirements**:
  1. Initial scan findings are stored as an immutable baseline.
  2. Rescan endpoint accepts corrected source code archives.
  3. Stable finding matcher correlates findings across scans using `rule_id`, normalized `file_path`, and snippet evidence.
  4. Findings are categorized into tri-state status: `resolved`, `unresolved` (persistent), or `new`.
  5. Findings that cannot be conclusively verified are not falsely marked resolved.
  6. Automated comparison tests in `backend/tests/test_comparison.py` pass.
- **Evidence**:
  - `py scripts/phase_check.py 5` exits with code `0`.

---

### Phase 6: End-to-End MVP Integration
- **Status**: **BLOCKED (Requires Phase 3)**
- **Objective**: Validate the full user journey seamlessly from archive submission to rescan diffing using local test fixtures.
- **Requirements**:
  1. Submit vulnerable project archive via API.
  2. Receive scan report with grounded findings and coverage metrics.
  3. Retrieve synthesized repair prompt.
  4. Submit corrected project archive for rescan.
  5. Receive diff comparing initial vs rescan findings showing resolved items.
  6. Verify contract compliance across all API responses.
  7. Validate error responses (invalid uploads, missing scans).
  8. Automated E2E tests in `backend/tests/test_e2e.py` pass without requiring external servers.
- **Evidence**:
  - `py scripts/phase_check.py 6` exits with code `0`.

---

### Phase 7: Production Readiness & Release Gate
- **Status**: **BLOCKED (Requires Phases 3–6)**
- **Objective**: Final release qualification audit confirming complete test passage, clean git tree, credential hygiene, and prerequisites.
- **Requirements**:
  1. Complete pytest suite passes (`py -m pytest backend/tests`).
  2. All prerequisite phase gates (Phases 1 through 6) pass.
  3. Secret audit: no high-entropy tokens or real API keys exist in git tracked files.
  4. Configuration hygiene: `.env.example` has no secrets; `.gitignore` ignores `.env*` and virtual environments.
  5. Documentation completeness: `README.md` and `CHECKPOINTS.md` accurately document commands and status.
  6. Working tree hygiene: git status shows no unignored build outputs, `.pyc`, or temporary zips.
  7. Explicit disclosure of scanner scope and limitations.
- **Evidence**:
  - `py scripts/phase_check.py 7` exits with code `0`.

---

## Running Checkpoints & Dashboard

```bash
# Display All-Phase Status Dashboard
py scripts/phase_check.py
# or
py scripts/phase_check.py --all

# Run specific phase gates
py scripts/phase_check.py 1   # Phase 1: Foundation
py scripts/phase_check.py 2   # Phase 2: Secure Intake
py scripts/phase_check.py 3   # Phase 3: Scanner Integration
```

On Linux or macOS, replace `py` with `python3`:
```bash
python3 scripts/phase_check.py --all
```
