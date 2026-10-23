# VibeCheck

> AI Security Reviewer for Vibe-Coded Websites (12-Hour Prototype)

VibeCheck accepts submitted website source code, analyzes it for high-impact security vulnerabilities (such as exposed secrets, dangerous JavaScript patterns, injection flaws, frontend risks, and insecure configurations), generates one consolidated repair prompt for AI coding assistants, and supports submitting corrected code for comparison rescans.

---

## Phase Implementation Status

| Phase | Gate Name | Current Status | Description |
|---|---|---|---|
| **Phase 1** | Foundation & Contracts | **PASSED** | Core schemas, JSON contracts, FastAPI readiness `/health`, baseline tests. |
| **Phase 2** | Secure Source Code Intake | **PASSED** | ZIP upload endpoint (`POST /api/v1/scans`), archive safety limits, zip slip/bomb protection, sandboxed staging, manifest generation. |
| **Phase 3** | Security Scanner Integration | **PASSED** | Deterministic static text analysis, 16 rules across 5 categories, secret masking, line-grounded evidence, zero-execution guarantee. |
| **Phase 4** | Findings & Remediation | **PASSED** | Deduplication, prompt-injection-resistant advisory repair prompt synthesis, 32 KiB budget limit, zero-execution advisory. |
| **Phase 5** | Rescan Comparison & Verification | **PASSED** | Deterministic finding matcher, tri-state classification (`RESOLVED`, `STILL_PRESENT`, `NEW`, `NOT_VERIFIABLE`), honest resolution guards, interactive dashboard UI. |
| **Phase 6** | End-to-End MVP | **BLOCKED** | Full user journey execution from submission to rescan diff (requires Phase 5). |
| **Phase 7** | Release Gate | **BLOCKED** | Release qualification audit (requires Phases 3–6). |

Detailed specifications, criteria, and evidence for every phase are documented in [CHECKPOINTS.md](file:///c:/Users/gopal/VibeCheck/CHECKPOINTS.md).

---

## Phase Checkpoint & Dashboard CLI

VibeCheck includes a persistent checkpoint runner that deterministically evaluates individual phase gates or renders a unified status dashboard across all seven phases.

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
py scripts/phase_check.py 4   # Verify Phase 4 (Remediation Synthesis)

# macOS / Linux
python3 scripts/phase_check.py 4
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

---

## Phase 3: Static Security Scanner Integration

Phase 3 introduces an automated, deterministic static security scanner in `backend/scanners/` that analyzes extracted source code strictly as plain text (never compiling, importing, or executing submitted code).

### Supported Languages and File Extensions
- **JavaScript & TypeScript**: `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`
- **Python**: `.py`, `.pyw`
- **Markup & Frontend**: `.html`, `.htm`, `.vue`, `.svelte`
- **Config & Shell**: `.env`, `.json`, `.yaml`, `.yml`, `.toml`, `.ini`, `.conf`, `.md`, `.txt`, `.sql`, `.sh`, `.css`

### Implemented Rule Catalog

| Rule ID | Category | Title | Severity | Confidence | Target Files |
|---|---|---|---|---|---|
| `VIBE-SEC-KEY` | `hardcoded-secret` | Exposed Production API Key or Access Token | Critical | High | All text files |
| `VIBE-SEC-CRED` | `hardcoded-secret` | Hardcoded Password or Client Secret | High | Medium | `.py`, `.js`, `.ts`, `.env`, configs |
| `VIBE-SEC-PRIVKEY` | `hardcoded-secret` | Hardcoded Private Key Material | Critical | High | All text files |
| `VIBE-JS-EVAL` | `dangerous-js` | Dangerous JavaScript eval() Invocation | High | High | `.js`, `.jsx`, `.ts`, `.tsx`, `.html` |
| `VIBE-JS-INNERHTML` | `dangerous-js` | Unsafe Assignment to innerHTML | Medium | Medium | `.js`, `.jsx`, `.ts`, `.tsx`, `.html` |
| `VIBE-JS-NEWFUNC` | `dangerous-js` | Dynamic Code Construction via Function Constructor | High | Medium | `.js`, `.jsx`, `.ts`, `.tsx` |
| `VIBE-INJ-SQL` | `injection` | Potential SQL Injection via String Interpolation | Critical | High | `.py`, `.js`, `.ts`, `.mjs` |
| `VIBE-INJ-SHELL` | `injection` | Potential Command Injection via Shell Execution | Critical | High | `.py`, `.js`, `.ts`, `.mjs` |
| `VIBE-INJ-DYNAMIC` | `injection` | Unsafe Dynamic Python eval() or exec() Execution | High | High | `.py`, `.pyw` |
| `VIBE-FE-INLINE` | `frontend-risk` | Inline JavaScript Event Handler in Markup | Medium | High | `.html`, `.vue`, `.svelte`, `.jsx` |
| `VIBE-FE-DANGEROUS-HTML` | `frontend-risk` | Potentially Unsafe HTML Injection (dangerouslySetInnerHTML) | High | High | `.jsx`, `.tsx`, `.js`, `.ts` |
| `VIBE-FE-HTTP-RESOURCE` | `frontend-risk` | Insecure Cleartext HTTP Resource Reference | Medium | Medium | `.html`, `.jsx`, `.tsx`, `.js` |
| `VIBE-CFG-TLS` | `insecure-config` | Disabled TLS / SSL Certificate Verification | Critical | High | `.py`, `.js`, `.ts`, `.env` |
| `VIBE-CFG-DEBUG` | `insecure-config` | Debug Mode Enabled in Application Configuration | High | High | `.py`, `.env`, `.ini`, `.yaml` |
| `VIBE-CFG-CORS` | `insecure-config` | Permissive Wildcard CORS with Credentials | High | High | `.py`, `.js`, `.ts`, `.mjs` |
| `VIBE-CFG-COOKIE` | `insecure-config` | Insecure Cookie Missing Secure or HttpOnly | Medium | Medium | `.py`, `.js`, `.ts` |

### Secret Redaction Guarantee
All secret values (such as Stripe API keys, AWS credentials, Google API keys, GitHub tokens, and hardcoded passwords) are automatically redacted using `mask_secret()`. Snippets and evidence strings display masked patterns (e.g., `sk_live_****cdef`) and never disclose raw credentials in API responses, logs, or exceptions.

### Severity and Confidence Definitions
- **Severity**:
  - `critical`: Direct, high-impact compromise (exposed live secrets, remote code execution, SQL/shell injection, disabled TLS).
  - `high`: Major vulnerability or significant exploit potential (eval usage, debug mode in production, permissive CORS with credentials).
  - `medium`: Insecure patterns or defense-in-depth issues (innerHTML assignment, inline event handlers, cleartext HTTP resources).
  - `low` / `info`: Informational recommendations.
- **Confidence**:
  - `high`: Deterministic token/regex match with known signature or exact syntax construct.
  - `medium`: Contextual heuristic pattern (e.g. variable naming assignment or string combination).

### Known Limitations & False Positive Considerations
- **Static Analysis Only**: The scanner reads source code purely as plain text. It does not construct full dynamic dependency graphs, execute code, or trace runtime taint flows across microservices.
- **Excluded Directories**: Dependencies in `node_modules/`, virtual environments (`.venv/`), and build output (`dist/`, `build/`) are skipped by default.
- **Interpreting Zero Findings**: A scan returning `findings: []` indicates that **no known patterns were triggered by the implemented rules**. It does **not** guarantee that the project is completely secure or free from logic flaws.

---

## API Usage

### Upload and Scan Archive (`POST /api/v1/scans`)
Upload a project ZIP to run intake validation, staging, and static scanning:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -F "file=@vulnerable-vibe.zip"
```

Example Response:
```json
{
  "scan_id": "scan_84532e36dd9f",
  "status": "completed",
  "project": "vulnerable-vibe",
  "coverage": {
    "files_scanned": 3,
    "total_lines": 120,
    "rules_evaluated": 16,
    "skipped_files": []
  },
  "findings": [
    {
      "id": "find-a7513662da",
      "rule_id": "VIBE-SEC-KEY",
      "category": "hardcoded-secret",
      "title": "Exposed Production API Key or Access Token",
      "severity": "critical",
      "confidence": "high",
      "status": "open",
      "location": {
        "file_path": "src/app.js",
        "line_start": 2,
        "line_end": 2,
        "snippet": "const STRIPE_SECRET = \"sk_live_****cdef\";"
      },
      "evidence": "Detected Stripe API Key token format 'sk_live_****cdef'.",
      "impact": "Exposing third-party API credentials in source files allows attackers to access associated cloud services.",
      "recommendation": "Extract credentials into secure environment variables and revoke the exposed token.",
      "verification_steps": [
        "Remove the hardcoded secret from the source code.",
        "Revoke and regenerate the compromised token in the provider console."
      ]
    }
  ],
  "repair_prompt": null,
  "limitations": [
    "Deterministic static text analysis only; source code is never executed, imported, or dynamically tested.",
    "Third-party build artifacts and excluded directories (e.g. node_modules, .git) were skipped from scanning.",
    "A scan with zero findings indicates that no vulnerabilities matched the active rule set, not that the application is guaranteed secure."
  ]
}
```

---

## Phase 5: Rescan Comparison & Developer Dashboard

Phase 5 introduces the deterministic comparison engine (`backend/comparison/`), rescan ingestion, honest finding verification states, and an interactive developer dashboard (`frontend/index.html`).

### Finding Dispositions
Every baseline finding receives an honest, evidence-based status:
- **`RESOLVED`**: The baseline finding has sufficient evidence of absence in a comparable, successful post-remediation scan with adequate coverage.
- **`STILL_PRESENT`**: The finding persists in the post-remediation scan, including when line numbers shifted or finding IDs changed.
- **`NEW`**: A finding in the post-remediation scan that cannot be matched to a baseline finding.
- **`NOT_VERIFIABLE`**: Evidence is insufficient to verify resolution (e.g., relevant files skipped, scan failure, zero files scanned, or inadequate rule coverage). Missing IDs or missing line numbers never automatically trigger `RESOLVED`.

### Available API Endpoints
- `POST /api/v1/scans`: Upload initial codebase archive (`.zip`) and run baseline scan.
- `GET /api/v1/scans`: List all previously recorded scans.
- `GET /api/v1/scans/{scan_id}`: Retrieve findings, coverage, and remediation prompt for a specific scan.
- `POST /api/v1/scans/{baseline_scan_id}/rescan`: Upload corrected codebase archive (`.zip`), execute rescan, and compare against baseline.
- `POST /api/v1/scans/compare`: Direct comparison between two scans by ID or JSON payload.
- `GET /api/v1/comparisons/{comparison_id}`: Retrieve stored comparison results and finding diffs.
- `GET /api/v1/phases`: Live status and checkpoint checks for Phases 1 through 7.
- `GET /`: Interactive VibeCheck developer dashboard.

---

## Running the API & Tests

### Start the FastAPI Server
```bash
# Windows
py -m uvicorn backend.app.main:app --reload --port 8000

# macOS / Linux
uvicorn backend.app.main:app --reload --port 8000
```

### Run Automated Tests
```bash
# Windows
py -m pytest

# Run only scanner integration tests
py -m pytest backend/tests/test_scanners.py

# macOS / Linux
pytest
```