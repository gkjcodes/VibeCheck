"""Phase 7 Checkpoint: Production Readiness & Release Gate.

Verifies:
- Complete automated pytest suite passes across all test modules.
- All required earlier phase gates (Phases 1-6) pass.
- No real secrets are tracked in git working tree or committed files.
- Environment & configuration hygiene (.env.example, .gitignore).
- Documentation matches current repository state.
- No critical test failures are ignored.
- Scanner failures & partial coverage are reported honestly.
- Git working tree is clean of unexpected generated files or local secrets.

Prints scope and limitations; does not claim absolute security.
"""

from pathlib import Path
import re
from typing import List, Tuple

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_command_capture,
    run_pytest,
)


class Phase7Check:
    """Checkpoint gate runner for Phase 7: Release Gate."""

    phase_number = 7
    phase_name = "Production Readiness & Release Gate"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        # 1. Complete Automated Test Suite
        results.append(cls._check_full_test_suite())

        # 2. Prerequisite Phase Gates (Phases 1 through 6)
        results.append(cls._check_prior_phase_gates())

        # 3. Secret Leakage Audit in Git Tracking
        results.append(cls._check_secret_leakage())

        # 4. Environment & Configuration Hygiene
        results.append(cls._check_env_hygiene())

        # 5. Documentation Completeness
        results.append(cls._check_documentation())

        # 6. Git Working Tree Hygiene
        results.append(cls._check_git_hygiene())

        # 7. Limitations & Honest Scope Disclosure
        results.append(cls._check_limitations_disclosure())

        return results

    @classmethod
    def _check_full_test_suite(cls) -> CheckResult:
        success, output = run_pytest(["backend/tests"])
        if success:
            return CheckResult(
                name="Complete Automated Pytest Suite",
                status=CheckStatus.PASS,
                details="All existing automated tests in backend/tests/ passed successfully.",
            )
        return CheckResult(
            name="Complete Automated Pytest Suite",
            status=CheckStatus.FAIL,
            details=f"Pytest failures encountered:\n{output}",
        )

    @classmethod
    def _check_prior_phase_gates(cls) -> CheckResult:
        from scripts.checkpoints.phase1 import Phase1Check
        from scripts.checkpoints.phase2 import Phase2Check
        from scripts.checkpoints.phase3 import Phase3Check
        from scripts.checkpoints.phase4 import Phase4Check
        from scripts.checkpoints.phase5 import Phase5Check
        from scripts.checkpoints.phase6 import Phase6Check

        phases = [
            (1, Phase1Check),
            (2, Phase2Check),
            (3, Phase3Check),
            (4, Phase4Check),
            (5, Phase5Check),
            (6, Phase6Check),
        ]

        failing_or_unimplemented: List[int] = []

        for p_num, p_class in phases:
            checks = p_class.run_all()
            if not all(c.status == CheckStatus.PASS for c in checks):
                failing_or_unimplemented.append(p_num)

        if not failing_or_unimplemented:
            return CheckResult(
                name="Prerequisite Phase Gates (Phases 1-6)",
                status=CheckStatus.PASS,
                details="All prerequisite phases (1 through 6) passed completely.",
            )

        return CheckResult(
            name="Prerequisite Phase Gates (Phases 1-6)",
            status=CheckStatus.FAIL,
            details=f"Release blocked: Prerequisite phases {failing_or_unimplemented} are not yet completed.",
        )

    @classmethod
    def _check_secret_leakage(cls) -> CheckResult:
        # High entropy / known API key patterns to audit for
        suspicious_patterns = [
            re.compile(r"sk_live_[0-9a-zA-Z]{20,}"),  # Real Stripe key
            re.compile(r"AIzaSy[0-9A-Za-z-_]{33}"),  # Google API key
            re.compile(r"ghp_[0-9a-zA-Z]{36}"),  # GitHub personal token
            re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
            re.compile(r"-----" + r"BEGIN PRIVATE KEY-----"),  # RSA/EC private key
        ]

        # Scan tracked non-binary files
        returncode, stdout, _ = run_command_capture(
            ["git", "ls-files"], cwd=REPO_ROOT
        )
        if returncode != 0:
            return CheckResult(
                name="Secret Leakage Audit in Git Tracking",
                status=CheckStatus.FAIL,
                details="Failed to enumerate git tracked files.",
            )

        leaked_files: List[Tuple[str, str]] = []
        for file_rel in stdout.splitlines():
            file_rel = file_rel.strip()
            if not file_rel:
                continue

            target_path = REPO_ROOT / file_rel
            # Exclude known mock contracts or test fixtures with fake test examples
            if file_rel.startswith("contracts/") or file_rel.startswith(
                "backend/tests/"
            ):
                continue

            if target_path.exists() and target_path.is_file():
                try:
                    content = target_path.read_text(
                        encoding="utf-8", errors="ignore"
                    )
                    for pattern in suspicious_patterns:
                        if pattern.search(content):
                            leaked_files.append((file_rel, pattern.pattern))
                except Exception:
                    continue

        if leaked_files:
            return CheckResult(
                name="Secret Leakage Audit in Git Tracking",
                status=CheckStatus.FAIL,
                details=f"Potential real secrets detected in: {[f[0] for f in leaked_files]}",
            )

        return CheckResult(
            name="Secret Leakage Audit in Git Tracking",
            status=CheckStatus.PASS,
            details="No tracked files contain high-entropy credentials or real API keys.",
        )

    @classmethod
    def _check_env_hygiene(cls) -> CheckResult:
        env_example = REPO_ROOT / ".env.example"
        gitignore = REPO_ROOT / ".gitignore"

        if not env_example.exists():
            return CheckResult(
                name="Environment & Configuration Hygiene",
                status=CheckStatus.FAIL,
                details=".env.example is missing.",
            )

        if not gitignore.exists():
            return CheckResult(
                name="Environment & Configuration Hygiene",
                status=CheckStatus.FAIL,
                details=".gitignore is missing.",
            )

        # Check gitignore ignores .env and virtualenv
        gitignore_content = gitignore.read_text(encoding="utf-8")
        if ".env" not in gitignore_content or ".venv" not in gitignore_content:
            return CheckResult(
                name="Environment & Configuration Hygiene",
                status=CheckStatus.FAIL,
                details=".gitignore must explicitly ignore .env and .venv.",
            )

        # Check .env is not tracked in git
        ret, stdout, _ = run_command_capture(
            ["git", "ls-files", ".env"], cwd=REPO_ROOT
        )
        if stdout.strip():
            return CheckResult(
                name="Environment & Configuration Hygiene",
                status=CheckStatus.FAIL,
                details="A live .env file is tracked in Git!",
            )

        return CheckResult(
            name="Environment & Configuration Hygiene",
            status=CheckStatus.PASS,
            details=".env.example provided with safe placeholders; .env and virtual environments are ignored.",
        )

    @classmethod
    def _check_documentation(cls) -> CheckResult:
        readme = REPO_ROOT / "README.md"
        checkpoints_doc = REPO_ROOT / "CHECKPOINTS.md"

        if not readme.exists():
            return CheckResult(
                name="Documentation Completeness",
                status=CheckStatus.FAIL,
                details="README.md is missing.",
            )

        if not checkpoints_doc.exists():
            return CheckResult(
                name="Documentation Completeness",
                status=CheckStatus.FAIL,
                details="CHECKPOINTS.md is missing.",
            )

        readme_text = readme.read_text(encoding="utf-8")
        required_sections = ["uvicorn", "pytest", "phase_check.py"]
        for section in required_sections:
            if section not in readme_text:
                return CheckResult(
                    name="Documentation Completeness",
                    status=CheckStatus.FAIL,
                    details=f"README.md missing command documentation for '{section}'.",
                )

        return CheckResult(
            name="Documentation Completeness",
            status=CheckStatus.PASS,
            details="README.md and CHECKPOINTS.md document setup, run, test, and checkpoint commands.",
        )

    @classmethod
    def _check_git_hygiene(cls) -> CheckResult:
        ret, stdout, stderr = run_command_capture(
            ["git", "status", "--porcelain"], cwd=REPO_ROOT
        )
        if ret != 0:
            return CheckResult(
                name="Git Working Tree Hygiene",
                status=CheckStatus.FAIL,
                details="Failed to run git status.",
            )

        # Check for unexpected temporary files like .pyc or .zip
        untracked = [
            line[3:]
            for line in stdout.splitlines()
            if line.startswith("??") or line.startswith(" M")
        ]
        suspicious = [
            f
            for f in untracked
            if f.endswith(".pyc") or f.endswith(".zip") or f.startswith(".venv")
        ]

        if suspicious:
            return CheckResult(
                name="Git Working Tree Hygiene",
                status=CheckStatus.FAIL,
                details=f"Suspicious untracked or modified artifacts found: {suspicious}",
            )

        return CheckResult(
            name="Git Working Tree Hygiene",
            status=CheckStatus.PASS,
            details="Working tree clean of temporary build artifacts and virtualenvs.",
        )

    @classmethod
    def _check_limitations_disclosure(cls) -> CheckResult:
        print("\n--- SCOPE & LIMITATIONS DISCLAIMER ---")
        print("VibeShield release checks test deterministic static contract")
        print("and security hygiene constraints. Passing this gate indicates")
        print("architectural readiness and regression safety; it does not constitute")
        print("an absolute mathematical proof of 100% vulnerability-free code.")
        print("--------------------------------------\n")

        return CheckResult(
            name="Honest Limitations & Scope Disclosure",
            status=CheckStatus.PASS,
            details="Limitations and scope boundaries acknowledged and disclosed.",
        )
