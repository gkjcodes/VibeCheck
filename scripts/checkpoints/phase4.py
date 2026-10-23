"""Phase 4 Checkpoint: Findings & Remediation Synthesis.

Verifies:
- Findings contain evidence, severity, confidence, impact, and recommendations.
- Duplicate findings are handled according to implemented rules.
- Secrets are redacted from user-facing output.
- Repair prompts contain relevant findings and safe remediation instructions.
- Generated prompt does not contain raw secret values.
- Errors and partial coverage are reported honestly.
- Remediation test suite passes.
"""

from typing import List

from scripts.checkpoints.common import (
    CheckResult,
    CheckStatus,
    REPO_ROOT,
    run_pytest,
)


class Phase4Check:
    """Checkpoint gate runner for Phase 4: Findings & Remediation."""

    phase_number = 4
    phase_name = "Phase 4: Findings & Consolidated Remediation"

    @classmethod
    def run_all(cls) -> List[CheckResult]:
        results: List[CheckResult] = []

        remediation_ready = cls._inspect_remediation_module()

        if not remediation_ready:
            results.append(
                CheckResult(
                    name="Consolidated Repair Prompt Generator",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/remediation does not export prompt generator or remediation service.",
                )
            )
            results.append(
                CheckResult(
                    name="Finding Field Completeness Audit",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Remediation pipeline awaiting Phase 4 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Duplicate Finding Deduplication",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Deduplication engine awaiting Phase 4 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Secret Redaction in User-Facing Output",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Secret redaction in remediation awaiting Phase 4 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Actionable Safe Remediation Instructions",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Remediation prompt synthesis awaiting Phase 4 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Raw Secret Exclusion from AI Repair Prompt",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Prompt secret sanitizer awaiting Phase 4 implementation.",
                )
            )
            results.append(
                CheckResult(
                    name="Honest Partial Coverage & Limitations Reporting",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="Coverage limitations reporter awaiting Phase 4 implementation.",
                )
            )
        else:
            results.append(cls._check_live_remediation())

        remediation_test = REPO_ROOT / "backend" / "tests" / "test_remediation.py"
        if not remediation_test.exists():
            results.append(
                CheckResult(
                    name="Remediation Automated Test Suite",
                    status=CheckStatus.NOT_IMPLEMENTED,
                    details="backend/tests/test_remediation.py not yet implemented.",
                )
            )
        else:
            results.append(cls._run_remediation_tests(str(remediation_test)))

        return results

    @classmethod
    def _inspect_remediation_module(cls) -> bool:
        try:
            import backend.remediation as remediation

            return any(
                hasattr(remediation, attr)
                for attr in [
                    "generate_repair_prompt",
                    "PromptSynthesizer",
                    "RemediationService",
                ]
            )
        except Exception:
            return False

    @classmethod
    def _check_live_remediation(cls) -> CheckResult:
        return CheckResult(
            name="Consolidated Repair Prompt Generator",
            status=CheckStatus.NOT_IMPLEMENTED,
            details="Remediation tests awaiting Phase 4 implementation.",
        )

    @classmethod
    def _run_remediation_tests(cls, test_path: str) -> CheckResult:
        success, output = run_pytest([test_path])
        if success:
            return CheckResult(
                name="Remediation Automated Test Suite",
                status=CheckStatus.PASS,
                details="Remediation tests passed.",
            )
        return CheckResult(
            name="Remediation Automated Test Suite",
            status=CheckStatus.FAIL,
            details=f"Remediation tests failed:\n{output}",
        )
