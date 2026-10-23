"""Automated unit tests for the Phase Checkpoint runner system."""

import subprocess
import sys
from pathlib import Path

from scripts.checkpoints import PHASE_REGISTRY
from scripts.checkpoints.common import CheckStatus, REPO_ROOT
from scripts.checkpoints.phase1 import Phase1Check
from scripts.checkpoints.phase2 import Phase2Check


def test_phase_registry_contains_all_seven_phases():
    """Verify that phases 1 through 7 are registered."""
    assert set(PHASE_REGISTRY.keys()) == {1, 2, 3, 4, 5, 6, 7}


def test_phase_1_checks_pass():
    """Verify that Phase 1 programmatic execution passes completely."""
    results = Phase1Check.run_all()
    assert len(results) >= 6
    for result in results:
        assert (
            result.status == CheckStatus.PASS
        ), f"Phase 1 check failed: {result.name} - {result.details}"


def test_phase_2_checks_report_not_implemented():
    """Verify that Phase 2 correctly reports not implemented for unbuilt features."""
    results = Phase2Check.run_all()
    assert len(results) > 0
    # Since intake is not yet built, all checks must be NOT_IMPLEMENTED
    not_impl = [r for r in results if r.status == CheckStatus.NOT_IMPLEMENTED]
    assert len(not_impl) == len(results)


def test_phase_check_cli_phase_1_passes():
    """Run `scripts/phase_check.py 1` via subprocess and assert exit code 0."""
    script_path = REPO_ROOT / "scripts" / "phase_check.py"
    cmd = [sys.executable, str(script_path), "1"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 0, f"Expected 0, got {proc.returncode}: {proc.stderr}"
    assert "Result: PASSED" in proc.stdout
    assert "Phase 1: Foundation" in proc.stdout


def test_phase_check_cli_phase_2_fails():
    """Run `scripts/phase_check.py 2` via subprocess and assert exit code 1."""
    script_path = REPO_ROOT / "scripts" / "phase_check.py"
    cmd = [sys.executable, str(script_path), "2"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 1, f"Expected 1, got {proc.returncode}"
    assert "Result: FAILED" in proc.stdout
    assert "not implemented" in proc.stdout


def test_phase_check_cli_invalid_phase_number():
    """Verify passing an out-of-range phase number returns exit code 2."""
    script_path = REPO_ROOT / "scripts" / "phase_check.py"
    cmd = [sys.executable, str(script_path), "99"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 2
    assert "Invalid phase number '99'" in proc.stderr


def test_phase_check_cli_non_integer_argument():
    """Verify passing a non-integer argument returns exit code 2."""
    script_path = REPO_ROOT / "scripts" / "phase_check.py"
    cmd = [sys.executable, str(script_path), "invalid"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 2
    assert "Phase argument must be an integer (1-7)" in proc.stderr
