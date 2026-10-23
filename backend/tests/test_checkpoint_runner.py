"""Automated unit tests for the Phase Checkpoint runner and All-Phase Dashboard system."""

import subprocess
import sys
from pathlib import Path

from scripts.checkpoints import PHASE_REGISTRY
from scripts.checkpoints.common import CheckStatus, REPO_ROOT
from scripts.checkpoints.phase1 import Phase1Check
from scripts.checkpoints.phase2 import Phase2Check
from scripts.checkpoints.phase3 import Phase3Check


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


def test_phase_2_checks_pass():
    """Verify that Phase 2 programmatic execution passes completely now that intake is built."""
    results = Phase2Check.run_all()
    assert len(results) == 10
    for result in results:
        assert (
            result.status == CheckStatus.PASS
        ), f"Phase 2 check failed: {result.name} - {result.details}"


def test_phase_3_checks_pass():
    """Verify that Phase 3 programmatic execution passes completely now that security scanner is built."""
    results = Phase3Check.run_all()
    assert len(results) == 9
    for result in results:
        assert (
            result.status == CheckStatus.PASS
        ), f"Phase 3 check failed: {result.name} - {result.details}"


def test_phase_check_cli_phase_1_passes():
    """Run `scripts/phase_check.py 1` via subprocess and assert exit code 0."""
    script_path = REPO_ROOT / "scripts" / "phase_check.py"
    cmd = [sys.executable, str(script_path), "1"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 0, f"Expected 0, got {proc.returncode}: {proc.stderr}"
    assert "Result: PASSED" in proc.stdout
    assert "Foundation & Contracts" in proc.stdout


def test_phase_check_cli_phase_2_passes():
    """Run `scripts/phase_check.py 2` via subprocess and assert exit code 0."""
    script_path = REPO_ROOT / "scripts" / "phase_check.py"
    cmd = [sys.executable, str(script_path), "2"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 0, f"Expected 0, got {proc.returncode}: {proc.stderr}"
    assert "Result: PASSED" in proc.stdout
    assert "Secure Source Code Intake" in proc.stdout


def test_phase_check_cli_phase_3_passes():
    """Run `scripts/phase_check.py 3` via subprocess and assert exit code 0."""
    script_path = REPO_ROOT / "scripts" / "phase_check.py"
    cmd = [sys.executable, str(script_path), "3"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 0, f"Expected 0, got {proc.returncode}: {proc.stderr}"
    assert "Result: PASSED" in proc.stdout
    assert "Security Scanner Integration" in proc.stdout


def test_phase_check_cli_phase_4_passes():
    """Run `scripts/phase_check.py 4` via subprocess and assert exit code 0."""
    script_path = REPO_ROOT / "scripts" / "phase_check.py"
    cmd = [sys.executable, str(script_path), "4"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 0, f"Expected 0, got {proc.returncode}: {proc.stderr}"
    assert "Result: PASSED" in proc.stdout
    assert "Findings & Consolidated Remediation" in proc.stdout


def test_phase_check_cli_dashboard_no_args():
    """Run `scripts/phase_check.py` with no args and assert dashboard output."""
    script_path = REPO_ROOT / "scripts" / "phase_check.py"
    cmd = [sys.executable, str(script_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    # Exits 1 because phases 5-7 are not yet passing
    assert proc.returncode == 1
    assert "All-Phase Status Dashboard" in proc.stdout
    assert "Phase 1: Foundation & Contracts" in proc.stdout
    assert "Phase 2: Secure Source Code Intake" in proc.stdout
    assert "Phase 3: Security Scanner Integration" in proc.stdout
    assert "Phase 4: Findings & Consolidated Remediation" in proc.stdout
    assert "4/7 phases passed" in proc.stdout
    assert "Next Phase:      Phase 5: Rescan Comparison & Verification" in proc.stdout


def test_phase_check_cli_dashboard_all_flag():
    """Run `scripts/phase_check.py --all` and assert dashboard output."""
    script_path = REPO_ROOT / "scripts" / "phase_check.py"
    cmd = [sys.executable, str(script_path), "--all"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 1
    assert "All-Phase Status Dashboard" in proc.stdout
    assert "Phase 4: Findings & Consolidated Remediation" in proc.stdout
    assert "4/7 phases passed" in proc.stdout
    assert "Next Phase:      Phase 5: Rescan Comparison & Verification" in proc.stdout


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
