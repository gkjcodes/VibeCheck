"""Common data types and test execution utilities for phase checkpoints."""

import enum
import os
from pathlib import Path
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class CheckStatus(enum.Enum):
    """Execution status for an individual phase check or overall phase."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_IMPLEMENTED = "NOT IMPLEMENTED"
    BLOCKED = "BLOCKED"


@dataclass
class CheckResult:
    """Outcome of a single deterministic phase check."""

    name: str
    status: CheckStatus
    details: str = ""


# Color support detection across Windows/Linux/macOS
USE_COLOR = sys.stdout.isatty() or os.environ.get("FORCE_COLOR") == "1"


def colorize(text: str, color_code: str) -> str:
    """Wrap text in ANSI color escape codes when terminal supports it."""
    if not USE_COLOR:
        return text
    return f"\033[{color_code}m{text}\033[0m"


def format_status(status: CheckStatus) -> str:
    """Render formatted status indicator with color."""
    if status == CheckStatus.PASS:
        return colorize("[PASS]", "32")  # Green
    elif status == CheckStatus.FAIL:
        return colorize("[FAIL]", "31")  # Red
    elif status == CheckStatus.NOT_IMPLEMENTED:
        return colorize("[NOT IMPLEMENTED]", "33")  # Yellow
    elif status == CheckStatus.BLOCKED:
        return colorize("[BLOCKED]", "35")  # Magenta
    return f"[{status.value}]"


def run_command_capture(
    cmd: List[str], cwd: Optional[Path] = None, timeout: int = 30
) -> Tuple[int, str, str]:
    """Execute a subprocess command, capturing stdout and stderr without hanging."""
    work_dir = str(cwd or REPO_ROOT)
    try:
        proc = subprocess.run(
            cmd,
            cwd=work_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout} seconds: {' '.join(cmd)}"
    except Exception as exc:
        return -1, "", f"Command failed to launch: {str(exc)}"


def run_pytest(test_paths: List[str], timeout: int = 180) -> Tuple[bool, str]:
    """Run pytest with the current Python interpreter on specific test paths."""
    if os.environ.get("VIBECHECK_FAST_CHECK") == "1" or "PYTEST_CURRENT_TEST" in os.environ:
        return True, "Subprocess pytest skipped in fast check mode or nested test run."
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        *test_paths,
        "-v",
        "--no-header",
    ]
    returncode, stdout, stderr = run_command_capture(cmd, timeout=timeout)
    combined = (stdout + ("\n" + stderr if stderr else "")).strip()
    return returncode == 0, combined
