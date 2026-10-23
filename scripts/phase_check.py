#!/usr/bin/env python3
"""VibeShield Phase Checkpoint Runner.

Executes phase gates 1 through 7 deterministically using the current Python
interpreter, reporting PASS, FAIL, or NOT IMPLEMENTED for each feature check.

Usage:
    py scripts/phase_check.py <phase_number>
    python3 scripts/phase_check.py <phase_number>

Supported phases: 1, 2, 3, 4, 5, 6, 7.
"""

from pathlib import Path
import sys

# Ensure repository root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.checkpoints import PHASE_REGISTRY
from scripts.checkpoints.common import CheckStatus, format_status


def print_banner(text: str) -> None:
    width = 80
    print("=" * width)
    print(text)
    print("=" * width)


def print_usage() -> None:
    print("VibeShield Phase Checkpoint Runner")
    print("\nUsage:")
    print("    py scripts/phase_check.py <phase_number>")
    print("    python3 scripts/phase_check.py <phase_number>")
    print("\nSupported Phases:")
    for num, checker in PHASE_REGISTRY.items():
        print(f"    {num} - {checker.phase_name}")
    print()


def run_phase_checkpoint(phase_num: int) -> int:
    """Run all checks for the requested phase number.
    
    Returns 0 if all checks pass; non-zero (1) otherwise.
    """
    checker = PHASE_REGISTRY.get(phase_num)
    if not checker:
        print(f"Error: Invalid phase number '{phase_num}'. Supported phases: 1 to 7.\n", file=sys.stderr)
        print_usage()
        return 2

    print_banner(f"VibeShield Checkpoint Gate: {checker.phase_name}")

    try:
        results = checker.run_all()
    except Exception as exc:
        print(f"\n[FATAL ERROR] Checkpoint execution encountered unexpected exception: {exc}\n", file=sys.stderr)
        return 1

    passed_count = sum(1 for r in results if r.status == CheckStatus.PASS)
    failed_count = sum(1 for r in results if r.status == CheckStatus.FAIL)
    not_impl_count = sum(1 for r in results if r.status == CheckStatus.NOT_IMPLEMENTED)

    # Print individual check results
    for r in results:
        status_tag = format_status(r.status)
        print(f"{status_tag} {r.name}")
        if r.details:
            prefix = "       Reason: " if r.status != CheckStatus.PASS else "       Info: "
            # Indent multi-line details cleanly
            indented = "\n               ".join(r.details.strip().splitlines())
            print(f"{prefix}{indented}")

    # Summary section
    print("-" * 80)
    print(f"Phase {phase_num} Summary: {passed_count} passed, {failed_count} failed, {not_impl_count} not implemented (Total: {len(results)})")

    all_passed = (passed_count == len(results)) and (len(results) > 0)

    if all_passed:
        print(f"Result: PASSED -- Phase {phase_num} gate requirements fully satisfied.")
        print("=" * 80)
        return 0
    else:
        reasons = []
        if failed_count > 0:
            reasons.append(f"{failed_count} check(s) failed")
        if not_impl_count > 0:
            reasons.append(f"{not_impl_count} check(s) not implemented")
        reason_str = ", ".join(reasons) or "incomplete requirements"
        print(f"Result: FAILED -- Phase {phase_num} gate NOT satisfied ({reason_str}).")
        print("=" * 80)
        return 1


def main() -> int:
    if len(sys.argv) < 2:
        print("Error: Missing phase number argument.\n", file=sys.stderr)
        print_usage()
        return 2

    raw_arg = sys.argv[1].strip()
    try:
        phase_num = int(raw_arg)
    except ValueError:
        print(f"Error: Phase argument must be an integer (1-7), got '{raw_arg}'.\n", file=sys.stderr)
        print_usage()
        return 2

    return run_phase_checkpoint(phase_num)


if __name__ == "__main__":
    sys.exit(main())
