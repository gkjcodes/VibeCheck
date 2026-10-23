#!/usr/bin/env python3
"""VibeShield Phase Checkpoint Runner & All-Phase Dashboard.

Executes phase gates 1 through 7 deterministically using the current Python
interpreter, reporting PASS, FAIL, NOT IMPLEMENTED, or BLOCKED for each feature check.

Usage:
    py scripts/phase_check.py              # Run all-phase status dashboard
    py scripts/phase_check.py --all        # Run all-phase status dashboard
    py scripts/phase_check.py <phase_num>  # Run detailed gate for specific phase (1-7)
"""

from pathlib import Path
import sys
from typing import Dict, Optional, Tuple

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
    print("    py scripts/phase_check.py              # Run all-phase dashboard")
    print("    py scripts/phase_check.py --all        # Run all-phase dashboard")
    print("    py scripts/phase_check.py <phase_num>  # Run specific phase gate (1-7)")
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


def run_all_phase_dashboard() -> int:
    """Evaluate and display status for all seven phases in a unified dashboard.
    
    Returns 0 if all phases pass; 1 otherwise.
    """
    print_banner("VibeShield All-Phase Status Dashboard")

    phase_results: Dict[int, Tuple[CheckStatus, str]] = {}
    prerequisite_failed: Optional[int] = None

    for phase_num in sorted(PHASE_REGISTRY.keys()):
        checker = PHASE_REGISTRY[phase_num]

        # Check if any prerequisite phase is not passing
        if prerequisite_failed is not None:
            prereq_name = PHASE_REGISTRY[prerequisite_failed].phase_name
            phase_results[phase_num] = (
                CheckStatus.BLOCKED,
                f"Blocked by prerequisite Phase {prerequisite_failed} ({prereq_name})",
            )
            continue

        try:
            checks = checker.run_all()
            fails = [c for c in checks if c.status == CheckStatus.FAIL]
            not_impls = [c for c in checks if c.status == CheckStatus.NOT_IMPLEMENTED]

            if fails:
                prerequisite_failed = phase_num
                reason = fails[0].details or fails[0].name
                phase_results[phase_num] = (CheckStatus.FAIL, reason)
            elif not_impls:
                prerequisite_failed = phase_num
                reason = not_impls[0].details or not_impls[0].name
                phase_results[phase_num] = (CheckStatus.NOT_IMPLEMENTED, reason)
            else:
                phase_results[phase_num] = (CheckStatus.PASS, "")
        except Exception as exc:
            prerequisite_failed = phase_num
            phase_results[phase_num] = (CheckStatus.FAIL, f"Exception during gate check: {exc}")

    # Display each phase status
    for phase_num in sorted(PHASE_REGISTRY.keys()):
        checker = PHASE_REGISTRY[phase_num]
        status, reason = phase_results[phase_num]
        status_tag = format_status(status)
        print(f"Phase {phase_num}: {checker.phase_name}")
        print(f"  Status: {status_tag}")
        if reason:
            first_line = reason.strip().splitlines()[0]
            print(f"  Reason: {first_line}")

    # Dashboard Metrics
    passed = sum(1 for s, _ in phase_results.values() if s == CheckStatus.PASS)
    failed = sum(1 for s, _ in phase_results.values() if s == CheckStatus.FAIL)
    not_impl = sum(1 for s, _ in phase_results.values() if s == CheckStatus.NOT_IMPLEMENTED)
    blocked = sum(1 for s, _ in phase_results.values() if s == CheckStatus.BLOCKED)

    # Next recommended phase: earliest phase with prerequisites met that has not passed
    next_phase_str = "None (All phases complete!)"
    for phase_num in sorted(PHASE_REGISTRY.keys()):
        s, _ = phase_results[phase_num]
        if s in (CheckStatus.NOT_IMPLEMENTED, CheckStatus.FAIL):
            next_phase_str = f"Phase {phase_num}: {PHASE_REGISTRY[phase_num].phase_name}"
            break

    print("-" * 80)
    print("Dashboard Summary:")
    print(f"  Passed:          {passed}")
    print(f"  Failed:          {failed}")
    print(f"  Not Implemented: {not_impl}")
    print(f"  Blocked:         {blocked}")
    print(f"  Progress:        {passed}/7 phases passed")
    print(f"  Next Phase:      {next_phase_str}")
    print("=" * 80)

    return 0 if passed == len(PHASE_REGISTRY) else 1


def main() -> int:
    # No arguments or --all flag -> run all-phase dashboard
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1].strip() in ("--all", "-a", "all")):
        return run_all_phase_dashboard()

    raw_arg = sys.argv[1].strip()
    try:
        phase_num = int(raw_arg)
    except ValueError:
        print(f"Error: Phase argument must be an integer (1-7) or '--all', got '{raw_arg}'.\n", file=sys.stderr)
        print_usage()
        return 2

    return run_phase_checkpoint(phase_num)


if __name__ == "__main__":
    sys.exit(main())
