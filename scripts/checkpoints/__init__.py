"""Phase checkpoint gate modules for VibeShield."""

from scripts.checkpoints.common import CheckResult, CheckStatus
from scripts.checkpoints.phase1 import Phase1Check
from scripts.checkpoints.phase2 import Phase2Check
from scripts.checkpoints.phase3 import Phase3Check
from scripts.checkpoints.phase4 import Phase4Check
from scripts.checkpoints.phase5 import Phase5Check
from scripts.checkpoints.phase6 import Phase6Check
from scripts.checkpoints.phase7 import Phase7Check

PHASE_REGISTRY = {
    1: Phase1Check,
    2: Phase2Check,
    3: Phase3Check,
    4: Phase4Check,
    5: Phase5Check,
    6: Phase6Check,
    7: Phase7Check,
}

__all__ = [
    "CheckResult",
    "CheckStatus",
    "PHASE_REGISTRY",
    "Phase1Check",
    "Phase2Check",
    "Phase3Check",
    "Phase4Check",
    "Phase5Check",
    "Phase6Check",
    "Phase7Check",
]
