"""Security scanning engine package for VibeCheck."""

from backend.scanners.engine import ScannerEngine, ScannerError
from backend.scanners.masking import mask_secret, sanitize_relative_path, sanitize_text
from backend.scanners.rules import (
    ALL_RULE_CLASSES,
    BaseRule,
    RuleMatch,
    get_default_rules,
)

__all__ = [
    "ScannerEngine",
    "ScannerError",
    "BaseRule",
    "RuleMatch",
    "ALL_RULE_CLASSES",
    "get_default_rules",
    "mask_secret",
    "sanitize_text",
    "sanitize_relative_path",
]
