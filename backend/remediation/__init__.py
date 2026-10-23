"""Consolidated remediation prompt generator module for VibeCheck.

Phase 4: Findings & Consolidated Remediation.
Synthesizes deterministic, advisory-only repair prompts for AI coding assistants.
"""

from backend.remediation.generator import (
    PromptSynthesizer,
    RemediationError,
    RemediationService,
    generate_repair_prompt,
)

__all__ = [
    "PromptSynthesizer",
    "RemediationError",
    "RemediationService",
    "generate_repair_prompt",
]
