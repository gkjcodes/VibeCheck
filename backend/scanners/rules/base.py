"""Base abstractions for VibeCheck security scanner rules."""

import abc
from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class RuleMatch:
    """Represents a discrete vulnerability detection instance in a source file."""

    rule_id: str
    category: str
    title: str
    severity: str
    confidence: str
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    evidence: str
    impact: str
    recommendation: str
    verification_steps: List[str] = field(default_factory=list)


class BaseRule(abc.ABC):
    """Abstract base class for all deterministic static analysis rules."""

    rule_id: str
    category: str
    title: str
    severity: str  # critical, high, medium, low, info
    confidence: str  # high, medium, low
    supported_extensions: Set[str]
    description: str

    @abc.abstractmethod
    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        """Inspect file content as text and return detected security matches.
        
        Args:
            file_path: Relative POSIX path of the file.
            content: Raw string content of the source file.
            
        Returns:
            List of RuleMatch instances.
        """
        pass
