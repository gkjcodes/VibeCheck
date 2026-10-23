"""Deterministic static security scanner engine for VibeCheck."""

import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from backend.app.intake.extractor import ManifestFile, ProjectManifest
from backend.app.schemas.finding import Finding, FindingLocation
from backend.app.schemas.scan import ScanCoverage
from backend.scanners.masking import sanitize_relative_path, sanitize_text
from backend.scanners.rules import BaseRule, get_default_rules

logger = logging.getLogger("vibecheck.scanner")

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

DEFAULT_LIMITATIONS = [
    "Deterministic static text analysis only; source code is never executed, imported, or dynamically tested.",
    "Third-party build artifacts and excluded directories (e.g. node_modules, .git) were skipped from scanning.",
    "A scan with zero findings indicates that no vulnerabilities matched the active rule set, not that the application is guaranteed secure.",
]


class ScannerError(Exception):
    """Raised when scanner engine encounters an unrecoverable failure."""
    pass


class ScannerEngine:
    """Orchestrates deterministic static security analysis over an extracted project workspace."""

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        self.rules: List[BaseRule] = rules if rules is not None else get_default_rules()
        self._rule_ext_map: Dict[str, List[BaseRule]] = {}
        self._init_rule_map()

    def _init_rule_map(self) -> None:
        for rule in self.rules:
            for ext in rule.supported_extensions:
                norm_ext = ext.lower()
                self._rule_ext_map.setdefault(norm_ext, []).append(rule)

    @property
    def total_rules_count(self) -> int:
        return len(self.rules)

    def scan_workspace(
        self,
        workspace_dir: Path,
        manifest: Optional[ProjectManifest] = None,
    ) -> Tuple[List[Finding], ScanCoverage, List[str]]:
        """Perform static analysis on files within an isolated scan workspace.
        
        Args:
            workspace_dir: Absolute Path to the extracted project workspace.
            manifest: Optional ProjectManifest from the safe extractor.
            
        Returns:
            Tuple of (findings_list, coverage_info, limitations_list)
        """
        resolved_workspace = workspace_dir.resolve()
        if not resolved_workspace.is_dir():
            raise ScannerError(f"Workspace directory does not exist or is not a directory: {resolved_workspace}")

        findings_map: Dict[str, Finding] = {}
        files_scanned_count = 0
        total_lines_evaluated = 0
        skipped_files: List[str] = []

        if manifest:
            skipped_files.extend(manifest.skipped_files)

        # Collect candidate files
        candidate_rel_paths: List[str] = []
        if manifest and manifest.files:
            candidate_rel_paths = [f.relative_path for f in manifest.files]
        else:
            for p in resolved_workspace.rglob("*"):
                if p.is_file():
                    try:
                        rel = p.relative_to(resolved_workspace).as_posix()
                        candidate_rel_paths.append(rel)
                    except ValueError:
                        continue

        for rel_path in sorted(candidate_rel_paths):
            clean_rel = sanitize_relative_path(rel_path)
            target_file = (resolved_workspace / clean_rel).resolve()

            # Workspace containment assertion: prevent path traversal or symlink escapes
            try:
                target_file.relative_to(resolved_workspace)
            except ValueError:
                logger.warning(f"File {clean_rel} escapes workspace {resolved_workspace}, skipping.")
                skipped_files.append(clean_rel)
                continue

            if not target_file.is_file():
                continue

            # Check if any rule supports this file extension
            ext = target_file.suffix.lower()
            applicable_rules = self._rule_ext_map.get(ext, [])
            if not applicable_rules:
                skipped_files.append(clean_rel)
                continue

            # Read file safely as plain text (never execute or import)
            try:
                with open(target_file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception as read_err:
                logger.warning(f"Failed to read file {clean_rel}: {read_err}")
                skipped_files.append(clean_rel)
                continue

            lines = content.splitlines()
            files_scanned_count += 1
            total_lines_evaluated += len(lines)

            # Apply all matching rules
            for rule in applicable_rules:
                try:
                    matches = rule.scan_file(clean_rel, content)
                except Exception as rule_err:
                    logger.error(f"Rule {rule.rule_id} failed on file {clean_rel}: {rule_err}")
                    continue

                for match in matches:
                    dedup_key = f"{clean_rel}:{match.line_start}:{match.rule_id}"
                    if dedup_key in findings_map:
                        continue

                    # Stable deterministic ID
                    id_hash = hashlib.sha256(dedup_key.encode("utf-8")).hexdigest()[:10]
                    finding_id = f"find-{id_hash}"

                    # Ensure snippet and evidence have all secrets masked
                    sanitized_snippet = sanitize_text(match.snippet) if match.snippet else None
                    sanitized_evidence = sanitize_text(match.evidence)

                    finding = Finding(
                        id=finding_id,
                        rule_id=match.rule_id,
                        category=match.category,
                        title=match.title,
                        severity=match.severity,
                        confidence=match.confidence,
                        status="open",
                        location=FindingLocation(
                            file_path=clean_rel,
                            line_start=match.line_start,
                            line_end=match.line_end,
                            snippet=sanitized_snippet,
                        ),
                        evidence=sanitized_evidence,
                        impact=match.impact,
                        recommendation=match.recommendation,
                        verification_steps=match.verification_steps,
                    )
                    findings_map[dedup_key] = finding

        # Stable sorting by severity rank, then file path, line, rule_id
        sorted_findings = sorted(
            findings_map.values(),
            key=lambda f: (
                SEVERITY_RANK.get(f.severity.lower(), 99),
                f.location.file_path,
                f.location.line_start or 0,
                f.rule_id,
            ),
        )

        coverage = ScanCoverage(
            files_scanned=files_scanned_count,
            total_lines=total_lines_evaluated,
            rules_evaluated=self.total_rules_count,
            skipped_files=sorted(list(set(skipped_files))),
        )

        return sorted_findings, coverage, DEFAULT_LIMITATIONS
