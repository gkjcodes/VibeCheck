"""Scan comparison and rescan verification engine for VibeCheck Phase 5."""

import re
from typing import Dict, List, Optional, Set, Tuple
import uuid

from backend.app.schemas.comparison import (
    ComparisonFindingItem,
    ComparisonResult,
    ComparisonSummary,
    FindingDisposition,
)
from backend.app.schemas.finding import Finding, FindingLocation
from backend.app.schemas.scan import ScanResponse
from backend.remediation.generator import scrub_all_secrets, validate_and_sanitize_path


def normalize_path(path: Optional[str]) -> str:
    """Normalize file path for cross-platform, deterministic comparison."""
    if not path or not isinstance(path, str):
        return ""
    path_str = path.replace("\\", "/").strip()
    path_str = re.sub(r"^(\./)+", "", path_str)
    path_str = re.sub(r"/+", "/", path_str)

    clean, is_valid = validate_and_sanitize_path(path_str)
    if is_valid:
        return clean.lower()

    # If invalid under strict relative POSIX (e.g. traversal or absolute), strip dangerous traversal components
    segments = [s for s in path_str.split("/") if s and s not in (".", "..")]
    if not segments:
        return ""
    return "/".join(segments).lower()


class ScanComparator:
    """Deterministic comparison engine analyzing baseline vs post-remediation scans."""

    def compare(
        self,
        baseline_scan: ScanResponse,
        current_scan: ScanResponse,
        comparison_id: Optional[str] = None,
    ) -> ComparisonResult:
        """Compare baseline scan and rescan to produce honest, grounded dispositions."""
        if not isinstance(baseline_scan, ScanResponse) or not isinstance(current_scan, ScanResponse):
            raise TypeError("Both baseline_scan and current_scan must be ScanResponse instances.")

        comp_id = comparison_id or f"comp_{uuid.uuid4().hex[:12]}"
        project = current_scan.project or baseline_scan.project or "submitted-project"

        baseline_findings = baseline_scan.findings or []
        current_findings = current_scan.findings or []

        # 1. Audit Scan Integrity & Coverage Boundaries
        baseline_failed = (baseline_scan.status or "").lower() != "completed"
        current_failed = (current_scan.status or "").lower() != "completed"
        is_scan_complete = not (baseline_failed or current_failed)

        # Normalize skipped files in current scan
        current_skipped_paths: Set[str] = set()
        if current_scan.coverage and current_scan.coverage.skipped_files:
            for sp in current_scan.coverage.skipped_files:
                norm_sp = normalize_path(sp)
                if norm_sp:
                    current_skipped_paths.add(norm_sp)

        verification_limitations: List[str] = []
        if baseline_failed:
            verification_limitations.append(
                f"Baseline scan status is '{baseline_scan.status}'; baseline may be incomplete or invalid."
            )
        if current_failed:
            verification_limitations.append(
                f"Post-remediation rescan status is '{current_scan.status}'; vulnerabilities cannot be verified as resolved."
            )
        if current_scan.coverage and current_scan.coverage.files_scanned == 0:
            verification_limitations.append(
                "Post-remediation rescan evaluated zero files; no verification possible."
            )
        if current_skipped_paths:
            verification_limitations.append(
                f"Rescan skipped {len(current_skipped_paths)} file(s); findings in these files cannot be verified."
            )
        if (
            baseline_scan.coverage
            and current_scan.coverage
            and baseline_scan.coverage.rules_evaluated is not None
            and current_scan.coverage.rules_evaluated is not None
            and current_scan.coverage.rules_evaluated < baseline_scan.coverage.rules_evaluated
        ):
            verification_limitations.append(
                f"Rescan evaluated fewer security rules ({current_scan.coverage.rules_evaluated}) than baseline ({baseline_scan.coverage.rules_evaluated})."
            )

        # 2. Match Baseline vs Current Findings
        # Determine candidate matches using deterministic scoring
        matched_pairs, unmatched_baseline, unmatched_current = self._match_findings(
            baseline_findings, current_findings
        )

        comparison_items: List[ComparisonFindingItem] = []
        resolved_count = 0
        still_present_count = 0
        new_count = 0
        not_verifiable_count = 0

        # 3. Classify Matched Findings (STILL_PRESENT)
        for base_f, curr_f, rationale in matched_pairs:
            still_present_count += 1
            item = ComparisonFindingItem(
                finding_id=curr_f.id or base_f.id,
                disposition=FindingDisposition.STILL_PRESENT,
                rule_id=curr_f.rule_id or base_f.rule_id,
                category=curr_f.category or base_f.category,
                title=curr_f.title or base_f.title,
                severity_before=base_f.severity,
                severity_after=curr_f.severity,
                location_before=base_f.location,
                location_after=curr_f.location,
                snippet_before=base_f.location.snippet if base_f.location else None,
                snippet_after=curr_f.location.snippet if curr_f.location else None,
                evidence_before=scrub_all_secrets(base_f.evidence or ""),
                evidence_after=scrub_all_secrets(curr_f.evidence or ""),
                match_rationale=rationale,
                unverifiable_reason=None,
                baseline_id=base_f.id,
                current_id=curr_f.id,
            )
            comparison_items.append(item)

        # 4. Classify Unmatched Baseline Findings (RESOLVED or NOT_VERIFIABLE)
        for base_f in unmatched_baseline:
            base_path = normalize_path(base_f.location.file_path if base_f.location else "")

            # Check for conditions preventing verification:
            # Condition A: Rescan failed or was incomplete
            if current_failed:
                not_verifiable_count += 1
                item = ComparisonFindingItem(
                    finding_id=base_f.id,
                    disposition=FindingDisposition.NOT_VERIFIABLE,
                    rule_id=base_f.rule_id,
                    category=base_f.category,
                    title=base_f.title,
                    severity_before=base_f.severity,
                    severity_after=None,
                    location_before=base_f.location,
                    location_after=None,
                    snippet_before=base_f.location.snippet if base_f.location else None,
                    snippet_after=None,
                    evidence_before=scrub_all_secrets(base_f.evidence or ""),
                    evidence_after=None,
                    match_rationale=None,
                    unverifiable_reason=(
                        f"Post-remediation rescan execution status is '{current_scan.status}' (failed/incomplete); "
                        "cannot conclusively verify resolution."
                    ),
                    baseline_id=base_f.id,
                    current_id=None,
                )
                comparison_items.append(item)
                continue

            # Condition B: Rescan evaluated 0 files
            if current_scan.coverage and current_scan.coverage.files_scanned == 0:
                not_verifiable_count += 1
                item = ComparisonFindingItem(
                    finding_id=base_f.id,
                    disposition=FindingDisposition.NOT_VERIFIABLE,
                    rule_id=base_f.rule_id,
                    category=base_f.category,
                    title=base_f.title,
                    severity_before=base_f.severity,
                    severity_after=None,
                    location_before=base_f.location,
                    location_after=None,
                    snippet_before=base_f.location.snippet if base_f.location else None,
                    snippet_after=None,
                    evidence_before=scrub_all_secrets(base_f.evidence or ""),
                    evidence_after=None,
                    match_rationale=None,
                    unverifiable_reason="Rescan inspected zero files; verification not possible.",
                    baseline_id=base_f.id,
                    current_id=None,
                )
                comparison_items.append(item)
                continue

            # Condition C: Relevant file was skipped in rescan
            if base_path and base_path in current_skipped_paths:
                not_verifiable_count += 1
                item = ComparisonFindingItem(
                    finding_id=base_f.id,
                    disposition=FindingDisposition.NOT_VERIFIABLE,
                    rule_id=base_f.rule_id,
                    category=base_f.category,
                    title=base_f.title,
                    severity_before=base_f.severity,
                    severity_after=None,
                    location_before=base_f.location,
                    location_after=None,
                    snippet_before=base_f.location.snippet if base_f.location else None,
                    snippet_after=None,
                    evidence_before=scrub_all_secrets(base_f.evidence or ""),
                    evidence_after=None,
                    match_rationale=None,
                    unverifiable_reason=(
                        f"File '{base_f.location.file_path}' was skipped during rescan; "
                        "resolution cannot be verified."
                    ),
                    baseline_id=base_f.id,
                    current_id=None,
                )
                comparison_items.append(item)
                continue

            # Condition D: Conclusively verified as RESOLVED
            resolved_count += 1
            item = ComparisonFindingItem(
                finding_id=base_f.id,
                disposition=FindingDisposition.RESOLVED,
                rule_id=base_f.rule_id,
                category=base_f.category,
                title=base_f.title,
                severity_before=base_f.severity,
                severity_after=None,
                location_before=base_f.location,
                location_after=None,
                snippet_before=base_f.location.snippet if base_f.location else None,
                snippet_after=None,
                evidence_before=scrub_all_secrets(base_f.evidence or ""),
                evidence_after=None,
                match_rationale="Vulnerability pattern no longer detected in scanned file context.",
                unverifiable_reason=None,
                baseline_id=base_f.id,
                current_id=None,
            )
            comparison_items.append(item)

        # 5. Classify Unmatched Current Findings (NEW)
        for curr_f in unmatched_current:
            new_count += 1
            item = ComparisonFindingItem(
                finding_id=curr_f.id,
                disposition=FindingDisposition.NEW,
                rule_id=curr_f.rule_id,
                category=curr_f.category,
                title=curr_f.title,
                severity_before=None,
                severity_after=curr_f.severity,
                location_before=None,
                location_after=curr_f.location,
                snippet_before=None,
                snippet_after=curr_f.location.snippet if curr_f.location else None,
                evidence_before=None,
                evidence_after=scrub_all_secrets(curr_f.evidence or ""),
                match_rationale="New finding introduced in rescan with no baseline match.",
                unverifiable_reason=None,
                baseline_id=None,
                current_id=curr_f.id,
            )
            comparison_items.append(item)

        # 6. Build Summary & Result
        summary = ComparisonSummary(
            baseline_total=len(baseline_findings),
            current_total=len(current_findings),
            resolved_count=resolved_count,
            still_present_count=still_present_count,
            new_count=new_count,
            not_verifiable_count=not_verifiable_count,
            is_scan_complete=is_scan_complete,
            verification_limitations=verification_limitations,
        )

        overall_status = "completed"
        if not is_scan_complete or not_verifiable_count > 0:
            overall_status = "inconclusive" if is_scan_complete else "failed"

        combined_limitations = list(
            dict.fromkeys((current_scan.limitations or []) + (baseline_scan.limitations or []) + verification_limitations)
        )

        return ComparisonResult(
            comparison_id=comp_id,
            baseline_scan_id=baseline_scan.scan_id,
            current_scan_id=current_scan.scan_id,
            project=project,
            status=overall_status,
            summary=summary,
            findings=comparison_items,
            limitations=combined_limitations,
        )

    def _match_findings(
        self,
        baseline_findings: List[Finding],
        current_findings: List[Finding],
    ) -> Tuple[List[Tuple[Finding, Finding, str]], List[Finding], List[Finding]]:
        """Deterministically match baseline findings to current findings."""
        matched_pairs: List[Tuple[Finding, Finding, str]] = []
        unmatched_baseline: List[Finding] = []
        unmatched_current: List[Finding] = list(current_findings)

        # Pre-compute normalized metadata for candidate comparisons
        candidate_scores: List[Tuple[int, int, int, str]] = []  # (score, base_idx, curr_idx, rationale)

        for b_idx, b_f in enumerate(baseline_findings):
            b_path = normalize_path(b_f.location.file_path if b_f.location else "")
            b_rule = (b_f.rule_id or "").strip().upper()
            b_cat = (b_f.category or "").strip().lower()
            b_line = b_f.location.line_start if b_f.location and b_f.location.line_start is not None else 0
            b_ev = (b_f.evidence or "").strip()
            b_snip = (b_f.location.snippet or "").strip() if b_f.location else ""

            for c_idx, c_f in enumerate(current_findings):
                c_path = normalize_path(c_f.location.file_path if c_f.location else "")
                c_rule = (c_f.rule_id or "").strip().upper()
                c_cat = (c_f.category or "").strip().lower()
                c_line = c_f.location.line_start if c_f.location and c_f.location.line_start is not None else 0
                c_ev = (c_f.evidence or "").strip()
                c_snip = (c_f.location.snippet or "").strip() if c_f.location else ""

                # Evaluate compatibility
                score = 0
                reasons: List[str] = []

                same_path = (b_path == c_path and b_path != "")
                same_rule = (b_rule == c_rule and b_rule != "")
                same_cat = (b_cat == c_cat and b_cat != "")

                if same_path:
                    score += 40
                if same_rule:
                    score += 35
                if same_cat:
                    score += 10

                # Exact ID match
                if b_f.id and c_f.id and b_f.id == c_f.id:
                    score += 15
                    reasons.append("Exact finding ID match")

                # Code evidence / snippet match
                if b_ev and c_ev and b_ev == c_ev:
                    score += 20
                    reasons.append("Identical evidence match")
                elif b_snip and c_snip and b_snip == c_snip:
                    score += 15
                    reasons.append("Identical code snippet match")
                elif b_ev and c_ev and (b_ev in c_ev or c_ev in b_ev):
                    score += 10
                    reasons.append("Partial evidence correlation")

                # Line coordinate correlation
                if same_path and b_line > 0 and c_line > 0:
                    diff = abs(b_line - c_line)
                    if diff == 0:
                        score += 10
                        reasons.append(f"Exact line match ({b_line})")
                    elif diff <= 5:
                        score += 7
                        reasons.append(f"Minor line shift (line {b_line} -> {c_line})")
                    elif diff <= 25:
                        score += 4
                        reasons.append(f"Moderate line shift (line {b_line} -> {c_line})")

                # Minimum threshold to be considered a viable match:
                # Requires (same path + same rule) OR (same rule + identical evidence/snippet)
                if (same_path and same_rule) or (same_rule and same_cat and (score >= 60)):
                    # Build detailed rationale
                    desc = f"Matched by rule '{b_f.rule_id}'"
                    if same_path:
                        desc += f" in '{b_f.location.file_path}'"
                    if b_line != c_line and b_line > 0 and c_line > 0:
                        desc += f" (line shifted from {b_line} to {c_line})"
                    elif b_line > 0:
                        desc += f" at line {b_line}"
                    if b_f.id != c_f.id:
                        desc += f" [ID changed from {b_f.id} to {c_f.id}]"
                    if b_f.severity != c_f.severity:
                        desc += f" [Severity changed from {b_f.severity} to {c_f.severity}]"

                    candidate_scores.append((score, b_idx, c_idx, desc))

        # Sort candidate matches by highest score first, then lowest line difference, then deterministically
        candidate_scores.sort(
            key=lambda x: (
                -x[0],
                abs(
                    (baseline_findings[x[1]].location.line_start or 0)
                    - (current_findings[x[2]].location.line_start or 0)
                ),
                baseline_findings[x[1]].id or "",
                current_findings[x[2]].id or "",
            )
        )

        matched_base_indices: Set[int] = set()
        matched_curr_indices: Set[int] = set()

        for score, b_idx, c_idx, rationale in candidate_scores:
            if b_idx in matched_base_indices or c_idx in matched_curr_indices:
                continue

            matched_base_indices.add(b_idx)
            matched_curr_indices.add(c_idx)
            matched_pairs.append((baseline_findings[b_idx], current_findings[c_idx], rationale))

        for b_idx, b_f in enumerate(baseline_findings):
            if b_idx not in matched_base_indices:
                unmatched_baseline.append(b_f)

        unmatched_current = [
            c_f for c_idx, c_f in enumerate(current_findings) if c_idx not in matched_curr_indices
        ]

        return matched_pairs, unmatched_baseline, unmatched_current


def compare_scans(
    baseline_scan: ScanResponse,
    current_scan: ScanResponse,
    comparison_id: Optional[str] = None,
) -> ComparisonResult:
    """Convenience function for performing scan comparisons."""
    comparator = ScanComparator()
    return comparator.compare(baseline_scan, current_scan, comparison_id)
