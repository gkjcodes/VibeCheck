"""Rules for detecting HTML and frontend security risks (inline events, dangerouslySetInnerHTML, cleartext HTTP)."""

import re
from typing import List, Set
from backend.scanners.rules.base import BaseRule, RuleMatch
from backend.scanners.masking import sanitize_text


# Inline JS event handlers (e.g. onclick="...", onload='...', onerror=...)
INLINE_EVENT_PATTERN = re.compile(
    r"""(?i)\b(on(?:click|load|error|mouseover|submit|keydown|keyup|change))\s*=\s*["']([^"']+)["']"""
)

# React dangerouslySetInnerHTML
DANGEROUS_HTML_PATTERN = re.compile(
    r"""(?i)dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:"""
)

# Insecure HTTP resource loading (script, link, iframe, or api fetch in client code)
INSECURE_HTTP_RESOURCE = re.compile(
    r"""(?i)<(?:script|iframe|link|img)[^>]*(?:src|href)\s*=\s*["'](http://[^"'\s>]+)["']"""
)
INSECURE_HTTP_API = re.compile(
    r"""(?i)(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["'](http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"'\s]+)["']"""
)


class InlineEventHandlerRule(BaseRule):
    """Detects inline JavaScript event handlers in HTML, templates, or JSX markup."""

    rule_id = "VIBE-FE-INLINE"
    category = "frontend-risk"
    title = "Inline JavaScript Event Handler in Markup"
    severity = "medium"
    confidence = "high"
    supported_extensions: Set[str] = {".html", ".htm", ".vue", ".svelte", ".jsx", ".tsx", ".php"}
    description = (
        "Detects inline JavaScript event handlers (e.g., onclick, onload, onerror) embedded directly in markup, "
        "which impede Content Security Policy (CSP) enforcement and increase XSS risk."
    )

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("<!--") or stripped.startswith("//") or stripped.startswith("/*"):
                continue

            match = INLINE_EVENT_PATTERN.search(line)
            if not match:
                continue

            event_attr = match.group(1)
            event_val = match.group(2)
            snippet = sanitize_text(stripped)

            matches.append(
                RuleMatch(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line_start=idx,
                    line_end=idx,
                    snippet=snippet,
                    evidence=f"Inline event handler '{event_attr}=\"{event_val[:30]}\"' found in markup.",
                    impact=(
                        "Inline event handlers bypass strict Content Security Policies (CSP) requiring unsafe-inline, "
                        "and are prime targets for cross-site scripting (XSS) payload injection."
                    ),
                    recommendation=(
                        "Attach event listeners unobtrusively in JavaScript (e.g. element.addEventListener('click', ...)) "
                        "and adopt a strict Content-Security-Policy header without 'unsafe-inline'."
                    ),
                    verification_steps=[
                        "Refactor markup to attach events using addEventListener.",
                        "Confirm CSP policy disables 'unsafe-inline' for scripts.",
                    ],
                )
            )

        return matches


class DangerousHTMLRule(BaseRule):
    """Detects React/JSX dangerouslySetInnerHTML usage."""

    rule_id = "VIBE-FE-DANGEROUS-HTML"
    category = "frontend-risk"
    title = "Potentially Unsafe HTML Injection via dangerouslySetInnerHTML"
    severity = "high"
    confidence = "high"
    supported_extensions: Set[str] = {".jsx", ".tsx", ".js", ".ts"}
    description = (
        "Detects React components using dangerouslySetInnerHTML, which directly bypasses React's built-in "
        "HTML entity escaping protections."
    )

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            if not DANGEROUS_HTML_PATTERN.search(line):
                continue

            snippet = sanitize_text(stripped)

            matches.append(
                RuleMatch(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line_start=idx,
                    line_end=idx,
                    snippet=snippet,
                    evidence="Direct usage of React 'dangerouslySetInnerHTML' property detected.",
                    impact=(
                        "dangerouslySetInnerHTML injects raw HTML into the virtual DOM. If the injected content includes "
                        "unsanitized user or third-party input, it enables stored or reflected Cross-Site Scripting (XSS)."
                    ),
                    recommendation=(
                        "Avoid dangerouslySetInnerHTML when standard React JSX elements suffice. If rendering markdown "
                        "or HTML, sanitize with DOMPurify.sanitize() prior to injection."
                    ),
                    verification_steps=[
                        "Ensure all injected content is sanitized via DOMPurify before rendering.",
                    ],
                )
            )

        return matches


class InsecureHTTPResourceRule(BaseRule):
    """Detects cleartext HTTP resource inclusions or API communications."""

    rule_id = "VIBE-FE-HTTP-RESOURCE"
    category = "frontend-risk"
    title = "Insecure Cleartext HTTP Resource or Endpoint Reference"
    severity = "medium"
    confidence = "medium"
    supported_extensions: Set[str] = {".html", ".htm", ".jsx", ".tsx", ".js", ".ts", ".vue"}
    description = (
        "Detects scripts, iframes, stylesheets, or API calls fetched over unencrypted HTTP (http://) instead of HTTPS."
    )

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("<!--"):
                continue

            match_res = INSECURE_HTTP_RESOURCE.search(line)
            match_api = INSECURE_HTTP_API.search(line)

            target_url = None
            if match_res:
                target_url = match_res.group(1)
            elif match_api:
                target_url = match_api.group(1)

            if not target_url:
                continue

            # Skip localhost or private test addresses
            if any(host in target_url for host in ("localhost", "127.0.0.1", "0.0.0.0", "example.com")):
                continue

            snippet = sanitize_text(stripped)

            matches.append(
                RuleMatch(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=self.severity,
                    confidence=self.confidence,
                    file_path=file_path,
                    line_start=idx,
                    line_end=idx,
                    snippet=snippet,
                    evidence=f"Resource or API URL requested over unencrypted HTTP: '{target_url[:50]}'.",
                    impact=(
                        "Loading external assets or calling APIs over plaintext HTTP exposes user sessions to active "
                        "Man-in-the-Middle (MITM) tampering, code injection, and traffic eavesdropping."
                    ),
                    recommendation=(
                        "Update the URL scheme from http:// to https:// to ensure encrypted transit with TLS integrity."
                    ),
                    verification_steps=[
                        "Replace http:// with https://.",
                        "Verify TLS certificate validity on the remote endpoint.",
                    ],
                )
            )

        return matches
