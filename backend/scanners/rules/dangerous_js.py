"""Rules for detecting dangerous JavaScript patterns (eval, innerHTML, dynamic code construction)."""

import re
from typing import List, Set
from backend.scanners.rules.base import BaseRule, RuleMatch
from backend.scanners.masking import sanitize_text


# Regex for eval calls (eval(anything))
EVAL_PATTERN = re.compile(r"""\beval\s*\(([^)]*)\)""")

# Regex for direct assignment to innerHTML / outerHTML
INNER_HTML_PATTERN = re.compile(r"""\b(?:innerHTML|outerHTML)\s*=(?!=)\s*([^;]+)""")

# Regex for new Function(...) or string execution in timer functions
DYNAMIC_FUNC_PATTERN = re.compile(r"""\bnew\s+Function\s*\(([^)]*)\)""")
TIMER_STRING_PATTERN = re.compile(r"""\b(?:setTimeout|setInterval)\s*\(\s*["'`][^"'`]+["'`]\s*\+""")


class EvalRule(BaseRule):
    """Detects dangerous use of eval() in JavaScript / TypeScript code."""

    rule_id = "VIBE-JS-EVAL"
    category = "dangerous-js"
    title = "Dangerous JavaScript eval() Invocation"
    severity = "high"
    confidence = "high"
    supported_extensions: Set[str] = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html"}
    description = "Detects direct invocations of eval() which execute arbitrary text as code in JavaScript."

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Ignore single-line comments
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            match = EVAL_PATTERN.search(line)
            if not match:
                continue

            arg_content = match.group(1).strip()
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
                    evidence=f"Direct call to eval({arg_content[:40]}) detected.",
                    impact=(
                        "Using eval() allows execution of arbitrary JavaScript code. If user-controlled data or untrusted "
                        "inputs reach eval(), it leads directly to Client-Side or Server-Side Remote Code Execution."
                    ),
                    recommendation=(
                        "Avoid eval(). Use structured JSON parsing (JSON.parse), predefined dictionary mappings, or "
                        "standard arithmetic functions instead of dynamic string evaluation."
                    ),
                    verification_steps=[
                        "Refactor code to eliminate eval().",
                        "Verify with linter (e.g. ESLint no-eval rule).",
                    ],
                )
            )

        return matches


class InnerHTMLRule(BaseRule):
    """Detects potentially unsafe assignment to innerHTML or outerHTML."""

    rule_id = "VIBE-JS-INNERHTML"
    category = "dangerous-js"
    title = "Unsafe Assignment to innerHTML"
    severity = "medium"
    confidence = "medium"
    supported_extensions: Set[str] = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".html"}
    description = (
        "Detects direct assignments to element.innerHTML or outerHTML which may introduce Cross-Site Scripting (XSS)."
    )

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            match = INNER_HTML_PATTERN.search(line)
            if not match:
                continue

            assigned_expr = match.group(1).strip()
            # If it's assigning an empty string or fixed static literal with no tags, lower false positive
            if assigned_expr in {"''", '""', "``"}:
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
                    evidence=f"Assignment to innerHTML/outerHTML with expression '{assigned_expr[:40]}'.",
                    impact=(
                        "Assigning unsanitized input to innerHTML can allow malicious actors to inject executable script tags "
                        "or event handlers, causing Cross-Site Scripting (DOM XSS)."
                    ),
                    recommendation=(
                        "Use textContent or innerText when rendering text. If HTML rendering is required, sanitize input "
                        "using a DOM sanitization library like DOMPurify."
                    ),
                    verification_steps=[
                        "Replace innerHTML with textContent where plain text is expected.",
                        "If HTML is required, pipe output through DOMPurify.sanitize().",
                    ],
                )
            )

        return matches


class DynamicFunctionRule(BaseRule):
    """Detects unsafe dynamic code construction via Function constructor or timer strings."""

    rule_id = "VIBE-JS-NEWFUNC"
    category = "dangerous-js"
    title = "Dynamic Code Construction via Function Constructor"
    severity = "high"
    confidence = "medium"
    supported_extensions: Set[str] = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    description = "Detects new Function(...) or string evaluations in setTimeout/setInterval."

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            is_func = DYNAMIC_FUNC_PATTERN.search(line)
            is_timer = TIMER_STRING_PATTERN.search(line)

            if not (is_func or is_timer):
                continue

            snippet = sanitize_text(stripped)
            matched_label = "new Function(...)" if is_func else "timer string concatenation"

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
                    evidence=f"Dynamic code evaluation construct '{matched_label}' identified.",
                    impact=(
                        "Constructing dynamic functions from strings opens the application to arbitrary code execution "
                        "similar to eval()."
                    ),
                    recommendation=(
                        "Refactor code to use explicit callback functions or standard closure functions instead of "
                        "dynamic string compilation."
                    ),
                    verification_steps=[
                        "Pass an arrow function or function reference instead of a compiled string or Function constructor.",
                    ],
                )
            )

        return matches
