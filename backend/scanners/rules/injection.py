"""Rules for detecting injection risks (SQL injection, command injection, dynamic evaluation)."""

import re
from typing import List, Set
from backend.scanners.rules.base import BaseRule, RuleMatch
from backend.scanners.masking import sanitize_text


# SQL injection patterns (f-string or string concatenation inside queries or execute calls)
SQL_KEYWORDS = r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|FROM|WHERE)\b"

SQL_EXECUTE_FSTRING = re.compile(
    rf"""(?i)\b(?:execute|raw_query|query)\s*\(\s*f["'].*?{SQL_KEYWORDS}.*?\{{[^}}]+\}}.*?["]\s*"""
)
SQL_CONCAT_PATTERN = re.compile(
    rf"""(?i)["'].*?{SQL_KEYWORDS}.*?["']\s*\+\s*[a-zA-Z0-9_.]+|[a-zA-Z0-9_.]+\s*\+\s*["'].*?{SQL_KEYWORDS}"""
)
SQL_TEMPLATE_LITERAL = re.compile(
    rf"""(?i)\b(?:query|execute|sql)\s*\(\s*`.*?{SQL_KEYWORDS}.*?\${{[^}}]+}}.*?`\s*"""
)

# Command injection patterns
SHELL_TRUE_PATTERN = re.compile(
    r"""(?i)\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True"""
)
OS_SYSTEM_PATTERN = re.compile(
    r"""(?i)\bos\.(?:system|popen)\s*\(\s*(?:f["'][^"']*\{[^}]+\}|[^)]*\+|[a-zA-Z0-9_]+\s*\))"""
)
NODE_EXEC_PATTERN = re.compile(
    r"""(?i)\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\${[^}]+}|["'][^"']*["']\s*\+|[a-zA-Z0-9_]+\s*\))"""
)

# Dynamic evaluation in Python
PYTHON_EVAL_PATTERN = re.compile(
    r"""(?i)\b(?:eval|exec)\s*\(\s*(?!["'][^"']*["']\s*\))([a-zA-Z0-9_.(), ]+)\)"""
)


class SQLInjectionRule(BaseRule):
    """Detects SQL queries built via string concatenation or interpolation."""

    rule_id = "VIBE-INJ-SQL"
    category = "injection"
    title = "Potential SQL Injection via String Interpolation or Concatenation"
    severity = "critical"
    confidence = "high"
    supported_extensions: Set[str] = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
    description = (
        "Detects SQL query strings constructed with direct string formatting (f-strings, template literals, "
        "or string concatenation) rather than parameterized queries."
    )

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            is_fstring = SQL_EXECUTE_FSTRING.search(line)
            is_concat = SQL_CONCAT_PATTERN.search(line)
            is_template = SQL_TEMPLATE_LITERAL.search(line)

            if not (is_fstring or is_concat or is_template):
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
                    evidence="Dynamic SQL construction detected with variable interpolation or concatenation.",
                    impact=(
                        "Building SQL statements with dynamic string interpolation enables attackers to manipulate query "
                        "syntax, bypass authentication, extract confidential data, or tamper with the database."
                    ),
                    recommendation=(
                        "Use parameterized queries (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))) "
                        "or an ORM rather than manual string concatenation."
                    ),
                    verification_steps=[
                        "Convert interpolated query string to parameterized statement.",
                        "Pass variables as parameter tuples or arrays separated from the query text.",
                    ],
                )
            )

        return matches


class CommandInjectionRule(BaseRule):
    """Detects command execution with shell=True or unescaped string arguments."""

    rule_id = "VIBE-INJ-SHELL"
    category = "injection"
    title = "Potential Command Injection via Shell Execution"
    severity = "critical"
    confidence = "high"
    supported_extensions: Set[str] = {".py", ".js", ".ts", ".mjs", ".cjs"}
    description = (
        "Detects invocations of system shell commands (subprocess shell=True, os.system, child_process.exec) "
        "using dynamic or concatenated arguments."
    )

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            matched = False
            label = ""

            if SHELL_TRUE_PATTERN.search(line):
                matched = True
                label = "subprocess with shell=True"
            elif OS_SYSTEM_PATTERN.search(line):
                matched = True
                label = "os.system or os.popen with dynamic argument"
            elif NODE_EXEC_PATTERN.search(line):
                matched = True
                label = "child_process.exec with dynamic argument"

            if not matched:
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
                    evidence=f"Shell execution construct '{label}' identified.",
                    impact=(
                        "Executing shell commands with untrusted inputs allows attackers to append arbitrary system commands "
                        "(e.g., using semicolons or pipes), leading to remote host takeover."
                    ),
                    recommendation=(
                        "Avoid shell=True. Pass arguments as a list of strings to subprocess.run(..., shell=False) or use "
                        "execFile with sanitized argument arrays."
                    ),
                    verification_steps=[
                        "Remove shell=True and pass command arguments as explicit arrays.",
                        "Validate all arguments against a strict allowlist.",
                    ],
                )
            )

        return matches


class DynamicCodeEvalRule(BaseRule):
    """Detects dynamic code evaluation via eval() or exec() in Python."""

    rule_id = "VIBE-INJ-DYNAMIC"
    category = "injection"
    title = "Unsafe Dynamic Python eval() or exec() Execution"
    severity = "high"
    confidence = "high"
    supported_extensions: Set[str] = {".py", ".pyw"}
    description = "Detects Python eval() or exec() calls using dynamic variables or expressions."

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            match = PYTHON_EVAL_PATTERN.search(line)
            if not match:
                continue

            # Skip common test fixtures or ast.literal_eval
            if "literal_eval" in line:
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
                    evidence=f"Dynamic evaluation call '{match.group(0)[:40]}' detected.",
                    impact=(
                        "exec() and eval() parse and execute strings as Python code, enabling arbitrary remote code execution "
                        "if user input reaches the evaluation environment."
                    ),
                    recommendation=(
                        "Replace dynamic eval/exec with ast.literal_eval for safe literals or safe parser combinators."
                    ),
                    verification_steps=[
                        "Refactor code to eliminate eval() / exec().",
                        "If parsing literal structures, replace with ast.literal_eval.",
                    ],
                )
            )

        return matches
