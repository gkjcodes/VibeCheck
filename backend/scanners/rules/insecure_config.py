"""Rules for detecting insecure configuration (disabled TLS, debug mode, permissive CORS, insecure cookies)."""

import re
from typing import List, Set
from backend.scanners.rules.base import BaseRule, RuleMatch
from backend.scanners.masking import sanitize_text


# Disabled TLS verification patterns
TLS_VERIFY_FALSE_PY = re.compile(r"""(?i)\bverify\s*=\s*False\b""")
TLS_NODE_REJECT_UNAUTH = re.compile(r"""(?i)rejectUnauthorized\s*:\s*false\b""")
TLS_ENV_DISABLED = re.compile(r"""(?i)NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?""")

# Debug settings enabled
DEBUG_TRUE_PATTERN = re.compile(r"""(?i)\b(?:DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*["']?1["']?)""")

# Permissive CORS with credentials
CORS_WILDCARD_CRED = re.compile(
    r"""(?i)(?:allow_origins\s*=\s*\[\s*["']\*["']\s*\][^;]*allow_credentials\s*=\s*True|origin\s*:\s*["']\*["'][^}]*credentials\s*:\s*true)"""
)

# Insecure cookie settings
INSECURE_COOKIE_PATTERN = re.compile(
    r"""(?i)(?:set_cookie\([^)]*(?:secure\s*=\s*False|httponly\s*=\s*False)|cookie\s*:\s*\{[^}]*(?:secure\s*:\s*false|httpOnly\s*:\s*false))"""
)


class DisabledTLSVerificationRule(BaseRule):
    """Detects disabling of TLS / SSL certificate verification."""

    rule_id = "VIBE-CFG-TLS"
    category = "insecure-config"
    title = "Disabled TLS / SSL Certificate Verification"
    severity = "critical"
    confidence = "high"
    supported_extensions: Set[str] = {".py", ".js", ".ts", ".mjs", ".env", ".json"}
    description = (
        "Detects disabled TLS certificate validation (e.g. verify=False, rejectUnauthorized: false, or "
        "NODE_TLS_REJECT_UNAUTHORIZED='0') allowing trivial Man-In-The-Middle interception."
    )

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            matched = False
            evidence = ""

            if TLS_VERIFY_FALSE_PY.search(line):
                matched = True
                evidence = "HTTP request executed with 'verify=False' disabling TLS certificate validation."
            elif TLS_NODE_REJECT_UNAUTH.search(line):
                matched = True
                evidence = "HTTPS options configured with 'rejectUnauthorized: false'."
            elif TLS_ENV_DISABLED.search(line):
                matched = True
                evidence = "Environment configuration sets NODE_TLS_REJECT_UNAUTHORIZED='0'."

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
                    evidence=evidence,
                    impact=(
                        "Disabling TLS verification turns off certificate identity checks, permitting network eavesdroppers "
                        "and rogue proxies to intercept and alter sensitive data in transit without warning."
                    ),
                    recommendation=(
                        "Enable TLS certificate verification. If working with private certificates, provide a valid custom "
                        "CA bundle rather than disabling verification globally."
                    ),
                    verification_steps=[
                        "Remove verify=False or rejectUnauthorized: false settings.",
                        "Supply custom CA certificates via verify='/path/to/ca.pem' if internal roots are needed.",
                    ],
                )
            )

        return matches


class DebugModeEnabledRule(BaseRule):
    """Detects debug mode actively enabled in application configurations."""

    rule_id = "VIBE-CFG-DEBUG"
    category = "insecure-config"
    title = "Debug Mode Enabled in Application Configuration"
    severity = "high"
    confidence = "high"
    supported_extensions: Set[str] = {".py", ".env", ".ini", ".conf", ".yaml", ".yml"}
    description = "Detects debug flags (DEBUG=True, debug=True) enabled in application entrypoints or configs."

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            if not DEBUG_TRUE_PATTERN.search(line):
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
                    evidence="Application configured with active debug mode enabled.",
                    impact=(
                        "Running in debug mode often enables interactive browser debuggers that allow arbitrary code "
                        "execution, exposes full stack traces with source snippets, and reveals sensitive configuration."
                    ),
                    recommendation=(
                        "Set debug to False in production environments. Load the debug setting conditionally from "
                        "an environment variable (e.g. os.getenv('DEBUG', 'False').lower() == 'true')."
                    ),
                    verification_steps=[
                        "Ensure debug mode is disabled by default for deployed environments.",
                    ],
                )
            )

        return matches


class PermissiveCORSRule(BaseRule):
    """Detects permissive wildcard CORS origin combined with credential sharing."""

    rule_id = "VIBE-CFG-CORS"
    category = "insecure-config"
    title = "Permissive Wildcard CORS with Credentials"
    severity = "high"
    confidence = "high"
    supported_extensions: Set[str] = {".py", ".js", ".ts", ".mjs", ".cjs"}
    description = (
        "Detects CORS policies configured with wildcard origin ('*') while allowing credentials or authentication."
    )

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        # Check line-by-line and also short multi-line windows
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Check single line match or combine with next 2 lines
            combined = line
            if idx < len(lines):
                combined += " " + lines[idx].strip()
            if idx + 1 < len(lines):
                combined += " " + lines[idx + 1].strip()

            if not CORS_WILDCARD_CRED.search(combined):
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
                    evidence="CORS policy configured with wildcard '*' origin and allow_credentials enabled.",
                    impact=(
                        "Allowing all origins while enabling credentials exposes authenticated user data to unauthorized "
                        "third-party origins via cross-origin browser requests."
                    ),
                    recommendation=(
                        "Specify an explicit allowlist of authorized origins rather than wildcard '*', or disable credentials "
                        "if the endpoint is truly public."
                    ),
                    verification_steps=[
                        "Replace wildcard '*' with specific trusted domain origins.",
                        "Test preflight CORS response headers to verify only trusted origins receive credentials.",
                    ],
                )
            )

        return matches


class InsecureCookieRule(BaseRule):
    """Detects cookies configured without Secure or HttpOnly flags."""

    rule_id = "VIBE-CFG-COOKIE"
    category = "insecure-config"
    title = "Insecure Cookie Configuration Missing Secure or HttpOnly"
    severity = "medium"
    confidence = "medium"
    supported_extensions: Set[str] = {".py", ".js", ".ts", ".mjs", ".cjs"}
    description = "Detects cookies set with secure=False or httponly=False flags."

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            if not INSECURE_COOKIE_PATTERN.search(line):
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
                    evidence="Cookie configuration explicitly disables Secure or HttpOnly protection.",
                    impact=(
                        "Cookies missing the Secure flag can be leaked over plaintext HTTP, and cookies missing HttpOnly "
                        "can be stolen by client-side scripts during XSS attacks."
                    ),
                    recommendation=(
                        "Always configure sensitive session cookies with secure=True, httponly=True, and SameSite='Lax' or 'Strict'."
                    ),
                    verification_steps=[
                        "Set secure=True and httponly=True on all session and authentication cookies.",
                    ],
                )
            )

        return matches
