"""Rules for detecting hardcoded secrets, API tokens, and private keys."""

import re
from typing import List, Set
from backend.scanners.rules.base import BaseRule, RuleMatch
from backend.scanners.masking import mask_secret, sanitize_text


# High-entropy / provider-specific API token signatures
KNOWN_KEY_PATTERNS = [
    (re.compile(r"((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{16,})"), "Stripe API Key"),
    (re.compile(r"(AIzaSy[0-9A-Za-z-_]{33})"), "Google API / Firebase Key"),
    (re.compile(r"(gh[pousr]_[0-9a-zA-Z]{36})"), "GitHub Personal Access Token"),
    (re.compile(r"(AKIA[0-9A-Z]{16})"), "AWS Access Key ID"),
    (re.compile(r"(xox[baprs]-[0-9a-zA-Z-]{10,48})"), "Slack Access Token"),
]

# Patterns for hardcoded credentials / passwords
ASSIGNMENT_CRED_PATTERN = re.compile(
    r"""(?i)(?:^|[\s,;{(])(?:password|passwd|pwd|client_secret|api_secret|db_pass|secret_key|auth_token)\s*[:=]\s*["']([^"'\r\n\t]{6,})["']"""
)

# Placeholders that are not real credentials
PLACEHOLDER_SUBSTRINGS = {
    "dummy", "placeholder", "example", "replace_me", "your_", "<your", "test_key",
    "fake", "sample", "changeme", "change_me", "secret123", "password123", "todo",
}

# Private key block header
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----")


class ExposedSecretRule(BaseRule):
    """Detects exposed API tokens, cloud keys, and access tokens."""

    rule_id = "VIBE-SEC-KEY"
    category = "hardcoded-secret"
    title = "Exposed Production API Key or Access Token"
    severity = "critical"
    confidence = "high"
    supported_extensions: Set[str] = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
        ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf",
        ".html", ".htm", ".txt", ".md", ".markdown", ".sql", ".sh", ".css",
    }
    description = (
        "Detects hardcoded API keys and third-party tokens (e.g., Stripe, AWS, Google, GitHub) "
        "committed in source code files."
    )

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            for regex, provider_name in KNOWN_KEY_PATTERNS:
                for match in regex.finditer(line):
                    raw_token = match.group(1)
                    lower_val = raw_token.lower()
                    if any(ph in lower_val for ph in PLACEHOLDER_SUBSTRINGS):
                        continue

                    masked_token = mask_secret(raw_token)
                    sanitized_snippet = sanitize_text(line.strip(), raw_token)

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
                            snippet=sanitized_snippet,
                            evidence=f"Detected {provider_name} token format '{masked_token}'.",
                            impact=(
                                "Exposing third-party API credentials in source files allows attackers to "
                                "access associated cloud services, impersonate the application, and trigger unauthorized actions."
                            ),
                            recommendation=(
                                "Extract credentials into secure environment variables (e.g. process.env or os.environ) "
                                "and immediately revoke/rotate the exposed token in your provider dashboard."
                            ),
                            verification_steps=[
                                "Remove the hardcoded secret from the source code.",
                                "Configure a secrets manager or .env file excluded from version control.",
                                "Revoke and regenerate the compromised token in the provider console.",
                            ],
                        )
                    )

        return matches


class HardcodedCredentialRule(BaseRule):
    """Detects hardcoded passwords, database secrets, and client secrets assigned in code."""

    rule_id = "VIBE-SEC-CRED"
    category = "hardcoded-secret"
    title = "Hardcoded Password or Client Secret"
    severity = "high"
    confidence = "medium"
    supported_extensions: Set[str] = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
        ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf",
    }
    description = (
        "Detects static literal passwords, client secrets, and database credentials assigned directly in source code."
    )

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            match = ASSIGNMENT_CRED_PATTERN.search(line)
            if not match:
                continue

            secret_val = match.group(1)
            lower_val = secret_val.lower()

            # Ignore obvious placeholders and common dummy defaults
            if any(ph in lower_val for ph in PLACEHOLDER_SUBSTRINGS):
                continue
            if lower_val in {"password", "secret", "admin", "root", "123456", "true", "false", "none", "null"}:
                continue

            # Ignore environmental lookups or references
            if "process.env" in line or "os.getenv" in line or "os.environ" in line:
                continue

            masked_val = mask_secret(secret_val)
            sanitized_snippet = sanitize_text(line.strip(), secret_val)

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
                    snippet=sanitized_snippet,
                    evidence=f"Hardcoded credential assignment detected matching literal '{masked_val}'.",
                    impact=(
                        "Hardcoded credentials expose administrative or internal system access to anyone with read "
                        "access to the codebase or bundled artifacts."
                    ),
                    recommendation=(
                        "Store credentials in environment variables or a vault, and inject them securely at runtime."
                    ),
                    verification_steps=[
                        "Replace literal string credential with an environment variable reference.",
                        "Verify no plain secrets remain in committed project files.",
                    ],
                )
            )

        return matches


class PrivateKeyRule(BaseRule):
    """Detects embedded cryptographic private keys."""

    rule_id = "VIBE-SEC-PRIVKEY"
    category = "hardcoded-secret"
    title = "Hardcoded Private Key Material"
    severity = "critical"
    confidence = "high"
    supported_extensions: Set[str] = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
        ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf",
        ".pem", ".key", ".txt",
    }
    description = "Detects embedded PEM-encoded RSA/EC/DSA/OPENSSH private key blocks in project files."

    def scan_file(self, file_path: str, content: str) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        lines = content.splitlines()

        for idx, line in enumerate(lines, start=1):
            if PRIVATE_KEY_HEADER.search(line):
                sanitized_snippet = "-----BEGIN PRIVATE KEY----- [KEY MATERIAL REDACTED]"
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
                        snippet=sanitized_snippet,
                        evidence="Embedded PEM private key block header detected in source file.",
                        impact=(
                            "Exposing private keys allows adversaries to decrypt traffic, forge digital signatures, "
                            "and compromise TLS, SSH, or identity infrastructure."
                        ),
                        recommendation=(
                            "Remove the private key from source control immediately, store keys on secure key management "
                            "hardware or environment secrets, and regenerate compromised key pairs."
                        ),
                        verification_steps=[
                            "Delete private key blocks from application source code.",
                            "Rotate key pairs and issue new certificates or authorization credentials.",
                        ],
                    )
                )

        return matches
