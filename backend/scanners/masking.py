"""Sensitive data redaction and masking utilities for security findings."""

from pathlib import Path
import re
from typing import Optional, Tuple

# Common secret pattern regexes for secondary defense-in-depth masking
SECRET_PATTERNS = [
    re.compile(r"((?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{16,})"),
    re.compile(r"(AIzaSy[0-9A-Za-z-_]{33})"),
    re.compile(r"(gh[pousr]_[0-9a-zA-Z]{36})"),
    re.compile(r"(xox[baprs]-[0-9a-zA-Z-]{10,})"),
    re.compile(r"(AKIA[0-9A-Z]{16})"),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
]


def mask_secret(secret: str) -> str:
    """Mask a secret value so sensitive credentials are never leaked in plain text.
    
    Examples:
        sk_live_51MzXYZ1234567890abcdef -> sk_live_****cdef
        AIzaSyA12345678901234567890123456 -> AIzaSy****3456
        supersecretpassword -> supe****word
    """
    if not secret:
        return "[REDACTED]"

    clean_secret = secret.strip().strip("'\"`")
    length = len(clean_secret)

    if length <= 8:
        return "****"

    # Known structured key prefixes
    for prefix in ("sk_live_", "sk_test_", "pk_live_", "pk_test_", "AIzaSy", "ghp_", "AKIA"):
        if clean_secret.startswith(prefix):
            suffix_len = min(4, max(2, length - len(prefix) - 4))
            suffix = clean_secret[-suffix_len:] if suffix_len > 0 else ""
            return f"{prefix}****{suffix}"

    # Generic masking: show first 4 and last 4
    prefix_len = min(4, length // 4)
    suffix_len = min(4, length // 4)
    return f"{clean_secret[:prefix_len]}****{clean_secret[-suffix_len:]}"


def sanitize_text(text: str, specific_secret: Optional[str] = None) -> str:
    """Mask specific and recognized secrets within a text snippet or evidence string."""
    if not text:
        return ""

    sanitized = text

    # First, replace the specifically identified secret
    if specific_secret and specific_secret in sanitized:
        masked = mask_secret(specific_secret)
        sanitized = sanitized.replace(specific_secret, masked)

    # Secondary sweep with known secret patterns
    for pattern in SECRET_PATTERNS:
        matches = pattern.findall(sanitized)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            if match and len(match) > 6 and "****" not in match:
                sanitized = sanitized.replace(match, mask_secret(match))

    return sanitized


def sanitize_relative_path(path_str: str) -> str:
    """Ensure a file path is clean, relative, and normalized using POSIX forward slashes."""
    if not path_str:
        return ""

    # Convert backslashes
    normalized = path_str.replace("\\", "/").strip()

    # Strip Windows drive letters (e.g. C:/)
    normalized = re.sub(r"^[a-zA-Z]:/", "", normalized)

    # Strip leading slashes
    normalized = normalized.lstrip("/")

    # Strip parent traversal segments
    parts = [p for p in normalized.split("/") if p and p != ".." and p != "."]
    return "/".join(parts)
