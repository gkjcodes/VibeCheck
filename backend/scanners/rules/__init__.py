"""VibeCheck security rules registry and exports."""

from typing import List, Type
from backend.scanners.rules.base import BaseRule, RuleMatch
from backend.scanners.rules.secrets import (
    ExposedSecretRule,
    HardcodedCredentialRule,
    PrivateKeyRule,
)
from backend.scanners.rules.dangerous_js import (
    EvalRule,
    InnerHTMLRule,
    DynamicFunctionRule,
)
from backend.scanners.rules.injection import (
    SQLInjectionRule,
    CommandInjectionRule,
    DynamicCodeEvalRule,
)
from backend.scanners.rules.frontend import (
    InlineEventHandlerRule,
    DangerousHTMLRule,
    InsecureHTTPResourceRule,
)
from backend.scanners.rules.insecure_config import (
    DisabledTLSVerificationRule,
    DebugModeEnabledRule,
    PermissiveCORSRule,
    InsecureCookieRule,
)

ALL_RULE_CLASSES: List[Type[BaseRule]] = [
    # A. Exposed Secrets
    ExposedSecretRule,
    HardcodedCredentialRule,
    PrivateKeyRule,
    # B. Dangerous JS
    EvalRule,
    InnerHTMLRule,
    DynamicFunctionRule,
    # C. Injection
    SQLInjectionRule,
    CommandInjectionRule,
    DynamicCodeEvalRule,
    # D. Frontend Risks
    InlineEventHandlerRule,
    DangerousHTMLRule,
    InsecureHTTPResourceRule,
    # E. Insecure Config
    DisabledTLSVerificationRule,
    DebugModeEnabledRule,
    PermissiveCORSRule,
    InsecureCookieRule,
]


def get_default_rules() -> List[BaseRule]:
    """Instantiate and return the standard suite of security rules."""
    return [rule_cls() for rule_cls in ALL_RULE_CLASSES]


__all__ = [
    "BaseRule",
    "RuleMatch",
    "ALL_RULE_CLASSES",
    "get_default_rules",
    "ExposedSecretRule",
    "HardcodedCredentialRule",
    "PrivateKeyRule",
    "EvalRule",
    "InnerHTMLRule",
    "DynamicFunctionRule",
    "SQLInjectionRule",
    "CommandInjectionRule",
    "DynamicCodeEvalRule",
    "InlineEventHandlerRule",
    "DangerousHTMLRule",
    "InsecureHTTPResourceRule",
    "DisabledTLSVerificationRule",
    "DebugModeEnabledRule",
    "PermissiveCORSRule",
    "InsecureCookieRule",
]
