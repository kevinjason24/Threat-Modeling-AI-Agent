"""Secret redaction utilities for sanitizing input before sending to LLM."""

import re
from dataclasses import dataclass


@dataclass
class RedactionPattern:
    """A pattern for redacting sensitive information."""

    name: str
    pattern: re.Pattern[str]
    replacement: str


# Common secret patterns
SECRET_PATTERNS: list[RedactionPattern] = [
    # API Keys
    RedactionPattern(
        name="OpenAI API Key",
        pattern=re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        replacement="[REDACTED_OPENAI_KEY]",
    ),
    RedactionPattern(
        name="Generic API Key",
        pattern=re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"),
        replacement=r"\1=[REDACTED_API_KEY]",
    ),
    # AWS
    RedactionPattern(
        name="AWS Access Key",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        replacement="[REDACTED_AWS_ACCESS_KEY]",
    ),
    RedactionPattern(
        name="AWS Secret Key",
        pattern=re.compile(r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?"),
        replacement=r"\1=[REDACTED_AWS_SECRET]",
    ),
    # GitHub
    RedactionPattern(
        name="GitHub Token",
        pattern=re.compile(r"ghp_[a-zA-Z0-9]{36}"),
        replacement="[REDACTED_GITHUB_TOKEN]",
    ),
    RedactionPattern(
        name="GitHub OAuth",
        pattern=re.compile(r"gho_[a-zA-Z0-9]{36}"),
        replacement="[REDACTED_GITHUB_OAUTH]",
    ),
    # Slack
    RedactionPattern(
        name="Slack Token",
        pattern=re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        replacement="[REDACTED_SLACK_TOKEN]",
    ),
    # Stripe (live and test keys)
    RedactionPattern(
        name="Stripe Secret Key",
        pattern=re.compile(r"sk_(live|test)_[a-zA-Z0-9]{24,}"),
        replacement="[REDACTED_STRIPE_KEY]",
    ),
    RedactionPattern(
        name="Stripe Publishable",
        pattern=re.compile(r"pk_(live|test)_[a-zA-Z0-9]{24,}"),
        replacement="[REDACTED_STRIPE_PK]",
    ),
    # JWT (be careful - might be example tokens)
    RedactionPattern(
        name="JWT Token",
        pattern=re.compile(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"),
        replacement="[REDACTED_JWT]",
    ),
    # Private Keys
    RedactionPattern(
        name="RSA Private Key",
        pattern=re.compile(r"-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----"),
        replacement="[REDACTED_RSA_PRIVATE_KEY]",
    ),
    RedactionPattern(
        name="Private Key",
        pattern=re.compile(r"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----"),
        replacement="[REDACTED_PRIVATE_KEY]",
    ),
    RedactionPattern(
        name="EC Private Key",
        pattern=re.compile(r"-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----"),
        replacement="[REDACTED_EC_PRIVATE_KEY]",
    ),
    # Passwords in common formats
    RedactionPattern(
        name="Password Assignment",
        pattern=re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?"),
        replacement=r"\1=[REDACTED_PASSWORD]",
    ),
    # Connection strings
    RedactionPattern(
        name="Database URL",
        pattern=re.compile(
            r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s]+"
        ),
        replacement=r"[REDACTED_DB_CONNECTION_STRING]",
    ),
    # Generic secrets
    RedactionPattern(
        name="Generic Secret",
        pattern=re.compile(r"(?i)(secret|token|credential)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"),
        replacement=r"\1=[REDACTED_SECRET]",
    ),
    # IP Addresses (optional - might want to keep for context)
    RedactionPattern(
        name="IPv4 Address",
        pattern=re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
        replacement="[REDACTED_IP]",
    ),
    # Email addresses
    RedactionPattern(
        name="Email Address",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        replacement="[REDACTED_EMAIL]",
    ),
]


class Redactor:
    """Redacts sensitive information from text."""

    def __init__(
        self,
        patterns: list[RedactionPattern] | None = None,
        redact_ips: bool = False,
        redact_emails: bool = False,
        custom_patterns: list[RedactionPattern] | None = None,
    ):
        """Initialize the redactor.

        Args:
            patterns: Override default patterns. If None, uses SECRET_PATTERNS.
            redact_ips: Whether to redact IP addresses (default False).
            redact_emails: Whether to redact email addresses (default False).
            custom_patterns: Additional patterns to include.
        """
        self.patterns = patterns or SECRET_PATTERNS.copy()

        # Filter out IP and email patterns if not requested
        if not redact_ips:
            self.patterns = [p for p in self.patterns if p.name != "IPv4 Address"]
        if not redact_emails:
            self.patterns = [p for p in self.patterns if p.name != "Email Address"]

        if custom_patterns:
            self.patterns.extend(custom_patterns)

        self._redaction_log: list[dict[str, str]] = []

    def redact(self, text: str, log_redactions: bool = True) -> str:
        """Redact sensitive information from text.

        Args:
            text: The text to redact.
            log_redactions: Whether to log what was redacted.

        Returns:
            The redacted text.
        """
        self._redaction_log = []
        result = text

        for pattern in self.patterns:
            matches = pattern.pattern.findall(result)
            if matches and log_redactions:
                self._redaction_log.append({
                    "pattern_name": pattern.name,
                    "count": len(matches) if isinstance(matches[0], str) else len(matches),
                })
            result = pattern.pattern.sub(pattern.replacement, result)

        return result

    def get_redaction_log(self) -> list[dict[str, str]]:
        """Get log of what was redacted in the last redact() call."""
        return self._redaction_log.copy()

    def get_redaction_summary(self) -> str:
        """Get a human-readable summary of redactions."""
        if not self._redaction_log:
            return "No sensitive data redacted."

        lines = ["Redacted sensitive data:"]
        for entry in self._redaction_log:
            lines.append(f"  - {entry['pattern_name']}: {entry['count']} occurrence(s)")
        return "\n".join(lines)


def redact_text(
    text: str,
    redact_ips: bool = False,
    redact_emails: bool = False,
) -> tuple[str, str]:
    """Convenience function to redact text and get summary.

    Args:
        text: The text to redact.
        redact_ips: Whether to redact IP addresses.
        redact_emails: Whether to redact email addresses.

    Returns:
        Tuple of (redacted_text, summary).
    """
    redactor = Redactor(redact_ips=redact_ips, redact_emails=redact_emails)
    redacted = redactor.redact(text)
    summary = redactor.get_redaction_summary()
    return redacted, summary



