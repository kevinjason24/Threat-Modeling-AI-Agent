"""Tests for secret redaction utilities."""


from app.redact import Redactor, redact_text, RedactionPattern
import re


class TestRedactor:
    """Tests for the Redactor class."""

    def test_redact_openai_key(self):
        """Test redacting OpenAI API keys."""
        text = "Use this key: sk-1234567890abcdefghijklmnop"
        redactor = Redactor()
        result = redactor.redact(text)
        assert "sk-" not in result
        assert "[REDACTED_OPENAI_KEY]" in result

    def test_redact_aws_access_key(self):
        """Test redacting AWS access keys."""
        text = "AWS key: AKIAIOSFODNN7EXAMPLE"
        redactor = Redactor()
        result = redactor.redact(text)
        assert "AKIA" not in result
        assert "[REDACTED_AWS_ACCESS_KEY]" in result

    def test_redact_github_token(self):
        """Test redacting GitHub tokens."""
        text = "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        redactor = Redactor()
        result = redactor.redact(text)
        assert "ghp_" not in result
        assert "[REDACTED_GITHUB_TOKEN]" in result

    def test_redact_stripe_key(self):
        """Test redacting Stripe keys."""
        # Using test prefix pattern with 24+ chars (not a real key)
        text = "Stripe: sk_test_XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        redactor = Redactor()
        result = redactor.redact(text)
        assert "sk_test_" not in result
        assert "[REDACTED_STRIPE_KEY]" in result

    def test_redact_jwt(self):
        """Test redacting JWT tokens."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        text = f"Bearer {jwt}"
        redactor = Redactor()
        result = redactor.redact(text)
        assert "eyJ" not in result
        assert "[REDACTED_JWT]" in result

    def test_redact_private_key(self):
        """Test redacting private keys."""
        text = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7...
-----END PRIVATE KEY-----"""
        redactor = Redactor()
        result = redactor.redact(text)
        assert "-----BEGIN PRIVATE KEY-----" not in result
        assert "[REDACTED_PRIVATE_KEY]" in result

    def test_redact_password(self):
        """Test redacting password assignments."""
        text = "password=MySecretP@ssw0rd123"
        redactor = Redactor()
        result = redactor.redact(text)
        assert "MySecretP@ssw0rd123" not in result
        assert "[REDACTED_PASSWORD]" in result

    def test_redact_database_url(self):
        """Test redacting database connection strings."""
        text = "DATABASE_URL=postgres://user:password@host:5432/db"
        redactor = Redactor()
        result = redactor.redact(text)
        assert "password" not in result
        assert "[REDACTED_DB_CONNECTION_STRING]" in result

    def test_redact_generic_secret(self):
        """Test redacting generic secret assignments."""
        text = "secret=abcdefghijklmnopqrstuvwxyz123456"
        redactor = Redactor()
        result = redactor.redact(text)
        assert "abcdefghijklmnopqrstuvwxyz123456" not in result

    def test_no_false_positives_short_strings(self):
        """Test that short strings are not falsely redacted."""
        text = "The API returns a simple token."
        redactor = Redactor()
        result = redactor.redact(text)
        assert result == text  # Should be unchanged

    def test_redact_ip_when_enabled(self):
        """Test IP redaction when enabled."""
        text = "Server IP: 192.168.1.100"
        redactor = Redactor(redact_ips=True)
        result = redactor.redact(text)
        assert "192.168.1.100" not in result
        assert "[REDACTED_IP]" in result

    def test_no_ip_redaction_by_default(self):
        """Test that IPs are not redacted by default."""
        text = "Server IP: 192.168.1.100"
        redactor = Redactor(redact_ips=False)
        result = redactor.redact(text)
        assert "192.168.1.100" in result

    def test_redact_email_when_enabled(self):
        """Test email redaction when enabled."""
        text = "Contact: admin@example.com"
        redactor = Redactor(redact_emails=True)
        result = redactor.redact(text)
        assert "admin@example.com" not in result
        assert "[REDACTED_EMAIL]" in result

    def test_redaction_log(self):
        """Test that redaction log is populated."""
        text = "sk-1234567890abcdefghijklmnop and ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        redactor = Redactor()
        redactor.redact(text)
        log = redactor.get_redaction_log()
        assert len(log) >= 2
        pattern_names = [entry["pattern_name"] for entry in log]
        assert "OpenAI API Key" in pattern_names
        assert "GitHub Token" in pattern_names

    def test_redaction_summary(self):
        """Test human-readable redaction summary."""
        text = "sk-1234567890abcdefghijklmnop"
        redactor = Redactor()
        redactor.redact(text)
        summary = redactor.get_redaction_summary()
        assert "Redacted sensitive data" in summary
        assert "OpenAI API Key" in summary

    def test_no_redaction_summary(self):
        """Test summary when nothing is redacted."""
        text = "Just some normal text"
        redactor = Redactor()
        redactor.redact(text)
        summary = redactor.get_redaction_summary()
        assert "No sensitive data redacted" in summary

    def test_custom_patterns(self):
        """Test adding custom redaction patterns."""
        custom_pattern = RedactionPattern(
            name="Custom Token",
            pattern=re.compile(r"CUSTOM_[A-Z0-9]{10}"),
            replacement="[REDACTED_CUSTOM]",
        )
        text = "Token: CUSTOM_ABCD123456"
        redactor = Redactor(custom_patterns=[custom_pattern])
        result = redactor.redact(text)
        assert "CUSTOM_ABCD123456" not in result
        assert "[REDACTED_CUSTOM]" in result

    def test_multiple_occurrences(self):
        """Test redacting multiple occurrences of the same pattern."""
        text = """
        Key 1: sk-1234567890abcdefghijklmnop
        Key 2: sk-abcdefghijklmnop1234567890
        """
        redactor = Redactor()
        result = redactor.redact(text)
        assert result.count("[REDACTED_OPENAI_KEY]") == 2


class TestRedactTextFunction:
    """Tests for the convenience redact_text function."""

    def test_returns_tuple(self):
        """Test that redact_text returns a tuple."""
        result = redact_text("test")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_redacts_and_summarizes(self):
        """Test that redact_text redacts and provides summary."""
        text = "sk-1234567890abcdefghijklmnop"
        redacted, summary = redact_text(text)
        assert "[REDACTED_OPENAI_KEY]" in redacted
        assert "OpenAI API Key" in summary

    def test_optional_ip_redaction(self):
        """Test optional IP redaction in convenience function."""
        text = "IP: 10.0.0.1"
        redacted_no_ip, _ = redact_text(text, redact_ips=False)
        redacted_with_ip, _ = redact_text(text, redact_ips=True)
        assert "10.0.0.1" in redacted_no_ip
        assert "10.0.0.1" not in redacted_with_ip



