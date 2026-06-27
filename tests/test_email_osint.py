"""Tests for email OSINT module."""

from src.modules.email_osint import (
    analyze_email,
    validate_email_format,
    EmailAnalysis,
)


class TestEmailValidation:
    """Test email format validation."""

    def test_valid_email(self):
        assert validate_email_format("test@example.com") is True

    def test_valid_email_with_dots(self):
        assert validate_email_format("first.last@example.com") is True

    def test_valid_email_with_plus(self):
        assert validate_email_format("user+tag@example.com") is True

    def test_invalid_no_at(self):
        assert validate_email_format("noatsign.com") is False

    def test_invalid_no_domain(self):
        assert validate_email_format("user@") is False

    def test_invalid_spaces(self):
        assert validate_email_format("user @example.com") is False

    def test_empty_string(self):
        assert validate_email_format("") is False


class TestEmailAnalysis:
    """Test email OSINT analysis."""

    def test_disposable_email_detection(self):
        """Disposable email domains should be flagged."""
        result = analyze_email("test@mailinator.com")
        assert result.is_disposable is True
        assert "disposable_email_domain" in result.risk_indicators

    def test_privacy_provider_detection(self):
        """Privacy-focused providers should be flagged."""
        result = analyze_email("test@tutanota.com")
        assert result.is_privacy_provider is True
        assert "privacy_email_provider" in result.risk_indicators

    def test_corporate_email_detection(self):
        """Custom domain emails should be detected as corporate."""
        result = analyze_email("john@acme-corp.com")
        assert result.is_corporate is True

    def test_free_provider_not_corporate(self):
        """Gmail/Yahoo should NOT be flagged as corporate."""
        result = analyze_email("user@gmail.com")
        assert result.is_corporate is False

    def test_invalid_email(self):
        """Invalid email format should be caught."""
        result = analyze_email("not-an-email")
        assert result.valid_format is False
        assert "invalid_email_format" in result.risk_indicators

    def test_domain_extraction(self):
        """Domain should be correctly extracted."""
        result = analyze_email("user@Example.COM")
        assert result.domain == "example.com"

    def test_local_part_extraction(self):
        """Local part should be correctly extracted."""
        result = analyze_email("john.doe@example.com")
        assert result.local_part == "john.doe"

    def test_to_dict(self):
        """to_dict should return a complete dictionary."""
        result = analyze_email("test@gmail.com")
        d = result.to_dict()
        assert "email" in d
        assert "domain" in d
        assert "is_disposable" in d
        assert "risk_indicators" in d

    def test_returns_email_analysis(self):
        """analyze_email should always return EmailAnalysis type."""
        result = analyze_email("anything@whatever.org")
        assert isinstance(result, EmailAnalysis)
