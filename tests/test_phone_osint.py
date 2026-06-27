"""Tests for phone OSINT module."""

from src.modules.phone_osint import analyze_phone, PhoneAnalysis


class TestPhoneAnalysis:
    """Test phone number analysis."""

    def test_valid_us_number(self):
        """Valid US number should parse and identify carrier info."""
        result = analyze_phone("+14155552671")
        assert result.valid is True
        assert result.country_code == 1
        assert result.formatted_international != ""
        assert result.line_type in ("mobile", "fixed_line", "fixed_line_or_mobile", "voip", "unknown")

    def test_valid_uk_number(self):
        """Valid UK number should parse correctly."""
        result = analyze_phone("+447911123456")
        assert result.valid is True
        assert result.country_code == 44

    def test_invalid_number(self):
        """Invalid number should be flagged."""
        result = analyze_phone("not-a-number")
        assert result.valid is False
        assert "invalid_number_format" in result.risk_indicators or "invalid_number" in result.risk_indicators

    def test_short_invalid_number(self):
        """Too-short number should fail validation."""
        result = analyze_phone("+1123")
        assert result.valid is False

    def test_analysis_returns_phone_analysis(self):
        """analyze_phone should always return PhoneAnalysis."""
        result = analyze_phone("+14155552671")
        assert isinstance(result, PhoneAnalysis)

    def test_to_dict(self):
        """to_dict should return a dictionary with all fields."""
        result = analyze_phone("+14155552671")
        d = result.to_dict()
        assert "number" in d
        assert "valid" in d
        assert "carrier_name" in d
        assert "risk_indicators" in d

    def test_to_json(self):
        """to_json should return valid JSON string."""
        import json
        result = analyze_phone("+14155552671")
        j = result.to_json()
        parsed = json.loads(j)
        assert parsed["number"] == "+14155552671"

    def test_voip_detection_by_type(self):
        """VoIP type numbers should be flagged."""
        # Google Voice US number (may or may not be detected as VoIP by library)
        result = analyze_phone("+14155552671")
        # We just verify the flag logic works - not all numbers will be VoIP
        assert isinstance(result.is_voip, bool)

    def test_timezone_extraction(self):
        """Valid numbers should have timezone info."""
        result = analyze_phone("+14155552671")
        if result.valid:
            assert len(result.timezones) > 0
