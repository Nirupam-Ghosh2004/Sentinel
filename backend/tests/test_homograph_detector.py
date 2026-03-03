"""Tests for the Homograph Detector."""
import pytest
from app.services.homograph_detector import HomographDetector, HomographResult


@pytest.fixture
def detector():
    return HomographDetector()


class TestHomographDetector:
    """Test suite for homograph attack detection."""

    def test_normal_url_passes(self, detector):
        """Normal URL should not be flagged."""
        result = detector.analyze("https://google.com")
        assert result.is_suspicious is False
        assert result.risk_boost == 0.0
        assert len(result.reasons) == 0

    def test_punycode_detected(self, detector):
        """Punycode domain should be flagged."""
        result = detector.analyze("http://xn--80ak6aa92e.com/login")
        assert result.is_suspicious is True
        assert result.risk_boost >= 10.0
        assert any("Punycode" in r for r in result.reasons)

    def test_https_in_hostname(self, detector):
        """HTTPS in hostname should be flagged as deceptive."""
        result = detector.analyze("http://https-secure-bank.com")
        assert result.is_suspicious is True
        assert any("Protocol" in r or "http" in r.lower() for r in result.reasons)

    def test_brand_impersonation(self, detector):
        """Brand in non-official domain should be flagged."""
        result = detector.analyze("http://paypal-secure.evil-domain.com")
        assert result.is_suspicious is True
        assert any("paypal" in r.lower() for r in result.reasons)

    def test_brand_on_official_domain(self, detector):
        """Brand on official domain should NOT be flagged."""
        result = detector.analyze("https://www.paypal.com/signin")
        # paypal.com is the official domain, so brand impersonation should not fire
        brand_reasons = [r for r in result.reasons if "paypal" in r.lower() and "non-official" in r.lower()]
        assert len(brand_reasons) == 0

    def test_risk_boost_range(self, detector):
        """Risk boost should be between 0 and 50 (max sum of all checks)."""
        result = detector.analyze("http://xn--80ak6aa92e.com")
        assert 0 <= result.risk_boost <= 50

    def test_result_has_checks_counts(self, detector):
        """Result should track passed and failed check counts."""
        result = detector.analyze("https://google.com")
        assert result.checks_passed > 0

    def test_multiple_flags_accumulate(self, detector):
        """URL with multiple issues should accumulate risk_boost."""
        # This URL has punycode + brand impersonation traits
        result = detector.analyze("http://xn--paypal.evil.com/login")
        assert result.risk_boost >= 10.0

    def test_empty_url(self, detector):
        """Empty URL should return clean result."""
        result = detector.analyze("")
        assert isinstance(result, HomographResult)
