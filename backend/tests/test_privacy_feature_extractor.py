"""Tests for the Privacy Feature Extractor."""
import pytest
from app.services.privacy_feature_extractor import PrivacyFeatureExtractor


@pytest.fixture
def extractor():
    return PrivacyFeatureExtractor()


class TestPrivacyFeatureExtractor:
    """Test suite for privacy-preserving feature extraction."""

    def test_feature_count(self, extractor):
        """Should return exactly 28 features."""
        features = extractor.extract("https://example.com/path?q=test")
        assert len(features) == len(extractor.FEATURE_NAMES)
        assert len(features) == 28

    def test_all_values_are_floats(self, extractor):
        """All feature values should be floats."""
        features = extractor.extract("https://google.com")
        for name, val in features.items():
            assert isinstance(val, float), f"{name} is not float: {type(val)}"

    def test_feature_names_match(self, extractor):
        """Returned feature keys should match FEATURE_NAMES."""
        features = extractor.extract("https://example.com")
        assert set(features.keys()) == set(extractor.FEATURE_NAMES)

    def test_normal_url_values(self, extractor):
        """Normal URL should have expected feature ranges."""
        features = extractor.extract("https://google.com")
        assert features['is_https'] == 1.0
        assert features['ip_as_host'] == 0.0
        assert features['has_punycode'] == 0.0
        assert features['has_at_symbol'] == 0.0
        assert features['subdomain_count'] == 0.0
        assert features['hostname_entropy'] > 0.0

    def test_ip_address_detection(self, extractor):
        """IP-based URL should flag ip_as_host."""
        features = extractor.extract("http://192.168.1.1/login")
        assert features['ip_as_host'] == 1.0
        assert features['is_https'] == 0.0

    def test_punycode_detection(self, extractor):
        """Punycode domain should flag has_punycode."""
        features = extractor.extract("http://xn--80ak6aa92e.com")
        assert features['has_punycode'] == 1.0

    def test_at_symbol_detection(self, extractor):
        """URL with @ should flag has_at_symbol."""
        features = extractor.extract("http://user@evil.com")
        assert features['has_at_symbol'] == 1.0

    def test_brand_in_subdomain(self, extractor):
        """Brand in subdomain of non-official domain should be flagged."""
        features = extractor.extract("http://paypal.evil-site.com/login")
        assert features['brand_in_subdomain'] == 1.0

    def test_brand_in_official_domain(self, extractor):
        """Brand in official domain should NOT be flagged."""
        features = extractor.extract("https://www.paypal.com/login")
        assert features['brand_in_subdomain'] == 0.0

    def test_https_in_hostname(self, extractor):
        """HTTPS string in hostname should be flagged."""
        features = extractor.extract("http://https-secure-login.com")
        assert features['https_in_hostname'] == 1.0

    def test_entropy_higher_for_random(self, extractor):
        """Random domains should have higher entropy than normal ones."""
        normal = extractor.extract("https://google.com")
        random_url = extractor.extract("https://x7k2m9q4p.com")
        assert random_url['hostname_entropy'] > normal['hostname_entropy']

    def test_subdomain_count(self, extractor):
        """Should count subdomains correctly."""
        features = extractor.extract("https://a.b.c.d.example.com")
        assert features['subdomain_count'] == 4.0

    def test_feature_vector_order(self, extractor):
        """get_feature_vector should return values in FEATURE_NAMES order."""
        features = extractor.extract("https://example.com")
        vector = extractor.get_feature_vector(features)
        assert len(vector) == len(extractor.FEATURE_NAMES)
        for i, name in enumerate(extractor.FEATURE_NAMES):
            assert vector[i] == features[name]

    def test_batch_extraction(self, extractor):
        """extract_batch should work for multiple URLs."""
        urls = ["https://google.com", "http://evil.com", "https://github.com"]
        results = extractor.extract_batch(urls)
        assert len(results) == 3
        assert all(len(r) == 28 for r in results)

    def test_malformed_url_returns_zeros(self, extractor):
        """Malformed URL should not crash and should return valid features."""
        features = extractor.extract("")
        # Should return the correct number of features without crashing
        assert len(features) == 28
        assert all(isinstance(v, float) for v in features.values())

    def test_raw_url_not_in_output(self, extractor):
        """Feature dict should NOT contain the raw URL string anywhere."""
        url = "https://secret-browsing-url.com/private/page"
        features = extractor.extract(url)
        for val in features.values():
            assert isinstance(val, float)
            assert url not in str(val)
