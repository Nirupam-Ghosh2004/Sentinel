"""
Privacy-Preserving Feature Extractor for Anomaly Detection

Extracts structural features from URLs and immediately discards raw URL data.
Only numerical feature vectors are returned — no browsing history is stored.
"""
import re
import math
from urllib.parse import urlparse
from collections import Counter
from typing import Dict, List, Optional


class PrivacyFeatureExtractor:
    """
    Extracts anomaly-focused structural features from URLs.
    
    Privacy guarantees:
    - Raw URL is never stored or returned
    - Only numerical features are produced
    - No browsing history is maintained
    - All computation is local
    """

    # Feature names in deterministic order
    FEATURE_NAMES = [
        # Length & Ratios
        'url_length', 'hostname_length', 'path_to_url_ratio',
        'query_to_url_ratio', 'hostname_to_url_ratio',
        # Entropy
        'hostname_entropy', 'path_entropy', 'full_url_entropy',
        # Character Distribution
        'digit_ratio', 'special_char_ratio', 'consonant_vowel_ratio',
        'uppercase_ratio',
        # Structural
        'subdomain_count', 'path_depth', 'query_param_count',
        'tld_length', 'num_dots', 'num_hyphens',
        # Protocol & Port
        'is_https', 'has_nonstandard_port',
        # Anomaly Signals
        'has_punycode', 'has_unicode', 'has_at_symbol',
        'has_double_slash_in_path', 'ip_as_host',
        # Deception Indicators
        'brand_in_subdomain', 'https_in_hostname', 'excessive_hyphens',
    ]

    _BRANDS = frozenset([
        'paypal', 'google', 'facebook', 'amazon', 'microsoft',
        'apple', 'netflix', 'instagram', 'twitter', 'linkedin',
        'yahoo', 'bank', 'chase', 'wellsfargo', 'citibank',
    ])

    _VOWELS = frozenset('aeiouAEIOU')
    _CONSONANTS = frozenset('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')

    def extract(self, url: str) -> Dict[str, float]:
        """
        Extract features from a URL.

        The raw URL string is used only within this method and is NOT stored.

        Returns:
            dict mapping feature name -> numerical value
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            parsed = urlparse(url)
            hostname = (parsed.hostname or '').lower()
            path = parsed.path or '/'
            query = parsed.query or ''

            features: Dict[str, float] = {}

            # Length & Ratios
            url_len = max(len(url), 1)
            features['url_length'] = float(url_len)
            features['hostname_length'] = float(len(hostname))
            features['path_to_url_ratio'] = len(path) / url_len
            features['query_to_url_ratio'] = len(query) / url_len
            features['hostname_to_url_ratio'] = len(hostname) / url_len

            # Entropy
            features['hostname_entropy'] = self._shannon_entropy(hostname)
            features['path_entropy'] = self._shannon_entropy(path)
            features['full_url_entropy'] = self._shannon_entropy(url)

            # Character Distribution
            digit_count = sum(c.isdigit() for c in url)
            special_count = sum(not c.isalnum() for c in url)
            features['digit_ratio'] = digit_count / url_len
            features['special_char_ratio'] = special_count / url_len
            features['consonant_vowel_ratio'] = self._cv_ratio(hostname)

            upper_count = sum(c.isupper() for c in hostname)
            features['uppercase_ratio'] = upper_count / max(len(hostname), 1)

            # Structural
            host_parts = hostname.split('.') if hostname else []
            features['subdomain_count'] = float(max(len(host_parts) - 2, 0))
            features['path_depth'] = float(len([t for t in path.split('/') if t]))
            features['query_param_count'] = float(
                len(query.split('&')) if query else 0
            )
            features['tld_length'] = float(
                len(host_parts[-1]) if host_parts else 0
            )
            features['num_dots'] = float(url.count('.'))
            features['num_hyphens'] = float(hostname.count('-'))

            # Protocol & Port
            features['is_https'] = 1.0 if parsed.scheme == 'https' else 0.0
            features['has_nonstandard_port'] = (
                1.0 if parsed.port and parsed.port not in (80, 443, 8080) else 0.0
            )

            # Anomaly Signals
            features['has_punycode'] = 1.0 if 'xn--' in hostname else 0.0
            features['has_unicode'] = (
                1.0 if any(ord(c) > 127 for c in url) else 0.0
            )
            features['has_at_symbol'] = 1.0 if '@' in url else 0.0
            features['has_double_slash_in_path'] = (
                1.0 if '//' in path else 0.0
            )
            features['ip_as_host'] = (
                1.0 if self._is_ip(hostname) else 0.0
            )

            # Deception Indicators
            features['brand_in_subdomain'] = (
                1.0 if self._has_brand_in_subdomain(host_parts) else 0.0
            )
            features['https_in_hostname'] = (
                1.0 if 'https' in hostname or 'http' in hostname else 0.0
            )
            features['excessive_hyphens'] = (
                1.0 if hostname.count('-') > 3 else 0.0
            )

            return features

        except Exception as e:
            # On any parsing error, return zero vector
            print(f"[WARN] Feature extraction error: {e}")
            return {name: 0.0 for name in self.FEATURE_NAMES}

    def extract_batch(self, urls: List[str]) -> List[Dict[str, float]]:
        """Extract features for a batch of URLs."""
        return [self.extract(url) for url in urls]

    def get_feature_vector(self, features: Dict[str, float]) -> List[float]:
        """Convert feature dict to ordered list (for model input)."""
        return [features.get(name, 0.0) for name in self.FEATURE_NAMES]

    # Private helpers

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def _cv_ratio(self, text: str) -> float:
        """Consonant-to-vowel ratio."""
        vowels = sum(1 for c in text if c in self._VOWELS)
        consonants = sum(1 for c in text if c in self._CONSONANTS)
        if vowels == 0:
            return float(consonants)
        return consonants / vowels

    @staticmethod
    def _is_ip(hostname: str) -> bool:
        """Check if hostname is an IPv4 address."""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname))

    def _has_brand_in_subdomain(self, host_parts: List[str]) -> bool:
        """Check if a brand name appears in subdomains (not the root domain)."""
        if len(host_parts) <= 2:
            return False
        subdomains = '.'.join(host_parts[:-2]).lower()
        return any(brand in subdomains for brand in self._BRANDS)
