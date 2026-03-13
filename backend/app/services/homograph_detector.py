"""
Homograph Attack Detector

Lightweight rule-based filter for detecting visual impersonation attacks:
- Mixed Unicode script detection (Latin + Cyrillic, Greek, etc.)
- Punycode domain analysis
- Fake HTTPS in hostname
- Brand impersonation via non-official domains

Runs in parallel with the anomaly ML model to boost confidence.
"""
import re
import unicodedata
from urllib.parse import urlparse
from typing import Dict, List, NamedTuple
from dataclasses import dataclass, field


@dataclass
class HomographResult:
    """Result of homograph analysis."""
    is_suspicious: bool = False
    risk_boost: float = 0.0        # 0-20 points added to anomaly score
    reasons: List[str] = field(default_factory=list)
    checks_passed: int = 0
    checks_failed: int = 0


class HomographDetector:
    """Detects visual impersonation and homograph attacks in URLs."""

    # Characters that look like Latin letters but are from other scripts
    _CONFUSABLE_SCRIPTS = {
        'CYRILLIC', 'GREEK', 'ARMENIAN', 'CHEROKEE',
    }

    # Brand names and their official domain patterns
    # Supports country-code TLDs to prevent false positives on regional sites
    _BRAND_DOMAINS: Dict[str, List[str]] = {
        'paypal': ['paypal.com', 'paypal.me'],
        'google': ['google.com', 'google.co.in', 'google.co.uk', 'google.de',
                   'google.fr', 'google.co.jp', 'google.com.br', 'google.ca',
                   'google.com.au', 'google.co.kr', 'google.es', 'google.it',
                   'google.nl', 'google.pl', 'google.ru', 'google.co.id',
                   'googleapis.com', 'google.co.za'],
        'facebook': ['facebook.com', 'fb.com', 'fb.me'],
        'amazon': ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de',
                   'amazon.fr', 'amazon.co.jp', 'amazon.com.br', 'amazon.ca',
                   'amazon.com.au', 'amazon.es', 'amazon.it', 'amazon.nl',
                   'amazon.sg', 'amazon.ae', 'amazon.sa', 'amazon.com.mx',
                   'amazon.co.za', 'amazon.pl', 'amazon.se', 'amazon.com.be',
                   'amazon.com.tr', 'amazon.eg', 'amazon.cn'],
        'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com',
                      'office365.com', 'microsoftonline.com'],
        'apple': ['apple.com', 'icloud.com'],
        'netflix': ['netflix.com'],
        'instagram': ['instagram.com'],
        'twitter': ['twitter.com', 'x.com'],
        'linkedin': ['linkedin.com'],
        'yahoo': ['yahoo.com', 'yahoo.co.jp', 'yahoo.co.in', 'yahoo.co.uk'],
        'chase': ['chase.com'],
        'wellsfargo': ['wellsfargo.com'],
        'bankofamerica': ['bankofamerica.com'],
    }

    def analyze(self, url: str) -> HomographResult:
        """
        Run all homograph checks on a URL.

        Returns:
            HomographResult with risk_boost (0-20) and explanations.
        """
        result = HomographResult()

        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            parsed = urlparse(url)
            hostname = (parsed.hostname or '').lower()

            if not hostname:
                return result

            # Check 1: Mixed Unicode Scripts
            self._check_mixed_scripts(hostname, url, result)

            # Check 2: Punycode Domain
            self._check_punycode(hostname, result)

            # Check 3: HTTPS/HTTP in Hostname
            self._check_fake_protocol(hostname, result)

            # Check 4: Brand Impersonation
            self._check_brand_impersonation(hostname, result)

            # Check 5: Lookalike Characters
            self._check_lookalike_chars(hostname, result)

            # Set overall suspicion flag
            result.is_suspicious = result.risk_boost > 0

        except Exception as e:
            print(f"[WARN] Homograph detection error: {e}")

        return result

    def _check_mixed_scripts(
        self, hostname: str, raw_url: str, result: HomographResult
    ) -> None:
        """Detect mixing of Latin with Cyrillic/Greek/Armenian characters."""
        scripts_found = set()

        for char in raw_url:
            if char.isalpha():
                try:
                    script = unicodedata.name(char, '').split()[0]
                    scripts_found.add(script)
                except (ValueError, IndexError):
                    pass

        # Flag if Latin is mixed with confusable scripts
        has_latin = 'LATIN' in scripts_found
        confusable = scripts_found & self._CONFUSABLE_SCRIPTS

        if has_latin and confusable:
            result.risk_boost += 15.0
            scripts_str = ', '.join(sorted(confusable))
            result.reasons.append(
                f"Mixed Unicode scripts detected: Latin + {scripts_str}"
            )
            result.checks_failed += 1
        else:
            result.checks_passed += 1

    def _check_punycode(self, hostname: str, result: HomographResult) -> None:
        """Detect and flag punycode (internationalized) domains."""
        if 'xn--' in hostname:
            result.risk_boost += 10.0
            result.reasons.append(
                "Punycode (xn--) domain detected — may be visually deceptive"
            )
            result.checks_failed += 1
        else:
            result.checks_passed += 1

    def _check_fake_protocol(
        self, hostname: str, result: HomographResult
    ) -> None:
        """Detect 'https' or 'http' embedded in the hostname itself."""
        # Remove common subdomains before checking
        clean = hostname.replace('www.', '')
        if 'https' in clean or ('http' in clean and 'httpd' not in clean):
            result.risk_boost += 12.0
            result.reasons.append(
                "Protocol string (http/https) found inside hostname — "
                "deceptive technique"
            )
            result.checks_failed += 1
        else:
            result.checks_passed += 1

    def _check_brand_impersonation(
        self, hostname: str, result: HomographResult
    ) -> None:
        """Detect brand names used in non-official domains."""
        for brand, official_domains in self._BRAND_DOMAINS.items():
            if brand in hostname:
                # Check if hostname matches any official domain or subdomain
                is_official = any(
                    hostname == domain or hostname.endswith('.' + domain)
                    for domain in official_domains
                )
                if not is_official:
                    result.risk_boost += 8.0
                    top_domains = list(official_domains)[:3]  # type: ignore[index]
                    domains_str = ', '.join(f'*{d}' for d in top_domains)
                    result.reasons.append(
                        f"Brand '{brand}' found in non-official domain "
                        f"(expected {domains_str})"
                    )
                    result.checks_failed += 1
                    return  # One brand match is enough

        result.checks_passed += 1

    def _check_lookalike_chars(
        self, hostname: str, result: HomographResult
    ) -> None:
        """Detect characters that visually resemble common Latin letters."""
        # Common lookalike substitutions
        lookalikes = {
            '0': 'o', '1': 'l', '!': 'l',
            '$': 's', '5': 's',
        }

        suspicious_count: int = 0
        for char in hostname:
            if char in lookalikes:
                suspicious_count = suspicious_count + 1  # type: ignore[operator]

        # Only flag if multiple substitutions
        if suspicious_count >= 3:
            result.risk_boost += 5.0
            result.reasons.append(
                f"Multiple lookalike character substitutions detected "
                f"({suspicious_count} found)"
            )
            result.checks_failed += 1
        else:
            result.checks_passed += 1
