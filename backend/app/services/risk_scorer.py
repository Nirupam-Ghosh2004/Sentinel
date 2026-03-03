"""
Risk Scorer — Combines Anomaly Score + Homograph Boost

Produces a final 0-100 risk score with:
- Risk level classification (NORMAL / SUSPICIOUS / HIGH_ANOMALY)
- Human-readable explanations
- Feature deviation details
- User override always allowed (non-aggressive)
"""
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from app.config import get_settings
from app.services.anomaly_detector import AnomalyDetector, get_anomaly_detector
from app.services.homograph_detector import HomographDetector, HomographResult


@dataclass
class RiskResult:
    """Final risk assessment result."""
    risk_score: int = 0
    risk_level: str = 'NORMAL'      # NORMAL / SUSPICIOUS / HIGH_ANOMALY
    reasons: List[str] = field(default_factory=list)
    feature_deviations: Dict = field(default_factory=dict)
    homograph_flags: List[str] = field(default_factory=list)
    anomaly_raw_score: float = 0.0
    homograph_boost: float = 0.0
    allow_override: bool = True      # Always allow user to proceed


# Deviation descriptions (human-readable)

_DEVIATION_DESCRIPTIONS = {
    'hostname_entropy': 'Domain name randomness',
    'path_entropy': 'URL path randomness',
    'full_url_entropy': 'Overall URL randomness',
    'url_length': 'URL length',
    'hostname_length': 'Domain name length',
    'digit_ratio': 'Digit concentration in URL',
    'special_char_ratio': 'Special character concentration',
    'consonant_vowel_ratio': 'Character pattern in domain',
    'subdomain_count': 'Number of subdomains',
    'path_depth': 'URL path depth',
    'query_param_count': 'Number of query parameters',
    'num_hyphens': 'Hyphen count in domain',
    'num_dots': 'Dot count in URL',
    'uppercase_ratio': 'Uppercase character ratio',
    'has_punycode': 'Punycode encoding presence',
    'has_unicode': 'Unicode character presence',
    'ip_as_host': 'IP address used as hostname',
    'has_at_symbol': '@ symbol in URL',
    'has_nonstandard_port': 'Non-standard port usage',
    'brand_in_subdomain': 'Brand name in subdomain',
    'https_in_hostname': 'Protocol string in hostname',
    'excessive_hyphens': 'Excessive hyphens in domain',
}


class RiskScorer:
    """
    Combines anomaly detection + homograph analysis into a unified risk score.

    Pipeline:
        URL → Anomaly Score (0-100) + Homograph Boost (0-20) → Final Risk
    """

    def __init__(self):
        self.settings = get_settings()
        self.anomaly_detector = get_anomaly_detector()
        self.homograph_detector = HomographDetector()

    def score(self, url: str) -> RiskResult:
        """
        Compute the final risk score for a URL.

        This is the main entry point for the anomaly detection pipeline.
        The raw URL is discarded after feature extraction.
        """
        result = RiskResult()

        # Step 1: Anomaly Detection
        anomaly_result = self.anomaly_detector.score_url(url)

        if anomaly_result.get('error'):
            result.reasons.append(f"Anomaly engine: {anomaly_result['error']}")
            return result

        anomaly_score = anomaly_result['anomaly_score']
        result.anomaly_raw_score = anomaly_score
        result.feature_deviations = anomaly_result.get('feature_deviations', {})

        # Step 2: Homograph Detection
        homograph_result = self.homograph_detector.analyze(url)
        result.homograph_boost = homograph_result.risk_boost
        result.homograph_flags = homograph_result.reasons

        # Step 3: Combine Scores
        # Anomaly (0-100) + Homograph boost (0-20), capped at 100
        combined = anomaly_score + homograph_result.risk_boost
        result.risk_score = int(min(round(combined), 100))

        # Step 4: Classify Risk Level
        high_thresh = self.settings.anomaly_high_threshold * 100
        sus_thresh = self.settings.anomaly_suspicious_threshold * 100

        if result.risk_score >= high_thresh:
            result.risk_level = 'HIGH_ANOMALY'
        elif result.risk_score >= sus_thresh:
            result.risk_level = 'SUSPICIOUS'
        else:
            result.risk_level = 'NORMAL'

        # Step 5: Generate Human-Readable Reasons
        result.reasons = self._generate_reasons(
            anomaly_score,
            result.feature_deviations,
            homograph_result,
            result.risk_level,
        )

        # Always allow override
        result.allow_override = True

        return result

    def _generate_reasons(
        self,
        anomaly_score: float,
        deviations: Dict,
        homograph: HomographResult,
        risk_level: str,
    ) -> List[str]:
        """Generate human-readable explanations for the risk score."""
        reasons = []

        # Anomaly-based reasons from feature deviations
        for feature_name, dev_info in deviations.items():
            z = dev_info['z_score']
            direction = dev_info['direction']
            description = _DEVIATION_DESCRIPTIONS.get(
                feature_name, feature_name.replace('_', ' ').title()
            )

            if z > 4.0:
                reasons.append(
                    f"{description} is significantly {direction} baseline "
                    f"({z:.1f}σ deviation)"
                )
            elif z > 2.5:
                reasons.append(
                    f"{description} is notably {direction} baseline "
                    f"({z:.1f}σ deviation)"
                )
            elif z > 1.5:
                reasons.append(
                    f"{description} is {direction} normal range "
                    f"({z:.1f}σ deviation)"
                )

        # Homograph reasons
        reasons.extend(homograph.reasons)

        # Overall summary based on risk level
        if risk_level == 'HIGH_ANOMALY' and not reasons:
            reasons.append(
                "URL structure is significantly different from normal browsing patterns"
            )
        elif risk_level == 'SUSPICIOUS' and not reasons:
            reasons.append(
                "URL shows some structural patterns that differ from typical browsing"
            )

        return reasons

    def is_ready(self) -> bool:
        """Check if the scorer is ready (anomaly model loaded)."""
        return self.anomaly_detector.is_loaded()
