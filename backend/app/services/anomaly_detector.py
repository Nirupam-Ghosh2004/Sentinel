"""
One-Class Anomaly Detector (Isolation Forest)

Detects structural deviation from a benign baseline.
Trained only on legitimate URLs; no malicious samples required.
All processing is local.
"""
import joblib
import numpy as np
from typing import Dict, Optional, List
import os

from app.config import get_settings
from app.services.privacy_feature_extractor import PrivacyFeatureExtractor


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detection service.

    The model was trained only on benign/legitimate URLs.
    Anything that deviates structurally from that baseline gets a high score.
    """

    def __init__(self):
        self.settings = get_settings()
        self.model = None
        self.scaler = None
        self.baseline_stats: Optional[Dict] = None
        self.extractor = PrivacyFeatureExtractor()

        self.load_model()

    def load_model(self) -> None:
        """Load the trained Isolation Forest model, scaler, and baseline stats."""
        try:
            model_path = self.settings.anomaly_model_path
            scaler_path = self.settings.anomaly_scaler_path
            baseline_path = self.settings.anomaly_baseline_path

            print(f"Loading anomaly model from: {model_path}")
            self.model = joblib.load(model_path)

            print(f"Loading scaler from: {scaler_path}")
            self.scaler = joblib.load(scaler_path)

            print(f"Loading baseline stats from: {baseline_path}")
            self.baseline_stats = joblib.load(baseline_path)

            print("Anomaly detection engine loaded.")
            print(f"  Features: {len(self.extractor.FEATURE_NAMES)}")

        except FileNotFoundError as e:
            print(f"[WARN] Anomaly model not found: {e}")
            print("   Run train_anomaly_model.py to generate the model files.")
            self.model = None
        except Exception as e:
            print(f"[ERROR] Loading anomaly model: {e}")
            self.model = None

    def score_url(self, url: str) -> Dict:
        """
        Score a URL for anomaly.

        Steps:
        1. Extract features (raw URL is discarded after extraction)
        2. Scale features using the fitted StandardScaler
        3. Run Isolation Forest to get anomaly score
        4. Normalize to 0-100 risk scale
        5. Identify which features deviated most from baseline

        Returns:
            dict with anomaly_score (0-100), feature_deviations, etc.
        """
        if not self.is_loaded():
            return {
                'anomaly_score': 0.0,
                'raw_score': 0.0,
                'risk_level': 'UNKNOWN',
                'feature_deviations': {},
                'error': 'Anomaly model not loaded'
            }

        features = self.extractor.extract(url)
        feature_vector = self.extractor.get_feature_vector(features)

        scaled_vector = self.scaler.transform(  # type: ignore[union-attr]
            np.array(feature_vector).reshape(1, -1)
        )

        raw_score = self.model.score_samples(scaled_vector)[0]  # type: ignore[union-attr]
        decision = self.model.decision_function(scaled_vector)[0]  # type: ignore[union-attr]
        anomaly_score = self._normalize_score(raw_score)

        deviations = self._find_deviations(features)

        return {
            'anomaly_score': anomaly_score,
            'raw_score': float(raw_score),
            'decision_value': float(decision),
            'is_anomaly': decision < 0,
            'feature_deviations': deviations,
            'features_extracted': len(features),
        }

    def score_features(self, feature_vector: List[float]) -> Dict:
        """Score a pre-extracted feature vector (for privacy-preserving usage)."""
        if not self.is_loaded():
            return {
                'anomaly_score': 0.0,
                'error': 'Anomaly model not loaded'
            }

        scaled = self.scaler.transform(  # type: ignore[union-attr]
            np.array(feature_vector).reshape(1, -1)
        )
        raw_score = self.model.score_samples(scaled)[0]  # type: ignore[union-attr]
        decision = self.model.decision_function(scaled)[0]  # type: ignore[union-attr]
        anomaly_score = self._normalize_score(raw_score)

        return {
            'anomaly_score': anomaly_score,
            'raw_score': float(raw_score),
            'decision_value': float(decision),
            'is_anomaly': decision < 0,
        }

    def _normalize_score(self, raw_score: float) -> float:
        """
        Normalize Isolation Forest raw score to a 0-100 risk scale.

        Calibrated against the v3 augmented model scores:
        
        Score ranges observed:
        - Simple legit (google.com):        -0.40 to -0.43
        - Complex legit (reddit/amazon):    -0.50 to -0.55
        - Borderline malicious:             -0.55 to -0.58
        - Clearly malicious (IP/punycode):  -0.58 to -0.65+
        
        Mapping:
        - score >= -0.38  →  risk 0       (very normal)
        - score -0.43     →  risk ~15     (normal)
        - score -0.50     →  risk ~35     (normal, complex URL)
        - score -0.55     →  risk ~50     (borderline)
        - score -0.60     →  risk ~65     (suspicious)
        - score -0.65     →  risk ~79     (high anomaly)
        - score <= -0.72  →  risk 100     (extremely anomalous)
        """
        # Clamp to expected range
        clamped = max(min(raw_score, -0.38), -0.72)
        
        # Linear map: -0.38 → 0, -0.72 → 100
        risk = ((-0.38 - clamped) / 0.34) * 100.0
        
        return round(float(max(0.0, min(100.0, risk))), 1)  # type: ignore[call-overload]

    def _find_deviations(
        self, features: Dict[str, float], top_n: int = 5
    ) -> Dict[str, Dict]:
        """
        Find the features that deviate most from the benign baseline.

        Returns the top-N deviations with z-scores and human-readable descriptions.
        """
        if not self.baseline_stats:
            return {}

        deviations = {}

        for name, value in features.items():
            if name in self.baseline_stats:  # type: ignore[operator]
                stats = self.baseline_stats[name]  # type: ignore[index]
                mean = stats.get('mean', 0.0)
                std = stats.get('std', 1.0)

                if std > 0:
                    z_score = abs(value - mean) / std
                else:
                    z_score = abs(value - mean)

                if z_score > 1.5:  # Only report significant deviations
                    deviations[name] = {
                        'value': round(float(value), 4),  # type: ignore[call-overload]
                        'baseline_mean': round(float(mean), 4),  # type: ignore[call-overload]
                        'baseline_std': round(float(std), 4),  # type: ignore[call-overload]
                        'z_score': round(float(z_score), 2),  # type: ignore[call-overload]
                        'direction': 'above' if value > mean else 'below',
                    }

        # Return top N by z-score
        sorted_devs = dict(
            sorted(deviations.items(), key=lambda x: x[1]['z_score'], reverse=True)[:top_n]  # type: ignore[index]
        )

        return sorted_devs

    def is_loaded(self) -> bool:
        """Check if the anomaly model is loaded and ready."""
        return (
            self.model is not None
            and self.scaler is not None
            and self.baseline_stats is not None
        )


# Singleton

_anomaly_detector: Optional[AnomalyDetector] = None


def get_anomaly_detector() -> AnomalyDetector:
    """Get anomaly detector singleton."""
    global _anomaly_detector
    if _anomaly_detector is None:
        _anomaly_detector = AnomalyDetector()
    return _anomaly_detector
