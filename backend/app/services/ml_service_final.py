"""
ML Service - ML-First Approach with Reputation Validation
The ML model is the PRIMARY decision maker
Reputation scoring is used for VALIDATION and CONFIDENCE ADJUSTMENT
"""
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Tuple, Optional
import os
from urllib.parse import urlparse
from app.config import get_settings
from app.services.feature_extractor import URLFeatureExtractorV2
from app.services.reputation.domain_reputation import DomainReputationService

class MLServiceFinal:
    """ML-First service with reputation validation"""
    
    def __init__(self):
        self.settings = get_settings()
        self.model = None
        self.feature_names = None
        self.extractor = URLFeatureExtractorV2()
        self.reputation_service = DomainReputationService()
        
        # MINIMAL whitelist - only for critical infrastructure
        # These domains are so critical that bypassing ML is justified
        self.critical_infrastructure = {
            'localhost', '127.0.0.1', 'chrome-extension://'
        }
        
        self.load_model()
    
    def load_model(self):
        """Load the trained model"""
        try:
            model_path = self.settings.model_path
            features_path = self.settings.feature_names_path
            
            print(f"📦 Loading ML model from: {model_path}")
            self.model = joblib.load(model_path)
            
            print(f"📦 Loading feature names from: {features_path}")
            self.feature_names = joblib.load(features_path)
            
            print(f"✅ ML-First Model Loaded!")
            print(f"   Features: {len(self.feature_names)}")
            print(f"   Strategy: ML predictions + Reputation validation")
            
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            raise
    
    def predict(self, url: str, use_reputation: bool = True) -> Dict:
        """
        ML-FIRST PREDICTION FLOW:
        
        1. Extract features from URL (YOUR ML PIPELINE)
        2. Run ML model prediction (CORE DECISION)
        3. Calculate reputation score (VALIDATION)
        4. Adjust confidence based on reputation (REFINEMENT)
        5. Return final decision with full transparency
        """
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            hostname = parsed.hostname if parsed.hostname else ''
            
            # Only skip for critical infrastructure
            if hostname in self.critical_infrastructure:
                return {
                    'status': 'LEGITIMATE',
                    'confidence': 1.0,
                    'prediction_score': 0.0,
                    'reason': 'Critical infrastructure (localhost, extensions)',
                    'source': 'infrastructure_whitelist',
                    'ml_used': False,
                    'reputation_used': False
                }
            
            # ============================================================
            # STEP 1: FEATURE EXTRACTION (YOUR ML PIPELINE)
            # ============================================================
            print(f"\n{'='*70}")
            print(f"🤖 ML PREDICTION FOR: {url}")
            print(f"{'='*70}")
            
            features = self.extractor.extract_features(url)
            print(f"  ✅ Extracted {len(features)} features")
            
            # Show key features
            print(f"  📊 Key features:")
            print(f"     - URL length: {features.get('url_length', 0)}")
            print(f"     - Has path: {features.get('has_path', 0)}")
            print(f"     - Is HTTPS: {features.get('is_https', 0)}")
            print(f"     - Subdomain count: {features.get('subdomain_count', 0)}")
            print(f"     - Is IP: {features.get('is_ip_address', 0)}")
            print(f"     - Suspicious TLD: {features.get('is_suspicious_tld', 0)}")
            
            # ============================================================
            # STEP 2: ML MODEL PREDICTION (CORE DECISION)
            # ============================================================
            feature_df = pd.DataFrame([features])
            feature_df = feature_df[self.feature_names]
            
            # Get raw ML prediction
            prediction_proba = self.model.predict_proba(feature_df)[0]
            ml_score = float(prediction_proba[1])  # Probability of malicious
            
            print(f"\n  🎯 ML Model Prediction:")
            print(f"     - Malicious probability: {ml_score:.4f} ({ml_score*100:.2f}%)")
            print(f"     - Legitimate probability: {1-ml_score:.4f} ({(1-ml_score)*100:.2f}%)")
            
            # ============================================================
            # STEP 3: REPUTATION SCORING (VALIDATION LAYER)
            # ============================================================
            reputation_score = None
            reputation_data = None
            
            if use_reputation:
                print(f"\n  🔍 Reputation Validation:")
                
                # Get root domain for reputation check
                check_domain = self._get_root_domain(hostname)
                
                reputation_result = self.reputation_service.calculate_reputation_score(
                    f"https://{check_domain}"
                )
                
                reputation_score = reputation_result['total_score']
                reputation_data = reputation_result
                
                print(f"     - Reputation score: {reputation_score}/100")
                print(f"     - Trust level: {reputation_result['trust_level']}")
            
            # ============================================================
            # STEP 4: INTELLIGENT CONFIDENCE ADJUSTMENT
            # ============================================================
            final_score = ml_score
            adjustment_reason = None
            
            if reputation_score is not None:
                print(f"\n  ⚖️  Confidence Adjustment:")
                
                # Case 1: ML says MALICIOUS but reputation is HIGH
                if ml_score >= 0.5 and reputation_score >= 70:
                    # Strong reputation contradicts ML → investigate
                    adjustment_factor = 0.3  # Reduce malicious confidence significantly
                    final_score = ml_score * adjustment_factor
                    adjustment_reason = f"High reputation ({reputation_score}/100) contradicts ML prediction - reducing malicious confidence"
                    print(f"     ⚠️  CONFLICT: ML={ml_score:.3f} but Reputation={reputation_score}/100")
                    print(f"     → Adjusted: {ml_score:.3f} → {final_score:.3f} (factor: {adjustment_factor})")
                
                # Case 2: ML says MALICIOUS and reputation is MEDIUM
                elif ml_score >= 0.5 and 50 <= reputation_score < 70:
                    # Moderate reputation → slightly reduce confidence
                    adjustment_factor = 0.7
                    final_score = ml_score * adjustment_factor
                    adjustment_reason = f"Moderate reputation ({reputation_score}/100) suggests reconsideration"
                    print(f"     📊 MODERATE: ML={ml_score:.3f}, Reputation={reputation_score}/100")
                    print(f"     → Adjusted: {ml_score:.3f} → {final_score:.3f} (factor: {adjustment_factor})")
                
                # Case 3: ML says LEGITIMATE but reputation is LOW
                elif ml_score < 0.5 and reputation_score < 30:
                    # Low reputation + ML says safe → increase suspicion slightly
                    adjustment_factor = 1.3
                    final_score = min(ml_score * adjustment_factor, 0.45)  # Cap at suspicious
                    adjustment_reason = f"Low reputation ({reputation_score}/100) raises concern"
                    print(f"     ⚠️  CONCERN: ML={ml_score:.3f} (safe) but Reputation={reputation_score}/100 (low)")
                    print(f"     → Adjusted: {ml_score:.3f} → {final_score:.3f} (factor: {adjustment_factor})")
                
                # Case 4: ML and Reputation agree
                else:
                    adjustment_reason = f"ML and reputation align (rep: {reputation_score}/100)"
                    print(f"     ✅ ALIGNED: ML={ml_score:.3f}, Reputation={reputation_score}/100")
                    print(f"     → No adjustment needed")
            
            # ============================================================
            # STEP 5: FINAL DECISION
            # ============================================================
            status, confidence, reason = self._interpret_prediction(
                final_score,
                ml_score,
                features,
                hostname,
                reputation_score,
                adjustment_reason
            )
            
            print(f"\n  🎯 FINAL DECISION:")
            print(f"     Status: {status}")
            print(f"     Confidence: {confidence:.4f} ({confidence*100:.2f}%)")
            print(f"     Reason: {reason}")
            print(f"{'='*70}\n")
            
            # ============================================================
            # RETURN FULL TRANSPARENCY
            # ============================================================
            result = {
                'status': status,
                'confidence': confidence,
                'prediction_score': final_score,
                'ml_raw_score': ml_score,
                'ml_features': features,
                'reputation_score': reputation_score,
                'reputation_data': reputation_data,
                'adjustment_applied': adjustment_reason,
                'reason': reason,
                'source': 'ml_with_reputation_validation' if use_reputation else 'ml_only',
                'ml_used': True,
                'reputation_used': use_reputation,
                'hostname': hostname,
                'transparency': {
                    'ml_predicted': 'malicious' if ml_score >= 0.5 else 'legitimate',
                    'ml_confidence': ml_score if ml_score >= 0.5 else 1 - ml_score,
                    'reputation_influenced': adjustment_reason is not None,
                    'final_override': final_score != ml_score
                }
            }
            
            return result
            
        except Exception as e:
            print(f"❌ Prediction error for {url}: {e}")
            raise
    
    def _get_root_domain(self, hostname: str) -> str:
        """Extract root domain from hostname"""
        parts = hostname.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return hostname
    
    def _interpret_prediction(
        self, 
        final_score: float,
        ml_score: float,
        features: Dict,
        hostname: str,
        reputation_score: Optional[int],
        adjustment_reason: Optional[str]
    ) -> Tuple[str, float, str]:
        """Interpret final prediction score"""
        reasons = []
        
        # Add ML-based reasons (from features)
        if features.get('is_ip_address', 0) == 1:
            reasons.append("IP address URL")
        
        if features.get('is_suspicious_tld', 0) == 1:
            reasons.append("Suspicious TLD (.tk, .ml, etc.)")
        
        if features.get('long_path', 0) == 1:
            reasons.append("Unusually long path")
        
        if features.get('high_entropy', 0) == 1:
            reasons.append("Random-looking domain")
        
        if features.get('num_at', 0) > 0:
            reasons.append("Contains @ symbol")
        
        if features.get('subdomain_count', 0) > 4:
            reasons.append("Excessive subdomains")
        
        if features.get('brand_without_official_tld', 0) == 1:
            reasons.append("Possible brand impersonation")
        
        # Add adjustment reason if applied
        if adjustment_reason:
            reasons.append(adjustment_reason)
        
        # Determine status
        if final_score >= self.settings.malicious_threshold:
            status = "MALICIOUS"
            confidence = final_score
            if not reasons:
                reasons.append("ML model detected multiple threat indicators")
        
        elif final_score >= self.settings.suspicious_threshold:
            status = "SUSPICIOUS"
            confidence = final_score
            if not reasons:
                reasons.append("ML model detected some concerning patterns")
        
        else:
            status = "LEGITIMATE"
            confidence = 1 - final_score
            
            if reputation_score and reputation_score >= 70:
                reasons = [f"ML model + high reputation ({reputation_score}/100) confirm legitimacy"]
            elif reputation_score and reputation_score >= 40:
                reasons = [f"ML model predicts safe, reputation moderate ({reputation_score}/100)"]
            else:
                reasons = ["ML model found no significant threats"]
        
        reason = "; ".join(reasons) if reasons else "Analysis complete"
        
        return status, confidence, reason
    
    def is_loaded(self) -> bool:
        """Check if model is loaded"""
        return self.model is not None and self.feature_names is not None

_ml_service = None

def get_ml_service():
    """Get ML service singleton"""
    global _ml_service
    if _ml_service is None:
        _ml_service = MLServiceFinal()
    return _ml_service