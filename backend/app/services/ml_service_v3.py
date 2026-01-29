"""
ML Model Service V3 - Fixed for Subdomains
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

class MLServiceV3:
    """Enhanced ML service with reputation scoring"""
    
    def __init__(self):
        self.settings = get_settings()
        self.model = None
        self.feature_names = None
        self.extractor = URLFeatureExtractorV2()
        self.reputation_service = DomainReputationService()
        
        # EXPANDED: Include all major brand domains and their subdomains
        self.core_safe_domains = {
            # Google ecosystem
            'google.com', 'youtube.com', 'gmail.com', 'google.co.in',
            'google.co.uk', 'googleblog.com', 'gstatic.com', 'googleapis.com',
            'googleusercontent.com', 'googlevideo.com', 'google', 'gemini.google',
            
            # Microsoft
            'microsoft.com', 'outlook.com', 'live.com', 'office.com',
            'azure.com', 'msn.com', 'bing.com', 'windows.com',
            
            # Meta
            'facebook.com', 'instagram.com', 'whatsapp.com', 'messenger.com',
            'meta.com', 'fb.com', 'fbcdn.net',
            
            # Others
            'twitter.com', 'x.com', 'github.com', 'stackoverflow.com',
            'apple.com', 'icloud.com', 'amazon.com', 'netflix.com',
            'linkedin.com', 'reddit.com', 'pinterest.com', 'tumblr.com',
            'cloudflare.com', 'mozilla.org', 'wikipedia.org'
        }
        
        # Trusted parent domains (for subdomain checking)
        self.trusted_parent_domains = {
            'google', 'microsoft', 'apple', 'amazon', 'facebook',
            'meta', 'twitter', 'github', 'cloudflare', 'netflix'
        }
        
        self.load_model()
    
    def load_model(self):
        """Load the trained model"""
        try:
            model_path = self.settings.model_path
            features_path = self.settings.feature_names_path
            
            print(f"📦 Loading V2 model from: {model_path}")
            self.model = joblib.load(model_path)
            
            print(f"📦 Loading feature names from: {features_path}")
            self.feature_names = joblib.load(features_path)
            
            print(f"✅ Model V3 loaded with reputation scoring!")
            print(f"   ML Features: {len(self.feature_names)}")
            
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            raise
    
    def _get_root_domain(self, hostname: str) -> str:
        """Extract root domain from hostname"""
        parts = hostname.split('.')
        if len(parts) >= 2:
            # Get last two parts (e.g., google.com from mail.google.com)
            return '.'.join(parts[-2:])
        return hostname
    
    def _is_trusted_subdomain(self, hostname: str) -> bool:
        """Check if this is a subdomain of a trusted parent"""
        hostname_lower = hostname.lower()
        
        # Check if any trusted parent domain is in the hostname
        for parent in self.trusted_parent_domains:
            if f'.{parent}.' in hostname_lower or hostname_lower.startswith(f'{parent}.'):
                print(f"  ✅ Trusted subdomain of {parent}")
                return True
        
        return False
    
    def _is_core_safe_domain(self, hostname: str) -> bool:
        """Check if domain is in core safe list"""
        hostname_lower = hostname.lower()
        
        # Direct match
        if hostname_lower in self.core_safe_domains:
            return True
        
        # Subdomain match
        for safe_domain in self.core_safe_domains:
            if hostname_lower.endswith('.' + safe_domain):
                return True
        
        # Check trusted subdomains
        if self._is_trusted_subdomain(hostname_lower):
            return True
        
        return False
    
    def predict(self, url: str, use_reputation: bool = True) -> Dict:
        """
        Predict if URL is malicious using ML + Reputation
        """
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            hostname = parsed.hostname if parsed.hostname else ''
            
            # Step 1: Check core safe domains (including subdomains)
            if self._is_core_safe_domain(hostname):
                return {
                    'status': 'LEGITIMATE',
                    'confidence': 0.99,
                    'prediction_score': 0.01,
                    'reason': 'Core trusted domain or subdomain',
                    'source': 'whitelist',
                    'reputation_used': False,
                    'hostname': hostname
                }
            
            # Step 2: Extract ML features
            features = self.extractor.extract_features(url)
            
            # Critical threat patterns (always block)
            if features.get('is_ip_address', 0) == 1:
                return {
                    'status': 'MALICIOUS',
                    'confidence': 0.95,
                    'prediction_score': 0.95,
                    'reason': 'IP address instead of domain name',
                    'source': 'heuristic',
                    'reputation_used': False
                }
            
            if features.get('is_suspicious_tld', 0) == 1:
                return {
                    'status': 'MALICIOUS',
                    'confidence': 0.85,
                    'prediction_score': 0.85,
                    'reason': 'Suspicious top-level domain',
                    'source': 'heuristic',
                    'reputation_used': False
                }
            
            # Step 3: Reputation scoring (if enabled)
            reputation_score = None
            if use_reputation:
                print(f"\n{'='*60}")
                
                # For subdomains, check the root domain
                check_domain = hostname
                if hostname.count('.') > 1:
                    root_domain = self._get_root_domain(hostname)
                    print(f"  🔍 Subdomain detected, checking root: {root_domain}")
                    check_domain = root_domain
                
                reputation_result = self.reputation_service.calculate_reputation_score(f"https://{check_domain}")
                print(f"{'='*60}\n")
                
                reputation_score = reputation_result['total_score']
                
                # High reputation = likely safe
                if reputation_score >= 70:
                    return {
                        'status': 'LEGITIMATE',
                        'confidence': reputation_score / 100,
                        'prediction_score': 1 - (reputation_score / 100),
                        'reason': reputation_result['recommendation'],
                        'source': 'reputation',
                        'reputation_score': reputation_score,
                        'reputation_breakdown': reputation_result['breakdown'],
                        'reputation_used': True
                    }
            
            # Step 4: ML Prediction
            feature_df = pd.DataFrame([features])
            feature_df = feature_df[self.feature_names]
            
            prediction_proba = self.model.predict_proba(feature_df)[0]
            ml_score = float(prediction_proba[1])
            
            # Step 5: Adjust ML prediction based on reputation
            final_score = ml_score
            confidence_adjustment = 1.0
            
            if reputation_score is not None:
                # If reputation is moderate-high, reduce ML confidence in malicious prediction
                if reputation_score >= 50 and ml_score >= 0.5:
                    confidence_adjustment = 0.6  # Stronger adjustment
                    final_score = ml_score * confidence_adjustment
                    print(f"  📊 ML confidence adjusted by reputation: {ml_score:.3f} → {final_score:.3f}")
                elif reputation_score >= 40 and ml_score >= 0.5:
                    confidence_adjustment = 0.75
                    final_score = ml_score * confidence_adjustment
                    print(f"  📊 ML confidence adjusted by reputation: {ml_score:.3f} → {final_score:.3f}")
            
            # Step 6: Determine final status
            status, confidence, reason = self._interpret_prediction(
                final_score,
                features,
                hostname,
                reputation_score
            )
            
            result = {
                'status': status,
                'confidence': confidence,
                'prediction_score': final_score,
                'ml_raw_score': ml_score,
                'reason': reason,
                'source': 'ml_with_reputation' if reputation_score else 'ml_only',
                'reputation_score': reputation_score,
                'reputation_used': use_reputation,
                'hostname': hostname
            }
            
            return result
            
        except Exception as e:
            print(f"❌ Prediction error for {url}: {e}")
            raise
    
    def _interpret_prediction(
        self, 
        score: float, 
        features: Dict,
        hostname: str,
        reputation_score: Optional[int]
    ) -> Tuple[str, float, str]:
        """Interpret prediction score"""
        reasons = []
        
        # Analyze features
        if features.get('long_path', 0) == 1:
            reasons.append("Long URL path")
        
        if features.get('num_at', 0) > 0:
            reasons.append("Contains @ symbol")
        
        if features.get('subdomain_count', 0) > 4:
            reasons.append("Excessive subdomains")
        
        if features.get('high_entropy', 0) == 1:
            reasons.append("Random-looking domain")
        
        # Add reputation context
        if reputation_score is not None:
            if reputation_score < 30:
                reasons.append(f"Low reputation ({reputation_score}/100)")
            elif reputation_score >= 50:
                reasons.append(f"Good reputation ({reputation_score}/100)")
        
        # Determine status with adjusted thresholds
        if score >= self.settings.malicious_threshold:
            status = "MALICIOUS"
            confidence = score
            if not reasons:
                reasons.append("Multiple suspicious patterns")
        elif score >= self.settings.suspicious_threshold:
            status = "SUSPICIOUS"
            confidence = score
            if not reasons:
                reasons.append("Some suspicious characteristics")
        else:
            status = "LEGITIMATE"
            confidence = 1 - score
            if reputation_score and reputation_score >= 50:
                reasons = [f"Good reputation score ({reputation_score}/100)"]
            else:
                reasons = ["No significant threats detected"]
        
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
        _ml_service = MLServiceV3()
    return _ml_service