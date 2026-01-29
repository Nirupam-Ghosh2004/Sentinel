"""
ML Model Service - Handles predictions (Updated with Smart Whitelisting)
"""
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Tuple
import os
from urllib.parse import urlparse
from app.config import get_settings
from app.services.feature_extractor import URLFeatureExtractorV2

class MLService:
    """Service for ML model predictions"""
    
    def __init__(self):
        self.settings = get_settings()
        self.model = None
        self.feature_names = None
        self.extractor = URLFeatureExtractorV2()
        
        # Whitelist of known safe domains (exact match or endswith)
        self.safe_domains = {
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
            'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'reddit.com', 'wikipedia.org', 'amazon.com', 'ebay.com',
            'microsoft.com', 'apple.com', 'netflix.com', 'yahoo.com',
            'bing.com', 'duckduckgo.com', 'cloudflare.com', 'mozilla.org',
            'twitch.tv', 'discord.com', 'slack.com', 'zoom.us',
            'dropbox.com', 'gdrive.google.com', 'docs.google.com',
            'leetcode.com', 'hackerrank.com', 'codepen.io', 'replit.com'
        }
        
        # Domains that legitimately have long URLs (with query params)
        self.long_url_ok_domains = {
            'google.com', 'youtube.com', 'amazon.com', 'ebay.com',
            'github.com', 'stackoverflow.com', 'reddit.com',
            'leetcode.com', 'hackerrank.com', 'twitter.com',
            'facebook.com', 'linkedin.com', 'pinterest.com',
            'aliexpress.com', 'alibaba.com', 'walmart.com'
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
            
            print(f"✅ Model V2 loaded successfully!")
            print(f"   Features: {len(self.feature_names)}")
            print(f"   Safe domains: {len(self.safe_domains)}")
            print(f"   Long URL OK domains: {len(self.long_url_ok_domains)}")
            
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            raise
    
    def _is_whitelisted_domain(self, hostname: str) -> bool:
        """Check if domain is in whitelist"""
        hostname_lower = hostname.lower()
        for safe_domain in self.safe_domains:
            if hostname_lower == safe_domain or hostname_lower.endswith('.' + safe_domain):
                return True
        return False
    
    def _allows_long_urls(self, hostname: str) -> bool:
        """Check if domain legitimately has long URLs"""
        hostname_lower = hostname.lower()
        for domain in self.long_url_ok_domains:
            if hostname_lower == domain or hostname_lower.endswith('.' + domain):
                return True
        return False
    
    def predict(self, url: str) -> Dict:
        """
        Predict if URL is malicious
        
        Returns:
            dict: Prediction result with status, confidence, etc.
        """
        try:
            # Extract features
            features = self.extractor.extract_features(url)
            
            # Apply heuristic overrides BEFORE ML prediction
            override_result = self._apply_heuristic_overrides(url, features)
            if override_result:
                return override_result
            
            # Convert to DataFrame with correct column order
            feature_df = pd.DataFrame([features])
            feature_df = feature_df[self.feature_names]
            
            # Get prediction
            prediction_proba = self.model.predict_proba(feature_df)[0]
            prediction_score = float(prediction_proba[1])  # Probability of malicious
            
            # Determine status
            status, confidence, reason = self._interpret_prediction(
                prediction_score, 
                features,
                url
            )
            
            return {
                'status': status,
                'confidence': confidence,
                'prediction_score': prediction_score,
                'reason': reason,
                'features': features
            }
            
        except Exception as e:
            print(f"❌ Prediction error for {url}: {e}")
            raise
    
    def _apply_heuristic_overrides(self, url: str, features: Dict) -> Dict:
        """Apply heuristic rules to override ML prediction"""
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            hostname = parsed.hostname if parsed.hostname else ''
            
            # Rule 1: Whitelist known safe domains (HIGHEST PRIORITY)
            if self._is_whitelisted_domain(hostname):
                return {
                    'status': 'LEGITIMATE',
                    'confidence': 0.99,
                    'prediction_score': 0.01,
                    'reason': 'Verified safe domain (whitelist)',
                    'features': features
                }
            
            # Rule 2: IP addresses (immediate block)
            if features.get('is_ip_address', 0) == 1:
                return {
                    'status': 'MALICIOUS',
                    'confidence': 0.95,
                    'prediction_score': 0.95,
                    'reason': 'IP address instead of domain name',
                    'features': features
                }
            
            # Rule 3: Suspicious TLD
            if features.get('is_suspicious_tld', 0) == 1:
                return {
                    'status': 'MALICIOUS',
                    'confidence': 0.85,
                    'prediction_score': 0.85,
                    'reason': 'Suspicious top-level domain (.tk, .ml, .ga, etc.)',
                    'features': features
                }
            
            # Rule 4: @ symbol (phishing redirect)
            if features.get('num_at', 0) > 0:
                return {
                    'status': 'MALICIOUS',
                    'confidence': 0.90,
                    'prediction_score': 0.90,
                    'reason': 'URL contains @ symbol (potential redirect)',
                    'features': features
                }
            
            return None
            
        except Exception as e:
            print(f"Error in heuristic override: {e}")
            return None
    
    def _interpret_prediction(
        self, 
        score: float, 
        features: Dict,
        url: str
    ) -> Tuple[str, float, str]:
        """Interpret prediction score and generate explanation"""
        reasons = []
        
        # Parse URL for additional checks
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            hostname = parsed.hostname if parsed.hostname else ''
        except:
            hostname = ''
        
        # Analyze features to build explanation
        if features.get('is_ip_address', 0) == 1:
            reasons.append("IP address instead of domain name")
        
        if features.get('is_suspicious_tld', 0) == 1:
            reasons.append("Suspicious top-level domain")
        
        # IMPROVED: Only flag long paths, not long queries
        if features.get('long_path', 0) == 1:
            # Check if this domain is allowed to have long URLs
            if not self._allows_long_urls(hostname):
                reasons.append("Unusually long URL path")
        
        if features.get('num_at', 0) > 0:
            reasons.append("Contains @ symbol (redirect)")
        
        if features.get('subdomain_count', 0) > 4:
            reasons.append("Excessive subdomains")
        
        if features.get('high_entropy', 0) == 1:
            # Don't flag high entropy for whitelisted domains
            if not self._is_whitelisted_domain(hostname):
                reasons.append("High randomness in domain name")
        
        if features.get('is_https', 0) == 0:
            # Only mention for non-whitelisted domains
            if not self._is_whitelisted_domain(hostname):
                reasons.append("No HTTPS encryption")
        
        if features.get('has_https_in_hostname', 0) == 1:
            reasons.append("HTTPS in domain name (deceptive)")
        
        if features.get('brand_without_official_tld', 0) == 1:
            reasons.append("Brand name in non-official domain (typosquatting)")
        
        # Determine status based on score
        if score >= self.settings.malicious_threshold:
            status = "MALICIOUS"
            confidence = score
            if not reasons:
                reasons.append("Multiple suspicious patterns detected")
        elif score >= self.settings.suspicious_threshold:
            status = "SUSPICIOUS"
            confidence = score
            if not reasons:
                reasons.append("Some suspicious characteristics found")
        else:
            status = "LEGITIMATE"
            confidence = 1 - score
            reasons = ["No suspicious patterns detected"]
        
        reason = "; ".join(reasons) if reasons else "Unknown"
        
        return status, confidence, reason
    
    def is_loaded(self) -> bool:
        """Check if model is loaded"""
        return self.model is not None and self.feature_names is not None

# Singleton instance
_ml_service = None

def get_ml_service() -> MLService:
    """Get ML service singleton"""
    global _ml_service
    if _ml_service is None:
        _ml_service = MLService()
    return _ml_service