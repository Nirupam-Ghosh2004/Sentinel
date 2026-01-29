"""
Smart URL Detector
Combines ML, reputation, threat intel, and user feedback
"""
from typing import Dict
from app.services.ml_service import get_ml_service
from app.services.reputation.domain_reputation import DomainReputationService
from app.services.reputation.threat_intel import ThreatIntelligenceService
import json
import os

class SmartURLDetector:
    """
    Multi-signal URL detection system
    
    Decision logic:
    1. Check static whitelist → LEGITIMATE
    2. Check threat intelligence → MALICIOUS if found
    3. Calculate reputation score → LEGITIMATE if high (80+)
    4. Check dynamic whitelist (user feedback) → LEGITIMATE
    5. Run ML prediction → Use confidence-based decision
    """
    
    def __init__(self):
        self.ml_service = get_ml_service()
        self.reputation_service = DomainReputationService()
        self.threat_intel = ThreatIntelligenceService()
        self.load_dynamic_whitelist()
    
    def load_dynamic_whitelist(self):
        """Load user-reported safe domains"""
        if os.path.exists('dynamic_whitelist.json'):
            with open('dynamic_whitelist.json', 'r') as f:
                self.dynamic_whitelist = set(json.load(f))
        else:
            self.dynamic_whitelist = set()
    
    def check_url(self, url: str) -> Dict:
        """
        Comprehensive URL check with multiple signals
        """
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            # Signal 1: Static whitelist (handled by ML service)
            ml_result = self.ml_service.predict(url)
            
            if ml_result['status'] == 'LEGITIMATE' and ml_result['confidence'] >= 0.99:
                # Already whitelisted
                return ml_result
            
            # Signal 2: Dynamic whitelist (user feedback)
            if hostname in self.dynamic_whitelist:
                return {
                    'status': 'LEGITIMATE',
                    'confidence': 0.95,
                    'reason': 'User-verified safe domain',
                    'source': 'user_feedback'
                }
            
            # Signal 3: Threat Intelligence (only if not whitelisted)
            threat_result = self.threat_intel.check_all_sources(url)
            if threat_result['is_malicious']:
                return {
                    'status': 'MALICIOUS',
                    'confidence': threat_result['threat_score'] / 100,
                    'reason': 'Flagged by threat intelligence databases',
                    'source': 'threat_intel',
                    'details': threat_result
                }
            
            # Signal 4: Domain Reputation
            reputation = self.reputation_service.calculate_reputation_score(url)
            
            # High reputation = likely legitimate
            if reputation['total_score'] >= 80:
                return {
                    'status': 'LEGITIMATE',
                    'confidence': reputation['total_score'] / 100,
                    'reason': 'High domain reputation score',
                    'source': 'reputation',
                    'reputation_breakdown': reputation
                }
            
            # Signal 5: ML Prediction (with context)
            # Adjust ML confidence based on reputation
            adjusted_confidence = ml_result['confidence']
            
            if reputation['total_score'] >= 50:
                # Moderate reputation - reduce ML confidence in malicious prediction
                if ml_result['status'] == 'MALICIOUS':
                    adjusted_confidence *= 0.7  # Reduce confidence
            
            ml_result['adjusted_confidence'] = adjusted_confidence
            ml_result['reputation_score'] = reputation['total_score']
            
            return ml_result
            
        except Exception as e:
            print(f"Error in smart detection: {e}")
            # Fallback to ML only
            return self.ml_service.predict(url)