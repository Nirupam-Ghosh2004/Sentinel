"""
Threat Intelligence Integration
Check domain against external databases
"""
import requests
from typing import Dict, Optional
import os

class ThreatIntelligenceService:
    """Integrate with multiple threat intelligence sources"""
    
    def __init__(self):
        # API keys (set via environment variables)
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.google_safe_browsing_key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')
        
    def check_all_sources(self, url: str) -> Dict:
        """
        Check URL against all available threat intel sources
        
        Returns aggregated threat intelligence
        """
        results = {
            'is_malicious': False,
            'threat_score': 0,  # 0-100, higher = more malicious
            'sources': {}
        }
        
        # 1. Google Safe Browsing
        gsb_result = self._check_google_safe_browsing(url)
        results['sources']['google_safe_browsing'] = gsb_result
        if gsb_result.get('is_malicious'):
            results['threat_score'] += 40
        
        # 2. VirusTotal
        vt_result = self._check_virustotal(url)
        results['sources']['virustotal'] = vt_result
        if vt_result.get('malicious_count', 0) > 3:
            results['threat_score'] += 30
        
        # 3. PhishTank (free, no API key needed)
        pt_result = self._check_phishtank(url)
        results['sources']['phishtank'] = pt_result
        if pt_result.get('in_database'):
            results['threat_score'] += 30
        
        # Overall determination
        if results['threat_score'] >= 30:
            results['is_malicious'] = True
        
        return results
    
    def _check_google_safe_browsing(self, url: str) -> Dict:
        """Check against Google Safe Browsing API"""
        if not self.google_safe_browsing_key:
            return {'available': False}
        
        try:
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_safe_browsing_key}"
            
            payload = {
                "client": {
                    "clientId": "malicious-url-detector",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                is_malicious = bool(data.get('matches'))
                
                return {
                    'available': True,
                    'is_malicious': is_malicious,
                    'details': data.get('matches', [])
                }
                
        except Exception as e:
            print(f"GSB API error: {e}")
            return {'available': False, 'error': str(e)}
        
        return {'available': False}
    
    def _check_virustotal(self, url: str) -> Dict:
        """Check against VirusTotal API"""
        if not self.virustotal_api_key:
            return {'available': False}
        
        try:
            # VirusTotal v3 API
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            headers = {
                "x-apikey": self.virustotal_api_key
            }
            
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(api_url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                return {
                    'available': True,
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'harmless_count': stats.get('harmless', 0),
                    'total_scans': sum(stats.values())
                }
                
        except Exception as e:
            print(f"VirusTotal API error: {e}")
            return {'available': False, 'error': str(e)}
        
        return {'available': False}
    
    def _check_phishtank(self, url: str) -> Dict:
        """Check against PhishTank (free, no API key)"""
        try:
            # PhishTank API
            api_url = "https://checkurl.phishtank.com/checkurl/"
            
            data = {
                'url': url,
                'format': 'json'
            }
            
            response = requests.post(api_url, data=data, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                
                return {
                    'available': True,
                    'in_database': result.get('results', {}).get('in_database', False),
                    'verified': result.get('results', {}).get('verified', False)
                }
                
        except Exception as e:
            print(f"PhishTank API error: {e}")
            return {'available': False, 'error': str(e)}
        
        return {'available': False}