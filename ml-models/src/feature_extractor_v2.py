"""
Improved Feature Extraction v2.0
Fixes false positives and adds better features
"""
import re
import math
from urllib.parse import urlparse
import pandas as pd
import numpy as np
from collections import Counter

class URLFeatureExtractorV2:
    """Enhanced feature extraction with better discriminative features"""
    
    def __init__(self):
        self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click', 
                                'link', 'download', 'top', 'stream', 'bid', 'date']
        
        self.brand_keywords = ['paypal', 'google', 'facebook', 'amazon', 'microsoft', 
                               'apple', 'netflix', 'instagram', 'twitter', 'linkedin',
                               'yahoo', 'bank', 'secure', 'account', 'verify', 'update']
        
        self.suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update',
                                    'confirm', 'suspended', 'locked', 'unusual', 'activity']
        
        # Common legitimate TLDs
        self.common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'ai']
    
    def extract_features(self, url):
        """Extract improved features from URL"""
        try:
            # Ensure URL has scheme
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            hostname = parsed.hostname if parsed.hostname else ''
            path = parsed.path if parsed.path else '/'
            query = parsed.query if parsed.query else ''
            
            features = {}
            
            #  IMPROVED FEATURES 
            
            # LENGTH FEATURES (NORMALIZED) 
            features['url_length'] = len(url)
            features['hostname_length'] = len(hostname)
            
            # IMPROVED: Ratio features instead of absolute lengths
            features['path_to_url_ratio'] = len(path) / len(url) if len(url) > 0 else 0
            features['query_to_url_ratio'] = len(query) / len(url) if len(url) > 0 else 0
            features['hostname_to_url_ratio'] = len(hostname) / len(url) if len(url) > 0 else 0
            
            # BINARY PATH FEATURES (BETTER THAN RAW LENGTH) 
            features['has_path'] = 1 if len(path) > 1 else 0  # More than just '/'
            features['has_query'] = 1 if len(query) > 0 else 0
            features['long_path'] = 1 if len(path) > 50 else 0  # Flag only very long paths
            
            #  CHARACTER DISTRIBUTION 
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_slashes'] = url.count('/')
            features['num_questionmarks'] = url.count('?')
            features['num_equals'] = url.count('=')
            features['num_at'] = url.count('@')
            features['num_ampersand'] = url.count('&')
            features['num_percent'] = url.count('%')
            
            # DIGIT FEATURES 
            features['num_digits'] = sum(c.isdigit() for c in url)
            features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0
            features['digits_in_hostname'] = sum(c.isdigit() for c in hostname)
            
            # HOSTNAME ANALYSIS 
            if hostname:
                parts = hostname.split('.')
                
                # Subdomain features
                features['subdomain_count'] = len(parts) - 2 if len(parts) >= 2 else 0
                features['has_subdomain'] = 1 if len(parts) > 2 else 0
                
                # IP address
                features['is_ip_address'] = 1 if self._is_ip_address(hostname) else 0
                
                # TLD analysis
                tld = parts[-1].lower() if len(parts) > 0 else ''
                features['tld_length'] = len(tld)
                features['is_suspicious_tld'] = 1 if tld in self.suspicious_tlds else 0
                features['is_common_tld'] = 1 if tld in self.common_tlds else 0
                
                # Entropy (randomness)
                features['hostname_entropy'] = self._calculate_entropy(hostname)
                features['high_entropy'] = 1 if features['hostname_entropy'] > 4.0 else 0
                
                # Deceptive patterns
                features['has_https_in_hostname'] = 1 if 'https' in hostname.lower() else 0
                features['has_http_in_hostname'] = 1 if 'http' in hostname.lower() else 0
                features['has_www_count'] = hostname.lower().count('www')
                
                # Brand impersonation
                features['contains_brand'] = 1 if any(brand in hostname.lower() for brand in self.brand_keywords) else 0
                
                # NEW: Brand typosquatting detection
                features['brand_without_official_tld'] = self._check_brand_typosquat(hostname)
                
                # Token analysis
                tokens = re.split(r'[.\-_]', hostname)
                features['longest_token_length'] = max([len(t) for t in tokens]) if tokens else 0
                features['avg_token_length'] = np.mean([len(t) for t in tokens]) if tokens else 0
                features['num_tokens'] = len(tokens)
                
                # NEW: Consonant-vowel ratio (random domains have unusual ratios)
                features['consonant_vowel_ratio'] = self._calculate_cv_ratio(hostname)
                
            else:
                # Defaults for missing hostname
                self._set_hostname_defaults(features)
            
            # === PROTOCOL FEATURES ===
            features['is_https'] = 1 if parsed.scheme == 'https' else 0
            features['has_port'] = 1 if parsed.port else 0
            features['unusual_port'] = 1 if parsed.port and parsed.port not in [80, 443, 8080] else 0
            
            # === PATH ANALYSIS ===
            path_tokens = [t for t in path.split('/') if t]
            features['path_token_count'] = len(path_tokens)
            features['has_fragment'] = 1 if parsed.fragment else 0
            
            # NEW: Suspicious path keywords
            features['suspicious_path_keywords'] = sum(1 for kw in self.suspicious_keywords 
                                                       if kw in path.lower())
            
            # === QUERY ANALYSIS ===
            features['query_param_count'] = len(query.split('&')) if query else 0
            features['many_params'] = 1 if features['query_param_count'] > 5 else 0
            
            # === SUSPICIOUS PATTERNS ===
            features['has_double_slash'] = 1 if '//' in path else 0
            features['excessive_hyphens'] = 1 if hostname.count('-') > 3 else 0
            features['has_punycode'] = 1 if 'xn--' in url else 0
            
            # NEW: URL shortener detection
            features['is_url_shortener'] = self._is_url_shortener(hostname)
            
            # NEW: Homograph attack detection (unicode lookalikes)
            features['has_unicode'] = 1 if any(ord(c) > 127 for c in url) else 0
            
            return features
            
        except Exception as e:
            print(f"Error extracting features from {url}: {e}")
            return self._get_default_features()
    
    def _is_ip_address(self, hostname):
        """Check if hostname is an IP address"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, hostname))
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy"""
        if not text:
            return 0
        freq = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())
        return entropy
    
    def _calculate_cv_ratio(self, text):
        """Calculate consonant to vowel ratio"""
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        
        text_lower = text.lower()
        v_count = sum(1 for c in text_lower if c in vowels)
        c_count = sum(1 for c in text_lower if c in consonants)
        
        if v_count == 0:
            return c_count
        return c_count / v_count
    
    def _check_brand_typosquat(self, hostname):
        """Check if hostname contains brand name but wrong TLD"""
        brands_with_tlds = {
            'paypal': 'paypal.com',
            'google': 'google.com',
            'facebook': 'facebook.com',
            'amazon': 'amazon.com',
            'microsoft': 'microsoft.com'
        }
        
        for brand, official in brands_with_tlds.items():
            if brand in hostname.lower() and not hostname.lower().endswith(official):
                return 1
        return 0
    
    def _is_url_shortener(self, hostname):
        """Check if URL is from a shortener service"""
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 
                      'buff.ly', 'is.gd', 'cli.gs', 'tiny.cc']
        return 1 if any(shortener in hostname.lower() for shortener in shorteners) else 0
    
    def _set_hostname_defaults(self, features):
        """Set default values for hostname features"""
        defaults = {
            'subdomain_count': 0, 'has_subdomain': 0, 'is_ip_address': 0,
            'tld_length': 0, 'is_suspicious_tld': 0, 'is_common_tld': 0,
            'hostname_entropy': 0, 'high_entropy': 0, 'has_https_in_hostname': 0,
            'has_http_in_hostname': 0, 'has_www_count': 0, 'contains_brand': 0,
            'brand_without_official_tld': 0, 'longest_token_length': 0,
            'avg_token_length': 0, 'num_tokens': 0, 'consonant_vowel_ratio': 0,
            'digits_in_hostname': 0
        }
        features.update(defaults)
    
    def _get_default_features(self):
        """Return default features (all zeros)"""
        features = {}
        # Add all feature names with 0 values
        feature_names = [
            'url_length', 'hostname_length', 'path_to_url_ratio', 'query_to_url_ratio',
            'hostname_to_url_ratio', 'has_path', 'has_query', 'long_path',
            'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
            'num_questionmarks', 'num_equals', 'num_at', 'num_ampersand', 'num_percent',
            'num_digits', 'digit_ratio', 'digits_in_hostname',
            'subdomain_count', 'has_subdomain', 'is_ip_address', 'tld_length',
            'is_suspicious_tld', 'is_common_tld', 'hostname_entropy', 'high_entropy',
            'has_https_in_hostname', 'has_http_in_hostname', 'has_www_count',
            'contains_brand', 'brand_without_official_tld', 'longest_token_length',
            'avg_token_length', 'num_tokens', 'consonant_vowel_ratio',
            'is_https', 'has_port', 'unusual_port', 'path_token_count', 'has_fragment',
            'suspicious_path_keywords', 'query_param_count', 'many_params',
            'has_double_slash', 'excessive_hyphens', 'has_punycode',
            'is_url_shortener', 'has_unicode'
        ]
        return {name: 0 for name in feature_names}
    
    def extract_features_batch(self, urls):
        """Extract features from list of URLs"""
        features_list = []
        for url in urls:
            features_list.append(self.extract_features(url))
        return pd.DataFrame(features_list)


# Test the improved extractor
if __name__ == '__main__':
    extractor = URLFeatureExtractorV2()
    
    test_urls = [
        'https://www.google.com',
        'http://192.168.1.1',
        'http://suspicious-phishing-site.tk',
        'https://paypal-secure-login-verify.com/account',
        'http://bit.ly/abc123',
        'https://amazon.com/products/item123'
    ]
    
    print("Testing Improved Feature Extraction V2:")
    print("=" * 70)
    
    for url in test_urls:
        features = extractor.extract_features(url)
        print(f"\nURL: {url}")
        print(f"  Total features: {len(features)}")
        print(f"  is_ip: {features['is_ip_address']}")
        print(f"  has_path: {features['has_path']}")
        print(f"  path_ratio: {features['path_to_url_ratio']:.3f}")
        print(f"  is_suspicious_tld: {features['is_suspicious_tld']}")
        print(f"  brand_typosquat: {features['brand_without_official_tld']}")