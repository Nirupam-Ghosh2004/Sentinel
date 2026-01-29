"""
Feature extraction from URLs for ML model training
"""
import re
import math
from urllib.parse import urlparse
import pandas as pd
import numpy as np

class URLFeatureExtractor:
    """Extract features from URLs for machine learning"""
    
    def __init__(self):
        self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click', 'link']
        self.brand_keywords = ['paypal', 'google', 'facebook', 'amazon', 'microsoft', 
                               'apple', 'netflix', 'instagram', 'twitter', 'linkedin']
    
    def extract_features(self, url):
        """Extract all features from a single URL"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or parsed.netloc
            path = parsed.path
            query = parsed.query
            
            features = {}
            
            # === LEXICAL FEATURES ===
            features['url_length'] = len(url)
            features['hostname_length'] = len(hostname) if hostname else 0
            features['path_length'] = len(path)
            features['query_length'] = len(query)
            
            # Character counts
            features['num_dots'] = url.count('.')
            features['num_hyphens'] = url.count('-')
            features['num_underscores'] = url.count('_')
            features['num_slashes'] = url.count('/')
            features['num_questionmarks'] = url.count('?')
            features['num_equals'] = url.count('=')
            features['num_at'] = url.count('@')
            features['num_ampersand'] = url.count('&')
            features['num_exclamation'] = url.count('!')
            features['num_space'] = url.count(' ')
            features['num_tilde'] = url.count('~')
            features['num_percent'] = url.count('%')
            
            # Digit features
            features['num_digits'] = sum(c.isdigit() for c in url)
            features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0
            
            # === HOSTNAME FEATURES ===
            if hostname:
                # Subdomain count
                parts = hostname.split('.')
                features['subdomain_count'] = len(parts) - 2 if len(parts) >= 2 else 0
                
                # IP address check
                features['is_ip_address'] = 1 if self._is_ip_address(hostname) else 0
                
                # TLD features
                tld = parts[-1] if len(parts) > 0 else ''
                features['tld_length'] = len(tld)
                features['is_suspicious_tld'] = 1 if tld.lower() in self.suspicious_tlds else 0
                
                # Entropy
                features['hostname_entropy'] = self._calculate_entropy(hostname)
                
                # Contains suspicious words
                features['has_https_in_hostname'] = 1 if 'https' in hostname.lower() else 0
                features['has_http_in_hostname'] = 1 if 'http' in hostname.lower() else 0
                features['has_www_count'] = hostname.lower().count('www')
                
                # Brand keywords
                features['contains_brand'] = 1 if any(brand in hostname.lower() for brand in self.brand_keywords) else 0
                
                # Longest token in hostname
                tokens = re.split(r'[.\-_]', hostname)
                features['longest_token_length'] = max([len(t) for t in tokens]) if tokens else 0
                features['avg_token_length'] = np.mean([len(t) for t in tokens]) if tokens else 0
            else:
                # Default values if no hostname
                features['subdomain_count'] = 0
                features['is_ip_address'] = 0
                features['tld_length'] = 0
                features['is_suspicious_tld'] = 0
                features['hostname_entropy'] = 0
                features['has_https_in_hostname'] = 0
                features['has_http_in_hostname'] = 0
                features['has_www_count'] = 0
                features['contains_brand'] = 0
                features['longest_token_length'] = 0
                features['avg_token_length'] = 0
            
            # === PROTOCOL FEATURES ===
            features['is_https'] = 1 if parsed.scheme == 'https' else 0
            features['has_port'] = 1 if parsed.port else 0
            features['port_number'] = parsed.port if parsed.port else 0
            
            # === PATH FEATURES ===
            features['path_token_count'] = len([t for t in path.split('/') if t])
            features['has_fragment'] = 1 if parsed.fragment else 0
            
            # === QUERY FEATURES ===
            features['query_param_count'] = len(query.split('&')) if query else 0
            
            # === SUSPICIOUS PATTERNS ===
            features['has_double_slash'] = 1 if '//' in path else 0
            features['prefix_suffix_count'] = hostname.count('-') if hostname else 0
            
            # Obfuscation detection
            features['has_punycode'] = 1 if 'xn--' in url else 0
            
            return features
            
        except Exception as e:
            print(f"Error extracting features from {url}: {e}")
            # Return default features on error
            return self._get_default_features()
    
    def _is_ip_address(self, hostname):
        """Check if hostname is an IP address"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, hostname))
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy"""
        if not text:
            return 0
        
        # Character frequency
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        length = len(text)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _get_default_features(self):
        """Return default feature dict (all zeros)"""
        return {
            'url_length': 0, 'hostname_length': 0, 'path_length': 0, 'query_length': 0,
            'num_dots': 0, 'num_hyphens': 0, 'num_underscores': 0, 'num_slashes': 0,
            'num_questionmarks': 0, 'num_equals': 0, 'num_at': 0, 'num_ampersand': 0,
            'num_exclamation': 0, 'num_space': 0, 'num_tilde': 0, 'num_percent': 0,
            'num_digits': 0, 'digit_ratio': 0, 'subdomain_count': 0, 'is_ip_address': 0,
            'tld_length': 0, 'is_suspicious_tld': 0, 'hostname_entropy': 0,
            'has_https_in_hostname': 0, 'has_http_in_hostname': 0, 'has_www_count': 0,
            'contains_brand': 0, 'longest_token_length': 0, 'avg_token_length': 0,
            'is_https': 0, 'has_port': 0, 'port_number': 0, 'path_token_count': 0,
            'has_fragment': 0, 'query_param_count': 0, 'has_double_slash': 0,
            'prefix_suffix_count': 0, 'has_punycode': 0
        }
    
    def extract_features_batch(self, urls):
        """Extract features from a list of URLs"""
        features_list = []
        for url in urls:
            features_list.append(self.extract_features(url))
        return pd.DataFrame(features_list)

# Test the feature extractor
if __name__ == '__main__':
    extractor = URLFeatureExtractor()
    
    # Test with sample URLs
    test_urls = [
        'https://www.google.com',
        'http://192.168.1.1',
        'http://suspicious-phishing-site.tk',
        'https://paypal-secure-login-verify.com/account'
    ]
    
    print("Testing Feature Extraction:")
    print("=" * 60)
    
    for url in test_urls:
        features = extractor.extract_features(url)
        print(f"\nURL: {url}")
        print(f"Features extracted: {len(features)}")
        print(f"Sample: url_length={features['url_length']}, "
              f"is_ip={features['is_ip_address']}, "
              f"entropy={features['hostname_entropy']:.2f}")