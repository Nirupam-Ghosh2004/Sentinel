"""
Domain Reputation Service
Calculates trust score based on multiple signals
"""
import whois
import socket
import ssl
from datetime import datetime
from typing import Dict, Optional
from urllib.parse import urlparse
import dns.resolver

class DomainReputationService:
    """Calculate domain reputation from multiple sources"""
    
    def __init__(self):
        # Top 10K domains cache (most popular sites)
        self.top_domains = self._load_top_domains()
        
    def _load_top_domains(self):
        """Load commonly visited domains"""
        # Top sites that should always be trusted
        return {
            # Search & Tech
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
            'instagram.com', 'linkedin.com', 'reddit.com', 'wikipedia.org',
            'github.com', 'stackoverflow.com', 'medium.com', 'quora.com',
            
            # E-commerce
            'amazon.com', 'ebay.com', 'walmart.com', 'target.com',
            'bestbuy.com', 'etsy.com', 'shopify.com', 'aliexpress.com',
            
            # Tech/Cloud
            'microsoft.com', 'apple.com', 'adobe.com', 'oracle.com',
            'ibm.com', 'dell.com', 'hp.com', 'intel.com', 'nvidia.com',
            'cloudflare.com', 'aws.amazon.com', 'azure.microsoft.com',
            
            # News/Media
            'cnn.com', 'bbc.com', 'nytimes.com', 'washingtonpost.com',
            'theguardian.com', 'reuters.com', 'bloomberg.com', 'forbes.com',
            'techcrunch.com', 'wired.com', 'theverge.com',
            
            # Entertainment
            'netflix.com', 'spotify.com', 'twitch.tv', 'discord.com',
            'hulu.com', 'disneyplus.com', 'hbo.com', 'primevideo.com',
            
            # Productivity
            'zoom.us', 'slack.com', 'notion.so', 'dropbox.com',
            'box.com', 'trello.com', 'asana.com', 'monday.com',
            
            # Education
            'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
            'duolingo.com', 'codecademy.com',
            
            # Developer
            'npmjs.com', 'pypi.org', 'docker.com', 'kubernetes.io',
            'gitlab.com', 'bitbucket.org', 'vercel.com', 'netlify.com',
            'heroku.com', 'digitalocean.com',
            
            # Gaming
            'steampowered.com', 'epicgames.com', 'twitch.tv', 'ign.com',
            
            # Other
            'paypal.com', 'stripe.com', 'pinterest.com', 'tumblr.com'
        }
    
    def calculate_reputation_score(self, url: str) -> Dict:
        """
        Calculate overall reputation score (0-100)
        
        Scoring breakdown:
        - Popularity: 0-30 points
        - Domain Age: 0-25 points
        - SSL Certificate: 0-20 points
        - DNS Health: 0-15 points
        - WHOIS Info: 0-10 points
        
        Returns:
            dict with score and breakdown
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if not hostname:
                return self._get_default_score("Invalid hostname")
            
            print(f"🔍 Calculating reputation for: {hostname}")
            
            score_breakdown = {}
            total_score = 0
            
            # 1. Check popularity
            popularity_score = self._check_popularity(hostname)
            score_breakdown['popularity'] = {
                'score': popularity_score,
                'max': 30,
                'description': 'Domain popularity/ranking'
            }
            total_score += popularity_score
            
            # 2. Check domain age
            age_score, age_days = self._check_domain_age(hostname)
            score_breakdown['domain_age'] = {
                'score': age_score,
                'max': 25,
                'age_days': age_days,
                'description': 'How long domain has existed'
            }
            total_score += age_score
            
            # 3. Check SSL certificate
            ssl_score, ssl_info = self._check_ssl_certificate(hostname)
            score_breakdown['ssl_certificate'] = {
                'score': ssl_score,
                'max': 20,
                'info': ssl_info,
                'description': 'SSL/TLS certificate validity'
            }
            total_score += ssl_score
            
            # 4. Check DNS records
            dns_score, dns_info = self._check_dns_health(hostname)
            score_breakdown['dns_health'] = {
                'score': dns_score,
                'max': 15,
                'info': dns_info,
                'description': 'DNS configuration quality'
            }
            total_score += dns_score
            
            # 5. Check WHOIS information
            whois_score, whois_info = self._check_whois_info(hostname)
            score_breakdown['whois'] = {
                'score': whois_score,
                'max': 10,
                'info': whois_info,
                'description': 'Domain registration details'
            }
            total_score += whois_score
            
            trust_level = self._get_trust_level(total_score)
            
            print(f"  ✅ Score: {total_score}/100 ({trust_level})")
            
            return {
                'total_score': total_score,
                'max_score': 100,
                'trust_level': trust_level,
                'breakdown': score_breakdown,
                'hostname': hostname,
                'recommendation': self._get_recommendation(total_score)
            }
            
        except Exception as e:
            print(f"  ❌ Error calculating reputation: {e}")
            return self._get_default_score(f"Error: {str(e)}")
    
    def _check_popularity(self, hostname: str) -> int:
        """
        Check if domain is in top sites list
        Returns: 0-30 points
        """
        hostname_lower = hostname.lower()
        
        # Check exact match or subdomain
        for top_domain in self.top_domains:
            if hostname_lower == top_domain or hostname_lower.endswith('.' + top_domain):
                print(f"  ✅ Popular domain detected")
                return 30
        
        return 0
    
    def _check_domain_age(self, hostname: str) -> tuple:
        """
        Check how old the domain is
        Returns: (score 0-25, age_in_days)
        """
        try:
            w = whois.whois(hostname)
            
            if w.creation_date:
                # Handle list or single date
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if creation_date:
                    age = datetime.now() - creation_date
                    days_old = age.days
                    
                    print(f"  📅 Domain age: {days_old} days ({days_old // 365} years)")
                    
                    # Scoring
                    if days_old > 3650:  # 10+ years
                        return (25, days_old)
                    elif days_old > 1825:  # 5-10 years
                        return (20, days_old)
                    elif days_old > 730:  # 2-5 years
                        return (15, days_old)
                    elif days_old > 365:  # 1-2 years
                        return (10, days_old)
                    elif days_old > 180:  # 6-12 months
                        return (5, days_old)
                    elif days_old > 90:  # 3-6 months
                        return (2, days_old)
                    else:  # < 3 months (very suspicious)
                        print(f"  ⚠️  Very new domain (< 3 months)")
                        return (0, days_old)
                    
        except Exception as e:
            print(f"  ⚠️  WHOIS lookup failed: {e}")
            return (0, None)
        
        return (0, None)
    
    def _check_ssl_certificate(self, hostname: str) -> tuple:
        """
        Check SSL certificate validity and issuer
        Returns: (score 0-20, cert_info)
        """
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    not_after = datetime.strptime(
                        cert['notAfter'], 
                        '%b %d %H:%M:%S %Y %Z'
                    )
                    
                    if not_after > datetime.now():
                        score = 12  # Valid cert
                        
                        # Get issuer
                        issuer = dict(x[0] for x in cert['issuer'])
                        issuer_org = issuer.get('organizationName', 'Unknown')
                        
                        # Bonus for trusted issuers
                        trusted_issuers = [
                            "Let's Encrypt",
                            'DigiCert',
                            'GlobalSign',
                            'GeoTrust',
                            'Comodo',
                            'Sectigo',
                            'GoDaddy',
                            'Cloudflare'
                        ]
                        
                        if any(trusted in issuer_org for trusted in trusted_issuers):
                            score += 8
                            print(f"  🔒 Valid SSL from {issuer_org}")
                        else:
                            print(f"  🔒 Valid SSL (issuer: {issuer_org})")
                        
                        cert_info = {
                            'valid': True,
                            'issuer': issuer_org,
                            'expires': not_after.isoformat()
                        }
                        
                        return (score, cert_info)
                    else:
                        print(f"  ⚠️  Expired SSL certificate")
                        return (0, {'valid': False, 'reason': 'expired'})
                    
        except Exception as e:
            print(f"  ⚠️  No SSL or connection failed: {e}")
            return (0, {'valid': False, 'reason': str(e)})
        
        return (0, {'valid': False})
    
    def _check_dns_health(self, hostname: str) -> tuple:
        """
        Check DNS records quality
        Returns: (score 0-15, dns_info)
        """
        score = 0
        dns_info = {}
        
        try:
            # Check A record (IPv4)
            try:
                answers = dns.resolver.resolve(hostname, 'A')
                dns_info['a_records'] = [str(rdata) for rdata in answers]
                score += 5
                print(f"  ✅ Has A record")
            except:
                print(f"  ⚠️  No A record")
            
            # Check MX record (email)
            try:
                answers = dns.resolver.resolve(hostname, 'MX')
                dns_info['mx_records'] = [str(rdata) for rdata in answers]
                score += 5
                print(f"  ✅ Has MX record (email configured)")
            except:
                pass
            
            # Check NS record (nameservers)
            try:
                answers = dns.resolver.resolve(hostname, 'NS')
                ns_count = len(list(answers))
                dns_info['ns_count'] = ns_count
                
                if ns_count >= 2:
                    score += 5
                    print(f"  ✅ Has {ns_count} nameservers")
                elif ns_count >= 1:
                    score += 3
                
            except:
                pass
            
            return (score, dns_info)
            
        except Exception as e:
            print(f"  ⚠️  DNS check failed: {e}")
            return (0, {})
    
    def _check_whois_info(self, hostname: str) -> tuple:
        """
        Check WHOIS information quality
        Returns: (score 0-10, whois_info)
        """
        try:
            w = whois.whois(hostname)
            score = 0
            whois_info = {}
            
            # Has registrar
            if w.registrar:
                score += 5
                whois_info['registrar'] = w.registrar
                print(f"  ✅ Registrar: {w.registrar}")
            
            # Has name servers
            if w.name_servers and len(w.name_servers) >= 2:
                score += 3
                whois_info['nameservers_count'] = len(w.name_servers)
            
            # Has status
            if w.status:
                score += 2
                whois_info['status'] = w.status if isinstance(w.status, str) else w.status[0]
            
            return (score, whois_info)
            
        except Exception as e:
            print(f"  ⚠️  WHOIS failed: {e}")
            return (0, {})
    
    def _get_trust_level(self, score: int) -> str:
        """Convert numeric score to trust level"""
        if score >= 80:
            return 'very_high'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'very_low'
    
    def _get_recommendation(self, score: int) -> str:
        """Get recommendation based on score"""
        if score >= 80:
            return 'SAFE - High reputation domain'
        elif score >= 60:
            return 'PROBABLY SAFE - Good reputation'
        elif score >= 40:
            return 'PROCEED WITH CAUTION - Medium reputation'
        elif score >= 20:
            return 'SUSPICIOUS - Low reputation'
        else:
            return 'DANGEROUS - Very low reputation'
    
    def _get_default_score(self, reason: str) -> Dict:
        """Return default score structure"""
        return {
            'total_score': 0,
            'max_score': 100,
            'trust_level': 'unknown',
            'breakdown': {},
            'hostname': None,
            'recommendation': f'Unknown - {reason}',
            'error': reason
        }