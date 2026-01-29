import { extractDomain, extractFeatures } from './url-parser.js';

export function quickHeuristicCheck(url) {
  const features = extractFeatures(url);
  
  if (!features) {
    return { shouldBlock: false };
  }

  // Rule 1: IP address instead of domain
  if (features.hasIPAddress) {
    return {
      shouldBlock: true,
      reason: 'URL uses IP address instead of domain name',
      confidence: 0.85
    };
  }

  // Rule 2: Suspicious TLD
  if (features.suspiciousTLD) {
    return {
      shouldBlock: true,
      reason: 'Suspicious top-level domain (TLD)',
      confidence: 0.75
    };
  }

  // Rule 3: Excessive subdomains
  if (features.subdomainCount > 4) {
    return {
      shouldBlock: true,
      reason: 'Excessive number of subdomains',
      confidence: 0.70
    };
  }

  // Rule 4: Very long URL
  if (features.urlLength > 200) {
    return {
      shouldBlock: true,
      reason: 'Abnormally long URL',
      confidence: 0.65
    };
  }

  // Rule 5: @ symbol in URL (redirects)
  if (features.numAt > 0) {
    return {
      shouldBlock: true,
      reason: 'URL contains @ symbol (potential redirect)',
      confidence: 0.90
    };
  }

  // Rule 6: High entropy (random characters)
  if (features.entropy > 4.5) {
    return {
      shouldBlock: true,
      reason: 'Highly random domain name',
      confidence: 0.60
    };
  }

  // Rule 7: Phishing keywords in URL
  const phishingKeywords = [
    'secure', 'account', 'update', 'signin', 'banking',
    'verify', 'login', 'ebayisapi', 'paypal', 'suspended'
  ];
  
  const urlLower = url.toLowerCase();
  for (let keyword of phishingKeywords) {
    if (urlLower.includes(keyword)) {
      // Check if it's actually from the legitimate domain
      const domain = extractDomain(url);
      if (!domain.includes('paypal.com') && urlLower.includes('paypal')) {
        return {
          shouldBlock: true,
          reason: `Suspicious keyword "${keyword}" in non-official domain`,
          confidence: 0.80
        };
      }
    }
  }

  // Rule 8: HTTPS in hostname (trying to look secure)
  const hostname = extractDomain(url);
  if (hostname.includes('https')) {
    return {
      shouldBlock: true,
      reason: 'Domain name contains "https" (deceptive)',
      confidence: 0.95
    };
  }

  return { shouldBlock: false };
}
