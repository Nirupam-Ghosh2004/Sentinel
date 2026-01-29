export function parseURL(url) {
  try {
    const urlObj = new URL(url);
    return {
      protocol: urlObj.protocol,
      hostname: urlObj.hostname,
      pathname: urlObj.pathname,
      search: urlObj.search,
      hash: urlObj.hash,
      port: urlObj.port
    };
  } catch (error) {
    console.error('Invalid URL:', url);
    return null;
  }
}

export function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (error) {
    return '';
  }
}

export function extractFeatures(url) {
  const features = {};
  
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const path = urlObj.pathname;
    
    // Lexical features
    features.urlLength = url.length;
    features.domainLength = hostname.length;
    features.pathLength = path.length;
    features.numDots = (url.match(/\./g) || []).length;
    features.numHyphens = (url.match(/-/g) || []).length;
    features.numUnderscores = (url.match(/_/g) || []).length;
    features.numSlashes = (url.match(/\//g) || []).length;
    features.numDigits = (url.match(/\d/g) || []).length;
    features.numQuestions = (url.match(/\?/g) || []).length;
    features.numEquals = (url.match(/=/g) || []).length;
    features.numAt = (url.match(/@/g) || []).length;
    
    // Domain features
    features.subdomainCount = hostname.split('.').length - 2;
    features.hasIPAddress = /^\d+\.\d+\.\d+\.\d+$/.test(hostname);
    features.hasPort = urlObj.port !== '';
    features.protocol = urlObj.protocol;
    features.isHTTPS = urlObj.protocol === 'https:'\;
    
    // TLD analysis
    const tld = hostname.split('.').pop();
    features.tld = tld;
    features.suspiciousTLD = ['tk', 'ml', 'ga', 'cf', 'gq'].includes(tld);
    
    // Entropy calculation (randomness)
    features.entropy = calculateEntropy(hostname);
    
    return features;
  } catch (error) {
    console.error('Error extracting features:', error);
    return null;
  }
}

function calculateEntropy(str) {
  const len = str.length;
  const frequencies = {};
  
  for (let char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  
  let entropy = 0;
  for (let char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}
