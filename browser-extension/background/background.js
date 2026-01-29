// Malicious URL Detector - Background Script (Fixed)

// ==================== CACHE MANAGER ====================
class CacheManager {
  constructor() {
    this.cacheDuration = 3600000; // 1 hour
  }
  
  async get(url) {
    try {
      const result = await chrome.storage.local.get([url]);
      if (result[url]) {
        const cached = result[url];
        if (Date.now() - cached.timestamp < this.cacheDuration) {
          return cached.data;
        }
        await this.remove(url);
      }
      return null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }
  
  async set(url, data) {
    try {
      const cacheEntry = { data: data, timestamp: Date.now() };
      await chrome.storage.local.set({ [url]: cacheEntry });
    } catch (error) {
      console.error('Cache set error:', error);
    }
  }
  
  async remove(url) {
    try {
      await chrome.storage.local.remove([url]);
    } catch (error) {
      console.error('Cache remove error:', error);
    }
  }
  
  async clear() {
    try {
      await chrome.storage.local.clear();
    } catch (error) {
      console.error('Cache clear error:', error);
    }
  }
}

// ==================== WHITELIST ====================
const SAFE_DOMAINS = [
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
  'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
  'reddit.com', 'wikipedia.org', 'amazon.com', 'ebay.com',
  'microsoft.com', 'apple.com', 'netflix.com', 'yahoo.com',
  'leetcode.com', 'hackerrank.com', 'codepen.io', 'replit.com',
  'twitch.tv', 'discord.com', 'slack.com', 'zoom.us',
  'pinterest.com', 'tumblr.com', 'dropbox.com', 'notion.so'
];

const LONG_URL_OK_DOMAINS = [
  'google.com', 'youtube.com', 'amazon.com', 'ebay.com',
  'github.com', 'stackoverflow.com', 'reddit.com',
  'leetcode.com', 'hackerrank.com', 'twitter.com',
  'facebook.com', 'linkedin.com', 'pinterest.com'
];

// ==================== UTILITY FUNCTIONS ====================
function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (error) {
    return '';
  }
}

function isWhitelistedDomain(url) {
  const hostname = extractDomain(url).toLowerCase();
  return SAFE_DOMAINS.some(domain => 
    hostname === domain || hostname.endsWith('.' + domain)
  );
}

function allowsLongURLs(url) {
  const hostname = extractDomain(url).toLowerCase();
  return LONG_URL_OK_DOMAINS.some(domain => 
    hostname === domain || hostname.endsWith('.' + domain)
  );
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

function extractFeatures(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const path = urlObj.pathname;
    
    return {
      urlLength: url.length,
      pathLength: path.length,
      domainLength: hostname.length,
      numDots: (url.match(/\./g) || []).length,
      numAt: (url.match(/@/g) || []).length,
      subdomainCount: hostname.split('.').length - 2,
      hasIPAddress: /^\d+\.\d+\.\d+\.\d+$/.test(hostname),
      tld: hostname.split('.').pop(),
      suspiciousTLD: ['tk', 'ml', 'ga', 'cf', 'gq'].includes(hostname.split('.').pop()),
      entropy: calculateEntropy(hostname)
    };
  } catch (error) {
    return null;
  }
}

// ==================== HEURISTICS ====================
function quickHeuristicCheck(url) {
  const features = extractFeatures(url);
  if (!features) {
    return { shouldBlock: false };
  }
  
  // Whitelist check (minimal - let ML handle most cases)
  if (isWhitelistedDomain(url)) {
    return { shouldBlock: false, reason: 'Whitelisted domain' };
  }
  
  // Critical threats only
  if (features.hasIPAddress) {
    return { shouldBlock: true, reason: 'IP address URL', confidence: 0.85 };
  }
  if (features.suspiciousTLD) {
    return { shouldBlock: true, reason: 'Suspicious TLD', confidence: 0.75 };
  }
  if (features.numAt > 0) {
    return { shouldBlock: true, reason: 'Contains @ symbol', confidence: 0.90 };
  }
  
  // Only block very long paths for non-whitelisted
  if (features.pathLength > 100 && !allowsLongURLs(url)) {
    return { shouldBlock: true, reason: 'Very long URL path', confidence: 0.60 };
  }
  
  if (features.subdomainCount > 4) {
    return { shouldBlock: true, reason: 'Too many subdomains', confidence: 0.70 };
  }
  
  const hostname = extractDomain(url).toLowerCase();
  if (hostname.includes('https')) {
    return { shouldBlock: true, reason: 'HTTPS in domain name', confidence: 0.95 };
  }
  
  return { shouldBlock: false };
}

// ==================== BACKEND API (FIXED) ====================
const BACKEND_API = 'http://localhost:8000/api';
const cache = new CacheManager();
let stats = { totalChecked: 0, blocked: 0, warnings: 0, legitimate: 0 };
const blockedTabs = new Set();

async function checkWithBackendAPI(url) {
  try {
    // Create manual timeout (instead of AbortSignal.timeout)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch(`${BACKEND_API}/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url }),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      console.error(`API returned status: ${response.status}`);
      return null;
    }
    
    const data = await response.json();
    console.log('✅ Backend API response:', data);
    return data;
    
  } catch (error) {
    if (error.name === 'AbortError') {
      console.error('⏱️ Backend API timeout (5 seconds)');
    } else {
      console.error('❌ Backend API error:', error.message);
    }
    return null;
  }
}

async function checkAndBlockURL(details) {
  // Only check main page navigations
  if (details.type !== 'main_frame') {
    return;
  }

  // Skip internal pages
  if (details.url.startsWith('chrome://') || 
      details.url.startsWith('chrome-extension://') ||
      details.url.startsWith('about:') ||
      details.url.startsWith('edge://')) {
    return;
  }

  const url = details.url;
  const tabId = details.tabId;

  if (tabId === -1) {
    return;
  }

  // Skip if we just blocked this tab
  if (blockedTabs.has(tabId)) {
    blockedTabs.delete(tabId);
    return;
  }

  console.log('🔍 Checking URL:', url);

  try {
    // Step 1: Whitelist check (minimal)
    if (isWhitelistedDomain(url)) {
      stats.totalChecked++;
      stats.legitimate++;
      console.log('✅ Whitelisted:', url);
      return;
    }

    // Step 2: Cache check
    const cachedResult = await cache.get(url);
    if (cachedResult) {
      stats.totalChecked++;
      
      if (cachedResult.status === 'MALICIOUS') {
        stats.blocked++;
        console.log('🚫 Cache hit - BLOCKED:', url);
        blockTab(tabId, url, cachedResult.reason);
      } else if (cachedResult.status === 'SUSPICIOUS') {
        stats.warnings++;
        console.log('⚠️ Cache hit - SUSPICIOUS:', url);
        warnUser(url, cachedResult.reason, cachedResult.confidence);
      } else {
        stats.legitimate++;
        console.log('✅ Cache hit - SAFE:', url);
      }
      return;
    }

    // Step 3: Quick heuristics (instant)
    const heuristicResult = quickHeuristicCheck(url);
    if (heuristicResult.shouldBlock) {
      const result = {
        status: 'MALICIOUS',
        confidence: heuristicResult.confidence,
        reason: heuristicResult.reason,
        source: 'local_heuristics'
      };
      
      await cache.set(url, result);
      stats.totalChecked++;
      stats.blocked++;
      console.log('🚫 Heuristic block:', url);
      blockTab(tabId, url, heuristicResult.reason);
      return;
    }

    // Step 4: Backend ML check
    console.log('📡 Calling backend ML API...');
    const apiResult = await checkWithBackendAPI(url);
    
    if (apiResult) {
      // ML API succeeded
      const result = {
        status: apiResult.status,
        confidence: apiResult.confidence,
        reason: apiResult.reason,
        source: 'backend_ml'
      };
      
      await cache.set(url, result);
      stats.totalChecked++;
      
      if (apiResult.status === 'MALICIOUS') {
        stats.blocked++;
        console.log('🚫 ML block:', url);
        blockTab(tabId, url, apiResult.reason);
      } else if (apiResult.status === 'SUSPICIOUS') {
        stats.warnings++;
        console.log('⚠️ ML warning:', url);
        warnUser(url, apiResult.reason, apiResult.confidence);
      } else {
        stats.legitimate++;
        console.log('✅ ML safe:', url);
      }
    } else {
      // Backend unavailable - use local only
      console.log('⚠️ Backend unavailable - using local check only');
      const result = {
        status: 'LEGITIMATE',
        confidence: 0.5,
        reason: 'Backend unavailable - local check passed',
        source: 'local_fallback'
      };
      
      await cache.set(url, result);
      stats.totalChecked++;
      stats.legitimate++;
    }

  } catch (error) {
    console.error('❌ Error in checkAndBlockURL:', error);
    // On error, allow the page to load (fail-safe)
  }
}

function blockTab(tabId, url, reason) {
  blockedTabs.add(tabId);

  // Show notification
  chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('assets/icons/icon48.png'),
    title: '🚫 Malicious Website Blocked',
    message: reason || 'This site was flagged as dangerous',
    priority: 2
  });

  console.log('🚫 BLOCKED:', url, '| Reason:', reason);

  // Redirect to warning page
  const warningUrl = chrome.runtime.getURL('warning.html') + 
                     '?url=' + encodeURIComponent(url) + 
                     '&reason=' + encodeURIComponent(reason || 'Malicious site detected');
  
  chrome.tabs.update(tabId, { url: warningUrl });
}

function warnUser(url, reason, confidence) {
  const confidencePct = confidence ? (confidence * 100).toFixed(0) : '50';
  
  chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('assets/icons/icon48.png'),
    title: '⚠️ Suspicious Website',
    message: `${reason} (${confidencePct}% confidence)`,
    priority: 1
  });
  
  console.log('⚠️ WARNING:', url);
}

// ==================== EVENT LISTENERS ====================

// Listen to navigation requests
chrome.webRequest.onBeforeRequest.addListener(
  checkAndBlockURL,
  { 
    urls: ["<all_urls>"],
    types: ["main_frame"]
  }
);

// Message handler for popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getStats') {
    sendResponse(stats);
  } else if (request.action === 'clearCache') {
    cache.clear().then(() => {
      sendResponse({ success: true });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true; // Async response
  }
  return true;
});

// Startup log
console.log('🛡️ Malicious URL Detector loaded!');
console.log('   🤖 ML-First detection enabled');
console.log('   📡 Backend API: ' + BACKEND_API);